"""Company lookup and validation service.

Uses free APIs to validate company names and get company details.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import httpx

from app.services.ingestion.source_config import get_source_api_key
from app.utils.logging import setup_logging

logger = setup_logging()


class CompanyLookupService:
    """Service for looking up and validating company names"""

    def __init__(self):
        # OpenCorporates free API (requires API key for free tier)
        self.opencorporates_base = "https://api.opencorporates.com/v0.4"
        # Get API key from config file first, then fall back to environment variable
        import os

        api_key = get_source_api_key("opencorporates")
        if not api_key:
            api_key = os.getenv("OPENCORPORATES_API_KEY", None)
        self.opencorporates_api_key = api_key
        self.use_opencorporates = self.opencorporates_api_key is not None

    async def search_companies(
        self, query: str, limit: int = 10, jurisdiction: Optional[str] = None
    ) -> List[Dict]:
        """
        Search for companies by name
        Returns list of company matches with details
        """
        results = []

        # Try OpenCorporates first (free tier: 50 requests/day)
        if self.use_opencorporates:
            try:
                opencorp_results = await self._search_opencorporates(
                    query, limit, jurisdiction
                )
                results.extend(opencorp_results)
            except Exception as e:
                logger.warning("OpenCorporates search failed: %s", e)

        # If we don't have enough results or no API key, provide a simple fallback
        if len(results) < limit and not self.use_opencorporates:
            # Simple fallback: return a message that API key is needed
            # In production, you could add other free APIs here
            logger.info(
                "OpenCorporates API key not configured. Set OPENCORPORATES_API_KEY env var for company lookup."
            )
            return []

        return results[:limit]

    async def _search_opencorporates(
        self, query: str, limit: int = 10, jurisdiction: Optional[str] = None
    ) -> List[Dict]:
        """Search using OpenCorporates API"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Build URL
            url = f"{self.opencorporates_base}/companies/search"
            params = {
                "q": query,
                "per_page": min(limit, 20),  # API limit
            }
            if jurisdiction:
                params["jurisdiction_code"] = jurisdiction
            if self.opencorporates_api_key:
                params["api_token"] = self.opencorporates_api_key

            try:
                response = await client.get(url, params=params)
                response.raise_for_status()
                data = response.json()

                companies = []
                if "results" in data and "companies" in data["results"]:
                    for company in data["results"]["companies"]:
                        company_data = company.get("company", {})
                        companies.append(
                            {
                                "name": company_data.get("name", ""),
                                "jurisdiction": company_data.get(
                                    "jurisdiction_code", ""
                                ),
                                "company_number": company_data.get(
                                    "company_number", ""
                                ),
                                "opencorporates_url": company_data.get(
                                    "opencorporates_url", ""
                                ),
                                "registry_url": company_data.get("registry_url", ""),
                                "source": "opencorporates",
                            }
                        )

                return companies
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    logger.warning("OpenCorporates rate limit reached")
                raise
            except Exception as e:
                logger.error("OpenCorporates API error: %s", e)
                raise

    async def get_company_details(
        self, company_name: str, jurisdiction: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Get detailed information about a specific company
        """
        # Search first to get company number
        results = await self.search_companies(
            company_name, limit=1, jurisdiction=jurisdiction
        )

        if not results:
            return None

        company = results[0]

        # If we have OpenCorporates data, try to get more details
        if company.get("source") == "opencorporates" and company.get("company_number"):
            try:
                details = await self._get_opencorporates_details(
                    company["jurisdiction"], company["company_number"]
                )
                if details:
                    company.update(details)
            except Exception as e:
                logger.debug("Could not fetch company details: %s", e)

        return company

    async def _get_opencorporates_details(
        self, jurisdiction: str, company_number: str
    ) -> Optional[Dict]:
        """Get detailed company info from OpenCorporates"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            url = (
                f"{self.opencorporates_base}/companies/{jurisdiction}/{company_number}"
            )

            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()

                if "results" in data and "company" in data["results"]:
                    company = data["results"]["company"]
                    return {
                        "registered_address": company.get(
                            "registered_address_in_full", ""
                        ),
                        "incorporation_date": company.get("incorporation_date", ""),
                        "company_type": company.get("company_type", ""),
                        "status": company.get("current_status", ""),
                        "officers": company.get("officers", []),
                    }
            except Exception as e:
                logger.debug("Error fetching company details: %s", e)

        return None

    async def validate_company_name(self, company_name: str) -> Dict:
        """
        Validate a company name and return confidence score
        """
        results = await self.search_companies(company_name, limit=5)

        if not results:
            return {
                "valid": False,
                "confidence": 0,
                "message": "No matching companies found",
                "suggestions": [],
            }

        # Check if exact match exists
        exact_match = None
        for result in results:
            if result["name"].lower() == company_name.lower():
                exact_match = result
                break

        if exact_match:
            return {
                "valid": True,
                "confidence": 100,
                "message": "Exact match found",
                "company": exact_match,
                "suggestions": results[:5],
            }

        # Check for close matches
        close_matches = [
            r
            for r in results
            if company_name.lower() in r["name"].lower()
            or r["name"].lower() in company_name.lower()
        ]

        if close_matches:
            return {
                "valid": True,
                "confidence": 75,
                "message": "Close matches found",
                "company": close_matches[0],
                "suggestions": results[:5],
            }

        return {
            "valid": False,
            "confidence": 50,
            "message": "Possible matches found, please verify",
            "suggestions": results[:5],
        }
