"""
NIST National Vulnerability Database (NVD) Ingestion
Fetches recent CVEs and maps them to MITRE techniques where possible
"""
import httpx
from datetime import datetime, date, timedelta
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.models import Source, EvidenceItem
from app.services.ingestion.normalizer import Normalizer
from app.services.ingestion.enhanced_extraction import extract_techniques_enhanced
from app.services.ingestion.source_config import get_source_api_key
from app.utils.logging import setup_logging

logger = setup_logging()

# NVD API v2 endpoint (free, no API key required for basic queries)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NistNvdIngester:
    """Ingests CVE data from NIST NVD"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
        self.source_name = "NIST NVD"
    
    async def ingest(self, days_back: int = 7, limit: Optional[int] = None) -> Dict:
        """
        Ingest recent CVEs from NIST NVD
        Note: NVD API has rate limits (5 requests per 30 seconds)
        """
        try:
            # Get or create source
            source = await self._get_or_create_source()
            
            # Calculate date range
            end_date = date.today()
            start_date = end_date - timedelta(days=days_back)
            
            # NVD API requires pagination
            start_index = 0
            results_per_page = 20
            total_processed = 0
            errors = 0
            
            # Get API key from config
            api_key = get_source_api_key("nist_nvd")
            headers = {}
            if api_key:
                headers["apiKey"] = api_key
                logger.info("Using NIST NVD API key for improved rate limits")
            
            async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
                while True:
                    # Build API URL
                    url = f"{NVD_API_BASE}?pubStartDate={start_date}T00:00:00.000&pubEndDate={end_date}T23:59:59.999&startIndex={start_index}&resultsPerPage={results_per_page}"
                    
                    try:
                        response = await client.get(url)
                        response.raise_for_status()
                        data = response.json()
                        
                        vulnerabilities = data.get("vulnerabilities", [])
                        if not vulnerabilities:
                            break
                        
                        for vuln_data in vulnerabilities:
                            if limit and total_processed >= limit:
                                break
                            
                            try:
                                cve = vuln_data.get("cve", {})
                                cve_id = cve.get("id", "")
                                
                                if not cve_id:
                                    continue
                                
                                # Extract CVE details
                                descriptions = cve.get("descriptions", [])
                                description = ""
                                for desc in descriptions:
                                    if desc.get("lang") == "en":
                                        description = desc.get("value", "")
                                        break
                                
                                # Get published date
                                published = cve.get("published", "")
                                pub_date = date.today()
                                if published:
                                    try:
                                        pub_date = datetime.fromisoformat(published.replace("Z", "+00:00")).date()
                                    except:
                                        pass
                                
                                # Extract metrics for severity
                                metrics = cve.get("metrics", {})
                                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                                base_score = cvss_v3.get("cvssData", {}).get("baseScore", 0)
                                
                                # Only process high-severity CVEs (CVSS >= 7.0) for relevance
                                if base_score < 7.0:
                                    continue
                                
                                # Extract techniques from description
                                techniques = extract_techniques_enhanced(description)
                                
                                # Map CVE to common techniques based on keywords
                                cve_techniques = self._map_cve_to_techniques(description, cve_id)
                                techniques.extend(cve_techniques)
                                techniques = list(set(techniques))  # Deduplicate
                                
                                # Create evidence item (CVEs don't have actors, so use "Unknown")
                                title = f"{cve_id} - {description[:100]}"
                                excerpt = f"CVE: {cve_id}\nCVSS Score: {base_score}\n{description[:400]}"
                                
                                await self.normalizer.create_evidence_item(
                                    actor_name="Unknown",  # CVEs don't typically have actors
                                    source=source,
                                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                    source_title=title,
                                    source_date=pub_date,
                                    industry_keywords=None,  # Could extract from description later
                                    technique_ids=techniques if techniques else None,
                                    excerpt=excerpt
                                )
                                
                                total_processed += 1
                                
                                # Rate limiting: NVD allows 5 requests per 30 seconds
                                if total_processed % 5 == 0:
                                    import asyncio
                                    await asyncio.sleep(6)  # Wait 6 seconds every 5 items
                                
                            except Exception as e:
                                logger.error(f"Error processing CVE: {e}")
                                errors += 1
                        
                        # Check if more pages
                        total_results = data.get("totalResults", 0)
                        if start_index + results_per_page >= total_results:
                            break
                        
                        start_index += results_per_page
                        
                        if limit and total_processed >= limit:
                            break
                        
                        # Rate limiting between pages
                        await asyncio.sleep(6)
                        
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == 403:
                            logger.warning("NVD API rate limit hit, stopping")
                            break
                        raise
                
                await self.db.commit()
                
                return {
                    "source": self.source_name,
                    "status": "success",
                    "items_processed": total_processed,
                    "errors": errors,
                    "date_range": f"{start_date} to {end_date}"
                }
                
        except Exception as e:
            logger.error(f"Error ingesting NIST NVD: {e}")
            await self.db.rollback()
            return {
                "source": self.source_name,
                "status": "error",
                "message": str(e),
                "items_processed": 0
            }
    
    async def _get_or_create_source(self) -> Source:
        """Get or create NIST NVD source"""
        from sqlalchemy import select
        from app.models import Source
        
        result = await self.db.execute(
            select(Source).where(Source.name == self.source_name)
        )
        source = result.scalar_one_or_none()
        
        if not source:
            source = Source(
                name=self.source_name,
                type="vulnerability_database",
                base_url="https://nvd.nist.gov",
                reliability_score=10  # NIST is authoritative
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    def _map_cve_to_techniques(self, description: str, cve_id: str) -> List[str]:
        """
        Map CVE descriptions to MITRE techniques based on vulnerability type
        """
        techniques = []
        desc_lower = description.lower()
        
        # Common vulnerability type to technique mappings
        vulnerability_mappings = {
            "sql injection": ["T1190"],  # Exploit Public-Facing Application
            "xss": ["T1190"],  # Cross-site scripting
            "remote code execution": ["T1190", "T1059"],  # Command and Scripting Interpreter
            "command injection": ["T1059"],  # Command and Scripting Interpreter
            "path traversal": ["T1190"],  # Exploit Public-Facing Application
            "privilege escalation": ["T1068"],  # Exploitation for Privilege Escalation
            "authentication bypass": ["T1078"],  # Valid Accounts
            "deserialization": ["T1190"],  # Exploit Public-Facing Application
            "buffer overflow": ["T1190"],  # Exploit Public-Facing Application
            "arbitrary file": ["T1190"],  # Exploit Public-Facing Application
            "code execution": ["T1059"],  # Command and Scripting Interpreter
            "memory corruption": ["T1190"],  # Exploit Public-Facing Application
        }
        
        for vuln_type, tech_ids in vulnerability_mappings.items():
            if vuln_type in desc_lower:
                techniques.extend(tech_ids)
        
        return list(set(techniques))  # Deduplicate
