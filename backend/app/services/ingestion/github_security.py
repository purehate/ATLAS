"""
GitHub Security Advisories (GHSA) Ingestion
Fetches GitHub Security Advisories RSS feed for vulnerability intelligence
"""
import httpx
from bs4 import BeautifulSoup
from datetime import datetime, date
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Source, EvidenceItem
from app.services.ingestion.normalizer import Normalizer
from app.services.ingestion.enhanced_extraction import (
    extract_actors_enhanced,
    extract_industries_enhanced,
    extract_techniques_enhanced
)
from app.utils.logging import setup_logging

logger = setup_logging()

# GitHub Security Advisories - using GitHub GraphQL API
GITHUB_GRAPHQL_API = "https://api.github.com/graphql"
# Alternative: GitHub Advisory Database RSS (if available)
GITHUB_ADVISORY_DB_RSS = "https://github.com/advisories/feed"


class GitHubSecurityIngester:
    """Ingests GitHub Security Advisories"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
        self.source_name = "GitHub Security Advisory"
    
    async def ingest(self, limit: Optional[int] = None) -> Dict:
        """Ingest GitHub Security Advisories from RSS feed"""
        try:
            # Get or create source
            source = await self._get_or_create_source()
            
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Try GitHub Advisory Database RSS feed
                try:
                    response = await client.get(GITHUB_ADVISORY_DB_RSS)
                    if response.status_code == 200:
                        # Parse RSS
                        soup = BeautifulSoup(response.text, "xml")
                        items = soup.find_all("item")
                    else:
                        logger.warning(f"GitHub Advisory RSS returned {response.status_code}, trying alternative")
                        items = []
                except Exception as e:
                    logger.warning(f"Failed to fetch GitHub Advisory RSS: {e}")
                    items = []
                
                # If RSS failed, try scraping the advisory database page
                if not items:
                    try:
                        response = await client.get("https://github.com/advisories")
                        response.raise_for_status()
                        soup = BeautifulSoup(response.text, "html.parser")
                        # Find advisory links
                        advisory_links = soup.select("a[href*='/advisories/GHSA-']")
                        # Convert to RSS-like items structure
                        items = []
                        for link in advisory_links[:limit] if limit else advisory_links:
                            href = link.get("href", "")
                            if href.startswith("/"):
                                href = f"https://github.com{href}"
                            # Create a mock item structure
                            item = BeautifulSoup("<item></item>", "xml").find("item")
                            title_elem = BeautifulSoup(f"<title>{link.get_text(strip=True)}</title>", "xml").find("title")
                            link_elem = BeautifulSoup(f"<link>{href}</link>", "xml").find("link")
                            item.append(title_elem)
                            item.append(link_elem)
                            items.append(item)
                        logger.info(f"Found {len(items)} advisories from HTML scraping")
                    except Exception as e2:
                        logger.error(f"Failed to fetch GitHub advisories: {e2}")
                        return {
                            "source": self.source_name,
                            "status": "error",
                            "message": str(e2),
                            "items_processed": 0
                        }
                
                processed = 0
                errors = 0
                
                for item in items[:limit] if limit else items:
                    try:
                        # Handle both RSS items (BeautifulSoup) and dict items (from HTML scraping)
                        if isinstance(item, dict):
                            title = item.get("title", "").strip()
                            url = item.get("link", "").strip()
                            pub_date_str = item.get("pubDate", "")
                            description = item.get("description", "").strip()
                        else:
                            title_elem = item.find("title")
                            link_elem = item.find("link")
                            pub_date_elem = item.find("pubDate")
                            description_elem = item.find("description")
                            
                            if not title_elem or not link_elem:
                                continue
                            
                            title = title_elem.text.strip()
                            url = link_elem.text.strip()
                            pub_date_str = pub_date_elem.text.strip() if pub_date_elem else ""
                            description = description_elem.text.strip() if description_elem else ""
                        
                        if not title or not url:
                            continue
                        
                        # Parse date
                        pub_date = date.today()
                        if pub_date_str:
                            try:
                                pub_date = datetime.strptime(
                                    pub_date_str[:25],
                                    "%a, %d %b %Y %H:%M:%S"
                                ).date()
                            except:
                                try:
                                    pub_date = datetime.strptime(
                                        pub_date_str[:10],
                                        "%Y-%m-%d"
                                    ).date()
                                except:
                                    pass
                        
                        # Get description (if not already extracted)
                        if not description:
                            # Try to fetch the advisory page for description
                            try:
                                response = await client.get(url, timeout=10.0)
                                if response.status_code == 200:
                                    page_soup = BeautifulSoup(response.text, "html.parser")
                                    desc_elem = page_soup.select_one(".markdown-body, article, .content")
                                    if desc_elem:
                                        description = desc_elem.get_text(separator=" ", strip=True)
                            except:
                                pass
                        
                        # Remove HTML tags from description if present
                        if description:
                            desc_soup = BeautifulSoup(description, "html.parser")
                            description = desc_soup.get_text(separator=" ", strip=True)
                        
                        # Extract GHSA ID from title or URL
                        import re
                        ghsa_id = ""
                        ghsa_pattern = r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}'
                        if "GHSA-" in title:
                            match = re.search(ghsa_pattern, title, re.IGNORECASE)
                            if match:
                                ghsa_id = match.group(0).upper()
                        if not ghsa_id and "GHSA-" in url:
                            match = re.search(ghsa_pattern, url, re.IGNORECASE)
                            if match:
                                ghsa_id = match.group(0).upper()
                        
                        # Extract techniques from description
                        techniques = extract_techniques_enhanced(description)
                        
                        # Map vulnerability types to techniques
                        vuln_techniques = self._map_vulnerability_to_techniques(description, title)
                        techniques.extend(vuln_techniques)
                        techniques = list(set(techniques))  # Deduplicate
                        
                        # Create evidence item (GHSA typically doesn't have actors)
                        excerpt = description[:500] if len(description) > 500 else description
                        
                        await self.normalizer.create_evidence_item(
                            actor_name="Unknown",  # GHSA typically doesn't have actors
                            source=source,
                            source_url=url,
                            source_title=title,
                            source_date=pub_date,
                            industry_keywords="technology",  # GitHub is tech-focused
                            technique_ids=techniques if techniques else None,
                            excerpt=excerpt
                        )
                        
                        processed += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing GHSA item: {e}")
                        errors += 1
                
                await self.db.commit()
                
                return {
                    "source": self.source_name,
                    "status": "success",
                    "items_processed": processed,
                    "errors": errors
                }
                
        except Exception as e:
            logger.error(f"Error ingesting GitHub Security Advisories: {e}")
            await self.db.rollback()
            return {
                "source": self.source_name,
                "status": "error",
                "message": str(e),
                "items_processed": 0
            }
    
    async def _get_or_create_source(self) -> Source:
        """Get or create GitHub Security Advisory source"""
        from sqlalchemy import select
        from app.models import Source
        
        result = await self.db.execute(
            select(Source).where(Source.name == self.source_name)
        )
        source = result.scalar_one_or_none()
        
        if not source:
            source = Source(
                name=self.source_name,
                type="security_advisory",
                base_url="https://github.com/security-advisories",
                reliability_score=8
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    def _map_vulnerability_to_techniques(self, description: str, title: str) -> List[str]:
        """Map vulnerability descriptions to MITRE techniques"""
        techniques = []
        combined = f"{title} {description}".lower()
        
        vulnerability_mappings = {
            "sql injection": ["T1190"],
            "xss": ["T1190"],
            "remote code execution": ["T1190", "T1059"],
            "command injection": ["T1059"],
            "path traversal": ["T1190"],
            "privilege escalation": ["T1068"],
            "authentication bypass": ["T1078"],
            "deserialization": ["T1190"],
            "buffer overflow": ["T1190"],
            "arbitrary file": ["T1190"],
            "code execution": ["T1059"],
            "memory corruption": ["T1190"],
            "prototype pollution": ["T1190"],
            "dependency confusion": ["T1190"],
        }
        
        for vuln_type, tech_ids in vulnerability_mappings.items():
            if vuln_type in combined:
                techniques.extend(tech_ids)
        
        return list(set(techniques))
