import httpx
from bs4 import BeautifulSoup
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, date
from typing import Dict, List
import re

from app.models import Source
from app.services.ingestion.normalizer import Normalizer
from app.services.matcher import extract_technique_ids
from app.utils.logging import setup_logging

logger = setup_logging()

CISA_BASE_URL = "https://www.cisa.gov"
CISA_ADVISORIES_URL = f"{CISA_BASE_URL}/news-events/cybersecurity-advisories"


class CisaIngester:
    """Ingest data from CISA advisories"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def ingest(self, limit: int = 50) -> Dict[str, int]:
        """
        Ingest CISA advisories
        Returns stats: {advisories_processed, evidence_created}
        """
        logger.info("Starting CISA advisories ingestion")
        
        # Get or create CISA source
        source = await self._get_or_create_source()
        
        # Fetch advisories page
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.get(CISA_ADVISORIES_URL)
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Failed to fetch CISA advisories: {e}")
                return {"error": str(e)}
        
        soup = BeautifulSoup(response.text, "lxml")
        
        stats = {
            "advisories_processed": 0,
            "evidence_created": 0
        }
        
        # Find advisory links - try multiple selectors
        valid_links = []
        seen_urls = set()
        
        # Try different selectors for advisory links
        selectors = [
            "article.c-view__row a",
            "article.c-teaser a",
            ".c-view__row a",
            "a[href*='/cybersecurity-advisories/']",
            ".view-content a",
        ]
        
        for selector in selectors:
            links = soup.select(selector)
            if links:
                for link in links:
                    href = link.get("href", "")
                    if not href:
                        continue
                    
                    # Make absolute URL
                    if href.startswith("/"):
                        url = f"{CISA_BASE_URL}{href}"
                    elif href.startswith("http"):
                        url = href
                    else:
                        continue
                    
                    # Only process actual advisory pages
                    # Advisories typically have format: /news-events/cybersecurity-advisories/AA##-###A
                    if ("/cybersecurity-advisories/" in url and 
                        url.count("/") >= 4 and
                        "?" not in url and 
                        "/resources" not in url and 
                        "/tools" not in url and
                        "/news-events/cybersecurity-advisories" != url and
                        url not in seen_urls):
                        seen_urls.add(url)
                        valid_links.append(url)
                
                if valid_links:
                    break  # Found links with this selector
        
        # Process advisories
        for url in valid_links[:limit]:
            try:
                evidence_count = await self._process_advisory(url, source, client)
                stats["advisories_processed"] += 1
                stats["evidence_created"] += evidence_count
            except Exception as e:
                logger.error(f"Error processing advisory {url}: {e}")
                continue
        
        # Update source last_checked_at
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"CISA ingestion complete: {stats}")
        return stats
    
    async def _get_or_create_source(self) -> Source:
        """Get or create CISA source"""
        result = await self.db.execute(
            select(Source).where(Source.name == "CISA Advisory")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            from config import settings
            source = Source(
                name="CISA Advisory",
                type="advisory",
                base_url=CISA_BASE_URL,
                reliability_score=settings.source_reliability_cisa,
                meta_data={"advisories_url": CISA_ADVISORIES_URL}
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    async def _process_advisory(
        self,
        url: str,
        source: Source,
        client: httpx.AsyncClient
    ) -> int:
        """Process a single CISA advisory"""
        try:
            response = await client.get(url, timeout=15.0)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return 0
        
        soup = BeautifulSoup(response.text, "lxml")
        
        # Extract title
        title_elem = soup.select_one("h1, .page-title, title")
        title = title_elem.get_text(strip=True) if title_elem else "CISA Advisory"
        
        # Extract date
        date_elem = soup.select_one("time, .date, .published-date")
        source_date = date.today()
        if date_elem:
            date_text = date_elem.get_text(strip=True)
            # Try to parse date
            try:
                from dateutil import parser
                source_date = parser.parse(date_text).date()
            except:
                pass
        
        # Extract text content
        content_elem = soup.select_one("article, .content, .body, main")
        if not content_elem:
            content_elem = soup
        
        text = content_elem.get_text(separator=" ", strip=True)
        
        # Extract actor names (use enhanced extraction)
        from app.services.ingestion.enhanced_extraction import extract_actors_enhanced
        actors = extract_actors_enhanced(text, title)
        if not actors:
            # Fallback to original method
            actors = self._extract_actors(text)
        
        # Extract industry keywords (use enhanced extraction)
        from app.services.ingestion.enhanced_extraction import extract_industries_enhanced, extract_techniques_enhanced
        industries = extract_industries_enhanced(text, title)
        industry_text = ", ".join(industries) if industries else text[:200]
        
        # Extract technique IDs (use enhanced extraction)
        technique_ids = extract_techniques_enhanced(text)
        if not technique_ids:
            # Fallback to original method
            technique_ids = extract_technique_ids(text)
        
        # Create evidence items
        evidence_count = 0
        for actor_name in actors:
            items = await self.normalizer.create_evidence_item(
                actor_name=actor_name,
                industry_keywords=industry_text,
                technique_ids=technique_ids if technique_ids else None,
                source=source,
                source_url=url,
                source_title=title,
                source_date=source_date,
                excerpt=text[:500] if len(text) > 500 else text
            )
            evidence_count += len(items)
        
        return evidence_count
    
    def _extract_actors(self, text: str) -> List[str]:
        """Extract threat actor names from text"""
        # Common actor name patterns
        # This is a simple implementation - can be enhanced with NER
        actors = []
        
        # Known actor patterns (case-insensitive)
        known_actors = [
            "Lazarus Group", "APT28", "APT29", "Fancy Bear", "Cozy Bear",
            "APT1", "APT10", "APT12", "APT17", "APT18", "APT19", "APT20",
            "APT21", "APT22", "APT23", "APT27", "APT30", "APT31", "APT32",
            "APT33", "APT34", "APT35", "APT36", "APT37", "APT38", "APT39",
            "APT40", "APT41", "BlackEnergy", "Carbanak", "Cobalt", "Dragonfly",
            "Energetic Bear", "Equation Group", "Gamaredon", "Gorgon Group",
            "HIDDEN COBRA", "Kimsuky", "Lazarus", "MuddyWater", "OilRig",
            "Panda", "Putter Panda", "Sandworm", "Silence", "Sofacy",
            "Stuxnet", "Turla", "WannaCry", "Wizard Spider", "Zeus"
        ]
        
        text_lower = text.lower()
        for actor in known_actors:
            if actor.lower() in text_lower:
                actors.append(actor)
        
        # Also look for "APT" followed by numbers
        apt_pattern = re.compile(r'APT\s*-?\s*\d+', re.IGNORECASE)
        apt_matches = apt_pattern.findall(text)
        actors.extend([m.strip() for m in apt_matches])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_actors = []
        for actor in actors:
            if actor not in seen:
                seen.add(actor)
                unique_actors.append(actor)
        
        return unique_actors[:10]  # Limit to 10 actors per advisory
