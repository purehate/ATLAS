"""
CISA ICS Advisories Ingestion
Scrapes CISA Industrial Control Systems (ICS) advisories for threat intelligence
"""
import httpx
from bs4 import BeautifulSoup
from datetime import datetime, date
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Source, EvidenceItem
from app.services.ingestion.normalizer import Normalizer
from app.services.ingestion.enhanced_extraction import (
    extract_actors_enhanced,
    extract_industries_enhanced,
    extract_techniques_enhanced
)
from app.utils.logging import setup_logging

logger = setup_logging()

CISA_ICS_URL = "https://www.cisa.gov/news-events/ics-advisories"


class CisaIcsIngester:
    """Ingests CISA ICS advisories"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
        self.source_name = "CISA ICS Advisory"
    
    async def ingest(self, limit: Optional[int] = None) -> Dict:
        """Ingest ICS advisories from CISA"""
        try:
            # Get or create source
            source = await self._get_or_create_source()
            
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(CISA_ICS_URL)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Find advisory links - CISA ICS uses similar structure to regular advisories
                advisory_links = []
                
                # Try multiple selectors
                selectors = [
                    "article.c-view__row a",
                    "article.c-teaser a",
                    ".c-view__row a",
                    "a[href*='/ics-advisories/']"
                ]
                
                for selector in selectors:
                    links = soup.select(selector)
                    if links:
                        advisory_links = links
                        break
                
                if not advisory_links:
                    logger.warning("No advisory links found with any selector")
                    return {
                        "source": self.source_name,
                        "status": "error",
                        "message": "No advisory links found",
                        "items_processed": 0
                    }
                
                processed = 0
                errors = 0
                
                for link in advisory_links[:limit] if limit else advisory_links:
                    try:
                        href = link.get("href", "")
                        if not href or not href.startswith("/"):
                            continue
                        
                        full_url = f"https://www.cisa.gov{href}"
                        title = link.get_text(strip=True)
                        
                        # Process advisory
                        result = await self._process_advisory(client, full_url, title, source)
                        if result:
                            processed += 1
                        else:
                            errors += 1
                            
                    except Exception as e:
                        logger.error(f"Error processing ICS advisory {href}: {e}")
                        errors += 1
                
                await self.db.commit()
                
                return {
                    "source": self.source_name,
                    "status": "success",
                    "items_processed": processed,
                    "errors": errors
                }
                
        except Exception as e:
            logger.error(f"Error ingesting CISA ICS advisories: {e}")
            await self.db.rollback()
            return {
                "source": self.source_name,
                "status": "error",
                "message": str(e),
                "items_processed": 0
            }
    
    async def _process_advisory(
        self,
        client: httpx.AsyncClient,
        url: str,
        title: str,
        source: Source
    ) -> bool:
        """Process a single ICS advisory"""
        try:
            response = await client.get(url, timeout=15.0)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract content
            content_selectors = [
                ".c-view__body",
                ".field--name-body",
                "article .content",
                "main article"
            ]
            
            content = ""
            for selector in content_selectors:
                elem = soup.select_one(selector)
                if elem:
                    content = elem.get_text(separator=" ", strip=True)
                    break
            
            if not content:
                content = soup.get_text(separator=" ", strip=True)
            
            # Extract date
            date_str = None
            date_selectors = [
                "time[datetime]",
                ".field--name-field-date",
                ".c-view__date",
                "time"
            ]
            
            for selector in date_selectors:
                elem = soup.select_one(selector)
                if elem:
                    date_attr = elem.get("datetime") or elem.get_text(strip=True)
                    if date_attr:
                        try:
                            date_str = datetime.fromisoformat(date_attr.replace("Z", "+00:00")).date()
                        except:
                            try:
                                date_str = datetime.strptime(date_attr, "%Y-%m-%d").date()
                            except:
                                pass
                    break
            
            if not date_str:
                date_str = date.today()
            
            # Extract actors, industries, techniques
            actors = extract_actors_enhanced(content, title)
            industries = extract_industries_enhanced(content, title)
            techniques = extract_techniques_enhanced(content)
            
            # ICS advisories are typically about industrial/manufacturing/energy
            if "manufacturing" not in industries and "energy" not in industries:
                industries.append("manufacturing")  # Default for ICS
            
            # Create evidence items for each actor/industry/technique combination
            excerpt = content[:500] if len(content) > 500 else content
            
            if not actors:
                actors = ["Unknown"]  # Create at least one evidence item
            
            for actor_name in actors:
                await self.normalizer.create_evidence_item(
                    actor_name=actor_name,
                    source=source,
                    source_url=url,
                    source_title=title,
                    source_date=date_str,
                    industry_keywords=", ".join(industries) if industries else None,
                    technique_ids=techniques if techniques else None,
                    excerpt=excerpt
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing ICS advisory {url}: {e}")
            return False
    
    async def _get_or_create_source(self) -> Source:
        """Get or create CISA ICS Advisory source"""
        from sqlalchemy import select
        from app.models import Source
        
        result = await self.db.execute(
            select(Source).where(Source.name == self.source_name)
        )
        source = result.scalar_one_or_none()
        
        if not source:
            source = Source(
                name=self.source_name,
                type="government_advisory",
                base_url=CISA_ICS_URL,
                reliability_score=9
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
