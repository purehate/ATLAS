"""
CISA Known Exploited Vulnerabilities (KEV) Catalog
Free JSON API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, date
from typing import Dict, List
import json

from app.models import Source
from app.services.ingestion.normalizer import Normalizer
from app.utils.logging import setup_logging

logger = setup_logging()

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevIngester:
    """Ingest data from CISA Known Exploited Vulnerabilities catalog"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def ingest(self) -> Dict[str, int]:
        """
        Ingest CISA KEV data
        Returns stats: {vulnerabilities_processed, evidence_created}
        """
        logger.info("Starting CISA KEV ingestion")
        
        # Get or create CISA KEV source
        source = await self._get_or_create_source()
        
        # Fetch KEV JSON
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.get(CISA_KEV_URL)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                logger.error(f"Failed to fetch CISA KEV: {e}")
                return {"error": str(e)}
        
        stats = {
            "vulnerabilities_processed": 0,
            "evidence_created": 0
        }
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Process vulnerabilities
        for vuln in vulnerabilities[:100]:  # Limit to 100 for MVP
            try:
                evidence_count = await self._process_vulnerability(vuln, source)
                stats["vulnerabilities_processed"] += 1
                stats["evidence_created"] += evidence_count
            except Exception as e:
                logger.error(f"Error processing vulnerability: {e}")
                continue
        
        # Update source last_checked_at
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"CISA KEV ingestion complete: {stats}")
        return stats
    
    async def _get_or_create_source(self) -> Source:
        """Get or create CISA KEV source"""
        result = await self.db.execute(
            select(Source).where(Source.name == "CISA KEV")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            from config import settings
            source = Source(
                name="CISA KEV",
                type="advisory",
                base_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                reliability_score=settings.source_reliability_cisa,
                meta_data={"kev_url": CISA_KEV_URL}
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    async def _process_vulnerability(
        self,
        vuln: Dict,
        source: Source
    ) -> int:
        """Process a single vulnerability entry"""
        # Extract information
        cve_id = vuln.get("cveID", "")
        vendor_project = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        vulnerability_name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")
        notes = vuln.get("notes", "")
        
        # Parse date
        source_date = date.today()
        try:
            if date_added:
                source_date = datetime.strptime(date_added, "%Y-%m-%d").date()
        except:
            pass
        
        # Build text for extraction
        text = f"{vulnerability_name} {description} {notes} {vendor_project} {product}"
        
        # Extract actor names (if mentioned)
        actors = self._extract_actors(text)
        
        # Extract industry keywords (from product/vendor context)
        industry_text = f"{vendor_project} {product} {description}"
        
        # Extract technique IDs (if mentioned)
        from app.services.matcher import extract_technique_ids
        technique_ids = extract_technique_ids(text)
        
        # Create evidence items
        evidence_count = 0
        for actor_name in actors:
            items = await self.normalizer.create_evidence_item(
                actor_name=actor_name,
                source=source,
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}",
                source_title=f"CISA KEV: {cve_id} - {vulnerability_name}",
                source_date=source_date,
                industry_keywords=industry_text,
                technique_ids=technique_ids if technique_ids else None,
                excerpt=f"{cve_id}: {description}"
            )
            evidence_count += len(items)
        
        # If no actors found, still create evidence for the vulnerability itself
        # This helps with industry targeting patterns
        if not actors and industry_text:
            items = await self.normalizer.create_evidence_item(
                actor_name="Unknown",  # Will create or match to generic actor
                source=source,
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}",
                source_title=f"CISA KEV: {cve_id} - {vulnerability_name}",
                source_date=source_date,
                industry_keywords=industry_text,
                technique_ids=technique_ids if technique_ids else None,
                excerpt=f"{cve_id}: {description}"
            )
            evidence_count += len(items)
        
        return evidence_count
    
    def _extract_actors(self, text: str) -> List[str]:
        """Extract threat actor names from text"""
        # Similar to CISA ingester
        actors = []
        
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
        
        import re
        apt_pattern = re.compile(r'APT\s*-?\s*\d+', re.IGNORECASE)
        apt_matches = apt_pattern.findall(text)
        actors.extend([m.strip() for m in apt_matches])
        
        seen = set()
        unique_actors = []
        for actor in actors:
            if actor not in seen:
                seen.add(actor)
                unique_actors.append(actor)
        
        return unique_actors[:5]  # Limit to 5 per vulnerability
