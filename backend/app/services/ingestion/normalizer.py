from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import date
from typing import Optional, List
import hashlib
import uuid

from app.models import (
    ThreatActorGroup, Industry, MitreTechnique, Source, EvidenceItem
)
from app.services.matcher import match_actor, match_industries, extract_technique_ids
from config import settings


class Normalizer:
    """Normalizes and stores ingested data"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_evidence_item(
        self,
        actor_name: str,
        source: Source,
        source_url: str,
        source_title: str,
        source_date: date,
        industry_keywords: Optional[str] = None,
        technique_ids: Optional[List[str]] = None,
        excerpt: Optional[str] = None
    ) -> List[EvidenceItem]:
        """
        Create evidence items from ingested data
        Returns list of created evidence items
        """
        # Match actor
        actor = await match_actor(actor_name, self.db)
        if not actor:
            # Create new actor (flagged for review)
            actor = ThreatActorGroup(
                name=actor_name,
                aliases=[],
                meta_data={"auto_created": True, "needs_review": True}
            )
            self.db.add(actor)
            await self.db.flush()
        
        # Match industries
        industries = []
        if industry_keywords:
            industries = await match_industries(industry_keywords, self.db)
        
        # Match techniques
        techniques = []
        if technique_ids:
            for tech_id in technique_ids:
                result = await self.db.execute(
                    select(MitreTechnique).where(MitreTechnique.technique_id == tech_id)
                )
                technique = result.scalar_one_or_none()
                if technique:
                    techniques.append(technique)
        
        # Create evidence items
        created_items = []
        
        # If no industries matched, create one evidence item without industry
        if not industries:
            industries = [None]
        
        # If no techniques matched, create one evidence item without technique
        if not techniques:
            techniques = [None]
        
        # Create evidence for each (industry, technique) combination
        for industry in industries:
            for technique in techniques:
                # Check for duplicates
                hash_key = self._generate_hash(
                    source_url, actor.id,
                    industry.id if industry else None,
                    technique.id if technique else None
                )
                
                # Check if exists
                existing = await self._check_duplicate(hash_key, source_date)
                if existing:
                    continue
                
                evidence = EvidenceItem(
                    threat_actor_group_id=actor.id,
                    industry_id=industry.id if industry else None,
                    technique_id=technique.id if technique else None,
                    source_id=source.id,
                    source_url=source_url,
                    source_title=source_title,
                    source_date=source_date,
                    excerpt=excerpt,
                    confidence_score=self._calculate_confidence_score(source),
                    meta_data={"hash": hash_key}
                )
                self.db.add(evidence)
                created_items.append(evidence)
        
        await self.db.commit()
        return created_items
    
    def _generate_hash(
        self,
        source_url: str,
        actor_id: uuid.UUID,
        industry_id: Optional[uuid.UUID],
        technique_id: Optional[uuid.UUID]
    ) -> str:
        """Generate hash for deduplication"""
        hash_string = f"{source_url}{actor_id}{industry_id or ''}{technique_id or ''}"
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    async def _check_duplicate(
        self,
        hash_key: str,
        source_date: date
    ) -> bool:
        """Check if evidence item with same hash and date exists"""
        result = await self.db.execute(
            select(EvidenceItem).where(
                EvidenceItem.meta_data["hash"].astext == hash_key
            )
        )
        existing = result.scalar_one_or_none()
        
        if existing and existing.source_date == source_date:
            return True
        
        return False
    
    def _calculate_confidence_score(self, source: Source) -> int:
        """Calculate confidence score based on source reliability"""
        # Base confidence on source reliability
        return min(max(source.reliability_score, 1), 10)
