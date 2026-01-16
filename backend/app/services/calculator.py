from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from datetime import date, timedelta
from typing import List, Optional
from uuid import UUID
import uuid

from app.models import (
    Industry, ThreatActorGroup, MitreTechnique, EvidenceItem,
    ActorIndustryScore, ActorTechniqueScore
)
from app.schemas import (
    CalculateResponse, ActorResult, ThreatActorInfo, TechniqueScore,
    TechniqueInfo, Explanation
)
from config import settings


class CalculatorService:
    """Service for calculating threat actor rankings"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def calculate(
        self,
        business_vertical: str,
        sub_vertical: Optional[str] = None
    ) -> CalculateResponse:
        """
        Calculate top 5 threat actors for given industry
        """
        # Match industry
        industry = await self._match_industry(business_vertical, sub_vertical)
        industry_id = industry.id if industry else None
        
        # Get or calculate actor-industry scores
        if industry_id:
            scores = await self._get_actor_industry_scores(industry_id)
        else:
            # If no industry match, return empty results
            return CalculateResponse(
                request_id=uuid.uuid4(),
                industry_id=None,
                results=[],
                metadata={
                    "calculated_at": date.today().isoformat(),
                    "message": "Industry not found. Please check available industries."
                }
            )
        
        # Get top 5 actors
        top_actors = scores[:5]
        
        # Build results
        results = []
        for score in top_actors:
            actor_result = await self._build_actor_result(
                score.threat_actor_group_id,
                industry_id,
                score.weighted_score,
                score.total_evidence_count
            )
            results.append(actor_result)
        
        # Get metadata
        total_evidence = await self._get_total_evidence_count(industry_id)
        sources_used = await self._get_sources_used(industry_id)
        
        return CalculateResponse(
            request_id=uuid.uuid4(),
            industry_id=industry_id,
            results=results,
            metadata={
                "calculated_at": date.today().isoformat(),
                "total_evidence_items": total_evidence,
                "sources_used": sources_used
            }
        )
    
    async def _match_industry(
        self,
        business_vertical: str,
        sub_vertical: Optional[str] = None
    ) -> Optional[Industry]:
        """Match industry by name, with fallback to parent if sub-vertical has no evidence"""
        matched_industry = None
        
        # Try sub-vertical first if provided
        if sub_vertical:
            result = await self.db.execute(
                select(Industry).where(Industry.name.ilike(f"%{sub_vertical}%"))
            )
            matched_industry = result.scalar_one_or_none()
        
        # Try business vertical if no sub-vertical match
        if not matched_industry:
            result = await self.db.execute(
                select(Industry).where(Industry.name.ilike(f"%{business_vertical}%"))
            )
            matched_industry = result.scalar_one_or_none()
        
        # If we have a sub-vertical with no evidence, check if parent has evidence
        if matched_industry:
            # Get parent_id directly from database to avoid lazy loading
            result = await self.db.execute(
                select(Industry.parent_id).where(Industry.id == matched_industry.id)
            )
            parent_id = result.scalar_one_or_none()
            
            if parent_id:
                from app.models import EvidenceItem
                from sqlalchemy import func
                
                # Check evidence count for sub-vertical
                result = await self.db.execute(
                    select(func.count(EvidenceItem.id))
                    .where(EvidenceItem.industry_id == matched_industry.id)
                )
                sub_evidence_count = result.scalar() or 0
                
                # Check evidence count for parent
                result = await self.db.execute(
                    select(func.count(EvidenceItem.id))
                    .where(EvidenceItem.industry_id == parent_id)
                )
                parent_evidence_count = result.scalar() or 0
                
                # If sub-vertical has no evidence but parent does, use parent
                if sub_evidence_count == 0 and parent_evidence_count > 0:
                    result = await self.db.execute(
                        select(Industry).where(Industry.id == parent_id)
                    )
                    return result.scalar_one_or_none()
        
        return matched_industry
    
    async def _get_actor_industry_scores(
        self,
        industry_id: UUID
    ) -> List[ActorIndustryScore]:
        """Get precomputed actor-industry scores, or calculate if missing"""
        result = await self.db.execute(
            select(ActorIndustryScore)
            .where(ActorIndustryScore.industry_id == industry_id)
            .order_by(ActorIndustryScore.weighted_score.desc())
        )
        scores = result.scalars().all()
        
        # If no precomputed scores, calculate on-the-fly
        if not scores:
            await self._calculate_actor_industry_scores(industry_id)
            result = await self.db.execute(
                select(ActorIndustryScore)
                .where(ActorIndustryScore.industry_id == industry_id)
                .order_by(ActorIndustryScore.weighted_score.desc())
            )
            scores = result.scalars().all()
        
        return list(scores)
    
    async def _calculate_actor_industry_scores(self, industry_id: UUID):
        """Calculate and store actor-industry scores"""
        # Get all evidence for this industry, eagerly load source
        from sqlalchemy.orm import selectinload
        
        result = await self.db.execute(
            select(EvidenceItem)
            .options(selectinload(EvidenceItem.source))
            .where(EvidenceItem.industry_id == industry_id)
        )
        evidence_items = result.scalars().all()
        
        # Group by actor and calculate scores
        actor_scores = {}
        today = date.today()
        
        for evidence in evidence_items:
            actor_id = evidence.threat_actor_group_id
            
            if actor_id not in actor_scores:
                actor_scores[actor_id] = {
                    "total_score": 0.0,
                    "count": 0
                }
            
            # Calculate weighted score for this evidence
            days_ago = (today - evidence.source_date).days
            recency_weight = 1.0 + (days_ago / 365.0) * settings.recency_decay_factor
            recency_weight = min(recency_weight, 2.0)  # Cap at 2.0
            
            source_reliability = (evidence.source.reliability_score / 10.0) if evidence.source else 0.5
            
            evidence_score = 1.0 * recency_weight * source_reliability
            
            actor_scores[actor_id]["total_score"] += evidence_score
            actor_scores[actor_id]["count"] += 1
        
        # Store or update scores
        for actor_id, score_data in actor_scores.items():
            # Check if score exists
            result = await self.db.execute(
                select(ActorIndustryScore).where(
                    and_(
                        ActorIndustryScore.threat_actor_group_id == actor_id,
                        ActorIndustryScore.industry_id == industry_id
                    )
                )
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                existing.weighted_score = score_data["total_score"]
                existing.total_evidence_count = score_data["count"]
                existing.last_calculated_at = today
            else:
                new_score = ActorIndustryScore(
                    threat_actor_group_id=actor_id,
                    industry_id=industry_id,
                    weighted_score=score_data["total_score"],
                    total_evidence_count=score_data["count"],
                    last_calculated_at=today
                )
                self.db.add(new_score)
        
        await self.db.commit()
    
    async def _build_actor_result(
        self,
        actor_id: UUID,
        industry_id: UUID,
        weighted_score: float,
        evidence_count: int
    ) -> ActorResult:
        """Build actor result with techniques and explanations"""
        # Get actor
        result = await self.db.execute(
            select(ThreatActorGroup).where(ThreatActorGroup.id == actor_id)
        )
        actor = result.scalar_one()
        
        # Get top techniques
        top_techniques = await self._get_top_techniques(actor_id, industry_id)
        
        # Get explanations (source citations)
        explanations = await self._get_explanations(actor_id, industry_id)
        
        # Determine confidence
        confidence = self._calculate_confidence(evidence_count, explanations)
        
        return ActorResult(
            threat_actor_group=ThreatActorInfo(
                id=actor.id,
                name=actor.name,
                aliases=actor.aliases or [],
                mitre_id=actor.mitre_id
            ),
            confidence=confidence,
            weighted_score=weighted_score,
            top_techniques=top_techniques,
            explanations=explanations[:5]  # Top 5 explanations
        )
    
    async def _get_top_techniques(
        self,
        actor_id: UUID,
        industry_id: UUID,
        limit: int = 10
    ) -> List[TechniqueScore]:
        """Get top techniques for actor in industry context"""
        # Get precomputed scores
        result = await self.db.execute(
            select(ActorTechniqueScore)
            .where(
                and_(
                    ActorTechniqueScore.threat_actor_group_id == actor_id,
                    or_(
                        ActorTechniqueScore.industry_id == industry_id,
                        ActorTechniqueScore.industry_id.is_(None)
                    )
                )
            )
            .order_by(ActorTechniqueScore.weighted_score.desc())
            .limit(limit)
        )
        technique_scores = result.scalars().all()
        
        # If no precomputed scores, calculate on-the-fly
        if not technique_scores:
            await self._calculate_actor_technique_scores(actor_id, industry_id)
            result = await self.db.execute(
                select(ActorTechniqueScore)
                .where(
                    and_(
                        ActorTechniqueScore.threat_actor_group_id == actor_id,
                        or_(
                            ActorTechniqueScore.industry_id == industry_id,
                            ActorTechniqueScore.industry_id.is_(None)
                        )
                    )
                )
                .order_by(ActorTechniqueScore.weighted_score.desc())
                .limit(limit)
            )
            technique_scores = result.scalars().all()
        
        # Build response
        results = []
        for score in technique_scores:
            # Get technique details
            tech_result = await self.db.execute(
                select(MitreTechnique).where(MitreTechnique.id == score.technique_id)
            )
            technique = tech_result.scalar_one()
            
            results.append(TechniqueScore(
                technique=TechniqueInfo(
                    id=technique.id,
                    technique_id=technique.technique_id or "",
                    name=technique.name or "",
                    tactic=technique.tactic or "Unknown",
                    description=technique.description,
                    url=technique.url
                ),
                score=score.weighted_score,
                evidence_count=score.evidence_count
            ))
        
        return results
    
    async def _calculate_actor_technique_scores(
        self,
        actor_id: UUID,
        industry_id: UUID
    ):
        """Calculate and store actor-technique scores"""
        from sqlalchemy.orm import selectinload
        
        # Get evidence for this actor and industry, eagerly load source
        result = await self.db.execute(
            select(EvidenceItem)
            .options(selectinload(EvidenceItem.source))
            .where(
                and_(
                    EvidenceItem.threat_actor_group_id == actor_id,
                    or_(
                        EvidenceItem.industry_id == industry_id,
                        EvidenceItem.industry_id.is_(None)
                    ),
                    EvidenceItem.technique_id.isnot(None)
                )
            )
        )
        evidence_items = result.scalars().all()
        
        # Group by technique
        technique_scores = {}
        today = date.today()
        
        for evidence in evidence_items:
            if not evidence.technique_id:
                continue
            
            tech_id = evidence.technique_id
            
            if tech_id not in technique_scores:
                technique_scores[tech_id] = {
                    "total_score": 0.0,
                    "count": 0,
                    "has_industry_match": False
                }
            
            # Check if industry-specific
            is_industry_specific = evidence.industry_id == industry_id
            if is_industry_specific:
                technique_scores[tech_id]["has_industry_match"] = True
            
            # Calculate score
            days_ago = (today - evidence.source_date).days
            recency_weight = 1.0 + (days_ago / 365.0) * settings.recency_decay_factor
            recency_weight = min(recency_weight, 2.0)
            
            source_reliability = (evidence.source.reliability_score / 10.0) if evidence.source else 0.5
            industry_bonus = settings.industry_match_bonus if is_industry_specific else 1.0
            
            evidence_score = 1.0 * recency_weight * source_reliability * industry_bonus
            
            technique_scores[tech_id]["total_score"] += evidence_score
            technique_scores[tech_id]["count"] += 1
        
        # Store or update scores
        for tech_id, score_data in technique_scores.items():
            result = await self.db.execute(
                select(ActorTechniqueScore).where(
                    and_(
                        ActorTechniqueScore.threat_actor_group_id == actor_id,
                        ActorTechniqueScore.technique_id == tech_id,
                        or_(
                            ActorTechniqueScore.industry_id == industry_id,
                            and_(
                                ActorTechniqueScore.industry_id.is_(None),
                                ActorTechniqueScore.industry_id == None
                            )
                        )
                    )
                )
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                existing.weighted_score = score_data["total_score"]
                existing.evidence_count = score_data["count"]
                existing.last_calculated_at = today
            else:
                new_score = ActorTechniqueScore(
                    threat_actor_group_id=actor_id,
                    technique_id=tech_id,
                    industry_id=industry_id if score_data["has_industry_match"] else None,
                    weighted_score=score_data["total_score"],
                    evidence_count=score_data["count"],
                    last_calculated_at=today
                )
                self.db.add(new_score)
        
        await self.db.commit()
    
    async def _get_explanations(
        self,
        actor_id: UUID,
        industry_id: UUID,
        limit: int = 5
    ) -> List[Explanation]:
        """Get source citations/explanations, deduplicated by source"""
        result = await self.db.execute(
            select(EvidenceItem)
            .where(
                and_(
                    EvidenceItem.threat_actor_group_id == actor_id,
                    EvidenceItem.industry_id == industry_id
                )
            )
            .order_by(EvidenceItem.source_date.desc())
            .limit(limit * 3)  # Get more to account for deduplication
        )
        evidence_items = result.scalars().all()
        
        # Deduplicate by source_title and source_url
        seen = set()
        explanations = []
        for evidence in evidence_items:
            # Create a unique key for deduplication
            title = evidence.source_title or "Unknown"
            url = evidence.source_url or ""
            key = (title, url)
            
            # Skip if we've already seen this source
            if key in seen:
                continue
            
            seen.add(key)
            explanations.append(Explanation(
                source_title=title,
                source_url=url,
                source_date=evidence.source_date,
                excerpt=evidence.excerpt
            ))
            
            # Stop once we have enough unique explanations
            if len(explanations) >= limit:
                break
        
        return explanations
    
    def _calculate_confidence(
        self,
        evidence_count: int,
        explanations: List[Explanation]
    ) -> str:
        """Calculate confidence level (High/Medium/Low)"""
        if evidence_count >= 5 and len(explanations) >= 2:
            # Check recency
            today = date.today()
            recent_count = sum(
                1 for exp in explanations
                if (today - exp.source_date).days <= 180
            )
            
            if recent_count >= 1:
                return "High"
        
        if evidence_count >= 2:
            return "Medium"
        
        return "Low"
    
    async def _get_total_evidence_count(self, industry_id: UUID) -> int:
        """Get total evidence count for industry"""
        result = await self.db.execute(
            select(func.count(EvidenceItem.id))
            .where(EvidenceItem.industry_id == industry_id)
        )
        return result.scalar() or 0
    
    async def _get_sources_used(self, industry_id: UUID) -> List[str]:
        """Get list of source names used for this industry"""
        from app.models import Source
        
        result = await self.db.execute(
            select(EvidenceItem.source_id)
            .where(EvidenceItem.industry_id == industry_id)
            .distinct()
        )
        source_ids = [row[0] for row in result.all()]
        
        if not source_ids:
            return []
        
        result = await self.db.execute(
            select(Source.name).where(Source.id.in_(source_ids))
        )
        return [row[0] for row in result.all()]
