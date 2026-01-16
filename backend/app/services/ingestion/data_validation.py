"""
Data validation and quality checks for ingested evidence
"""
from typing import Dict, List, Optional
from datetime import date, datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.models import EvidenceItem, Source, ThreatActorGroup, MitreTechnique, Industry
from app.utils.logging import setup_logging

logger = setup_logging()


class DataValidator:
    """Validate and check quality of ingested data"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def validate_evidence_item(self, evidence: EvidenceItem) -> Dict[str, any]:
        """
        Validate a single evidence item
        Returns dict with validation results
        """
        issues = []
        warnings = []
        
        # Check required fields
        if not evidence.source_title or len(evidence.source_title.strip()) < 5:
            issues.append("Missing or too short title")
        
        if not evidence.source_url:
            issues.append("Missing source URL")
        elif not evidence.source_url.startswith(("http://", "https://")):
            warnings.append("Invalid URL format")
        
        if not evidence.source_date:
            issues.append("Missing source date")
        elif evidence.source_date > date.today():
            issues.append("Future date")
        elif evidence.source_date < date(2000, 1, 1):
            warnings.append("Very old date (pre-2000)")
        
        # Check relationships
        if not evidence.threat_actor_group_id:
            issues.append("Missing threat actor")
        
        if not evidence.technique_id and not evidence.industry_id:
            warnings.append("No technique or industry linked")
        
        # Check excerpt quality
        if not evidence.excerpt or len(evidence.excerpt.strip()) < 20:
            warnings.append("Short or missing excerpt")
        
        # Check confidence score
        if evidence.confidence_score < 3:
            warnings.append("Low confidence score")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "score": max(0, 10 - len(issues) * 2 - len(warnings))
        }
    
    async def get_quality_report(self) -> Dict:
        """
        Generate overall data quality report
        """
        # Count total evidence items
        result = await self.db.execute(select(func.count(EvidenceItem.id)))
        total_items = result.scalar()
        
        # Count items by validation status
        result = await self.db.execute(select(EvidenceItem))
        all_items = result.scalars().all()
        
        valid_count = 0
        invalid_count = 0
        warning_count = 0
        issues_found = {}
        
        for item in all_items[:1000]:  # Sample first 1000 for performance
            validation = await self.validate_evidence_item(item)
            if validation["valid"]:
                valid_count += 1
            else:
                invalid_count += 1
            
            if validation["warnings"]:
                warning_count += 1
            
            for issue in validation["issues"]:
                issues_found[issue] = issues_found.get(issue, 0) + 1
        
        # Check for orphaned items
        result = await self.db.execute(
            select(func.count(EvidenceItem.id)).where(
                EvidenceItem.threat_actor_group_id.is_(None)
            )
        )
        orphaned_actors = result.scalar()
        
        result = await self.db.execute(
            select(func.count(EvidenceItem.id)).where(
                and_(
                    EvidenceItem.technique_id.is_(None),
                    EvidenceItem.industry_id.is_(None)
                )
            )
        )
        orphaned_links = result.scalar()
        
        # Check recency
        thirty_days_ago = date.today() - timedelta(days=30)
        result = await self.db.execute(
            select(func.count(EvidenceItem.id)).where(
                EvidenceItem.source_date >= thirty_days_ago
            )
        )
        recent_items = result.scalar()
        
        return {
            "total_items": total_items,
            "valid_items": valid_count,
            "invalid_items": invalid_count,
            "items_with_warnings": warning_count,
            "common_issues": issues_found,
            "orphaned_actor_items": orphaned_actors,
            "orphaned_link_items": orphaned_links,
            "recent_items_30d": recent_items,
            "quality_score": round((valid_count / max(1, valid_count + invalid_count)) * 100, 2)
        }
    
    async def find_duplicates(self, limit: int = 100) -> List[Dict]:
        """
        Find potential duplicate evidence items
        """
        # Find items with same URL and similar dates
        result = await self.db.execute(
            select(EvidenceItem)
            .order_by(EvidenceItem.source_url, EvidenceItem.source_date)
            .limit(limit * 2)
        )
        items = result.scalars().all()
        
        duplicates = []
        seen_urls = {}
        
        for item in items:
            url = item.source_url
            if url in seen_urls:
                # Check if dates are close (within 7 days)
                date_diff = abs((item.source_date - seen_urls[url]["date"]).days)
                if date_diff <= 7:
                    duplicates.append({
                        "url": url,
                        "item1_id": str(seen_urls[url]["id"]),
                        "item2_id": str(item.id),
                        "date_diff_days": date_diff
                    })
            else:
                seen_urls[url] = {"id": item.id, "date": item.source_date}
        
        return duplicates[:limit]
    
    async def get_source_statistics(self) -> Dict:
        """
        Get statistics for each source
        """
        result = await self.db.execute(select(Source))
        sources = result.scalars().all()
        
        stats = {}
        for source in sources:
            result = await self.db.execute(
                select(func.count(EvidenceItem.id)).where(
                    EvidenceItem.source_id == source.id
                )
            )
            count = result.scalar()
            
            # Get recent items
            thirty_days_ago = date.today() - timedelta(days=30)
            result = await self.db.execute(
                select(func.count(EvidenceItem.id)).where(
                    and_(
                        EvidenceItem.source_id == source.id,
                        EvidenceItem.source_date >= thirty_days_ago
                    )
                )
            )
            recent_count = result.scalar()
            
            stats[source.name] = {
                "total_items": count,
                "recent_items_30d": recent_count,
                "reliability_score": source.reliability_score,
                "last_checked": source.last_checked_at.isoformat() if source.last_checked_at else None
            }
        
        return stats
