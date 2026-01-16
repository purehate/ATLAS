"""
Breach detection service
Analyzes evidence items to detect potential breaches or security incidents
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload
from typing import Dict, List, Optional
from datetime import date, timedelta
from app.models import EvidenceItem, Source
from app.utils.logging import setup_logging

logger = setup_logging()

# Keywords that suggest breaches or security incidents
BREACH_KEYWORDS = [
    "breach", "breached", "compromised", "compromise", "incident", "attack",
    "ransomware", "data breach", "security breach", "cyber attack",
    "unauthorized access", "data exfiltration", "leaked", "stolen data",
    "security incident", "cyber incident", "intrusion", "hacked",
    "data theft", "malware", "phishing attack", "exploit", "vulnerability exploited"
]

# High-confidence breach indicators (from specific sources)
HIGH_CONFIDENCE_SOURCES = [
    "CISA Advisory",
    "FBI Flash Report",
    "CISA KEV",  # Known Exploited Vulnerabilities
]


class BreachDetectionService:
    """Service for detecting potential breaches or security incidents"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def check_company_breach(
        self,
        company_name: str,
        industry_keywords: Optional[str] = None
    ) -> Dict:
        """
        Search for public articles/posts about breaches involving this specific company
        Returns breach detection results with links to public reports
        """
        # Search for evidence items mentioning this company AND breach-related keywords
        breach_indicators = []
        
        # 1. Search for company name + breach keywords in evidence items
        breach_evidence = await self._search_company_breach_articles(company_name, industry_keywords)
        breach_indicators.extend(breach_evidence)
        
        # 2. Check CISA KEV for company-specific vulnerabilities (if company name appears)
        kev_evidence = await self._check_cisa_kev_company(company_name)
        if kev_evidence:
            breach_indicators.extend(kev_evidence)
        
        # 3. Check advisories that mention the company name
        advisory_evidence = await self._check_company_advisories(company_name)
        if advisory_evidence:
            breach_indicators.extend(advisory_evidence)
        
        # Calculate breach confidence based on how many articles found
        confidence = self._calculate_breach_confidence(breach_indicators)
        
        # Determine breach status (simpler - just based on if we found articles)
        status = "none"
        if len(breach_indicators) >= 3:
            status = "high"
        elif len(breach_indicators) >= 1:
            status = "medium"
        
        return {
            "status": status,
            "confidence": confidence,
            "articles": breach_indicators[:10],  # Limit to top 10 articles
            "article_count": len(breach_indicators),
            "last_updated": date.today().isoformat(),
            "message": f"Found {len(breach_indicators)} public article(s) mentioning {company_name} and security incidents"
        }
    
    async def _search_company_breach_articles(
        self,
        company_name: str,
        industry_keywords: Optional[str] = None
    ) -> List[Dict]:
        """
        Search for articles that mention the company name AND breach-related keywords
        This finds actual public reports about breaches involving this company
        """
        # Normalize company name for searching (remove common suffixes)
        company_normalized = company_name.lower()
        company_variants = [
            company_normalized,
            company_normalized.replace(" inc", "").replace(" inc.", "").replace(", inc", "").replace(", inc.", ""),
            company_normalized.replace(" corp", "").replace(" corp.", "").replace(", corp", "").replace(", corp.", ""),
            company_normalized.replace(" llc", "").replace(" llc.", "").replace(", llc", "").replace(", llc.", ""),
            company_normalized.replace(" ltd", "").replace(" ltd.", "").replace(", ltd", "").replace(", ltd.", ""),
        ]
        
        # Build search query: company name AND breach keywords
        company_conditions = []
        for variant in company_variants:
            if len(variant) > 2:  # Only search meaningful variants
                company_conditions.append(
                    or_(
                        EvidenceItem.excerpt.ilike(f"%{variant}%"),
                        EvidenceItem.source_title.ilike(f"%{variant}%")
                    )
                )
        
        if not company_conditions:
            return []
        
        # Also need breach keywords
        breach_conditions = []
        for keyword in BREACH_KEYWORDS:
            breach_conditions.append(
                or_(
                    EvidenceItem.excerpt.ilike(f"%{keyword}%"),
                    EvidenceItem.source_title.ilike(f"%{keyword}%")
                )
            )
        
        if not breach_conditions:
            return []
        
        # Query: company name AND breach keyword
        query = select(EvidenceItem).options(
            selectinload(EvidenceItem.source)
        ).where(
            and_(
                or_(*company_conditions),  # Must mention company
                or_(*breach_conditions)   # Must mention breach
            )
        )
        
        # Limit to recent items (last 3 years for breach history)
        three_years_ago = date.today() - timedelta(days=1095)
        query = query.where(EvidenceItem.source_date >= three_years_ago)
        
        # Order by date (most recent first)
        query = query.order_by(EvidenceItem.source_date.desc())
        query = query.limit(20)
        
        result = await self.db.execute(query)
        evidence_items = result.scalars().all()
        
        articles = []
        for item in evidence_items:
            # Verify it's actually about this company (not just mentioning the name)
            excerpt_lower = (item.excerpt or "").lower()
            title_lower = (item.source_title or "").lower()
            combined_text = f"{excerpt_lower} {title_lower}"
            
            # Check if company name appears in context
            company_mentioned = any(variant in combined_text for variant in company_variants if len(variant) > 2)
            breach_mentioned = any(kw.lower() in combined_text for kw in BREACH_KEYWORDS)
            
            if company_mentioned and breach_mentioned:
                # Check source reliability
                source = item.source
                source_reliability = source.reliability_score if source else 5
                
                # Higher confidence for high-reliability sources
                article_confidence = min(100, 40 + (source_reliability * 4))
                
                # Extract relevant excerpt (try to get context around company name)
                excerpt = item.excerpt or ""
                if excerpt:
                    # Try to find sentence with company name
                    sentences = excerpt.split('.')
                    relevant_sentence = ""
                    for sentence in sentences:
                        if any(variant in sentence.lower() for variant in company_variants if len(variant) > 2):
                            relevant_sentence = sentence.strip()
                            break
                    if not relevant_sentence and len(excerpt) > 200:
                        relevant_sentence = excerpt[:200] + "..."
                    elif not relevant_sentence:
                        relevant_sentence = excerpt
                else:
                    relevant_sentence = ""
                
                articles.append({
                    "type": "breach_article",
                    "source": source.name if source else "Unknown",
                    "title": item.source_title,
                    "url": item.source_url,
                    "date": item.source_date.isoformat(),
                    "confidence": article_confidence,
                    "excerpt": relevant_sentence[:300] if relevant_sentence else ""  # First 300 chars
                })
        
        return articles
    
    async def _check_cisa_kev_company(self, company_name: str) -> List[Dict]:
        """Check CISA KEV for vulnerabilities that mention this company"""
        # Normalize company name
        company_normalized = company_name.lower()
        company_variants = [
            company_normalized,
            company_normalized.replace(" inc", "").replace(" inc.", ""),
            company_normalized.replace(" corp", "").replace(" corp.", ""),
        ]
        
        # Search for CISA KEV source
        result = await self.db.execute(
            select(Source).where(Source.name == "CISA KEV")
        )
        kev_source = result.scalar_one_or_none()
        
        if not kev_source:
            return []
        
        # Build company name conditions
        company_conditions = []
        for variant in company_variants:
            if len(variant) > 2:
                company_conditions.append(
                    or_(
                        EvidenceItem.excerpt.ilike(f"%{variant}%"),
                        EvidenceItem.source_title.ilike(f"%{variant}%")
                    )
                )
        
        if not company_conditions:
            return []
        
        # Search evidence items from CISA KEV that mention the company
        query = select(EvidenceItem).options(
            selectinload(EvidenceItem.source)
        ).where(
            and_(
                EvidenceItem.source_id == kev_source.id,
                or_(*company_conditions)
            )
        )
        query = query.order_by(EvidenceItem.source_date.desc()).limit(10)
        
        result = await self.db.execute(query)
        kev_items = result.scalars().all()
        
        articles = []
        for item in kev_items:
            articles.append({
                "type": "cisa_kev",
                "source": "CISA KEV",
                "title": item.source_title,
                "url": item.source_url,
                "date": item.source_date.isoformat(),
                "confidence": 70,  # CISA KEV is reliable
                "excerpt": (item.excerpt or "")[:200]
            })
        
        return articles
    
    async def _check_company_advisories(self, company_name: str) -> List[Dict]:
        """Check CISA advisories that mention this specific company"""
        # Normalize company name
        company_normalized = company_name.lower()
        company_variants = [
            company_normalized,
            company_normalized.replace(" inc", "").replace(" inc.", ""),
            company_normalized.replace(" corp", "").replace(" corp.", ""),
        ]
        
        # Search for CISA Advisory source
        result = await self.db.execute(
            select(Source).where(Source.name == "CISA Advisory")
        )
        cisa_source = result.scalar_one_or_none()
        
        if not cisa_source:
            return []
        
        # Build company name conditions
        company_conditions = []
        for variant in company_variants:
            if len(variant) > 2:
                company_conditions.append(
                    or_(
                        EvidenceItem.excerpt.ilike(f"%{variant}%"),
                        EvidenceItem.source_title.ilike(f"%{variant}%")
                    )
                )
        
        if not company_conditions:
            return []
        
        # Get recent advisories mentioning the company (last 2 years)
        two_years_ago = date.today() - timedelta(days=730)
        
        query = select(EvidenceItem).options(
            selectinload(EvidenceItem.source)
        ).where(
            and_(
                EvidenceItem.source_id == cisa_source.id,
                EvidenceItem.source_date >= two_years_ago,
                or_(*company_conditions)
            )
        )
        
        query = query.order_by(EvidenceItem.source_date.desc()).limit(10)
        
        result = await self.db.execute(query)
        advisories = result.scalars().all()
        
        articles = []
        for item in advisories:
            articles.append({
                "type": "cisa_advisory",
                "source": "CISA Advisory",
                "title": item.source_title,
                "url": item.source_url,
                "date": item.source_date.isoformat(),
                "confidence": 85,  # CISA advisories are high-confidence
                "excerpt": (item.excerpt or "")[:200]
            })
        
        return articles
    
    def _calculate_breach_confidence(self, articles: List[Dict]) -> int:
        """Calculate overall breach confidence score (0-100) based on articles found"""
        if not articles:
            return 0
        
        # Base confidence from number of articles found
        # More articles = higher confidence that breaches were reported
        base_confidence = min(60, len(articles) * 8)
        
        # Add confidence from source reliability
        total_confidence = sum(art.get("confidence", 0) for art in articles)
        avg_confidence = total_confidence / len(articles) if articles else 0
        
        # Weighted average
        final_confidence = (base_confidence * 0.4) + (avg_confidence * 0.6)
        
        # Boost for high-confidence sources (CISA, FBI)
        high_confidence_count = sum(
            1 for art in articles
            if art.get("source") in HIGH_CONFIDENCE_SOURCES
        )
        
        if high_confidence_count > 0:
            final_confidence += min(20, high_confidence_count * 5)
        
        return min(100, int(final_confidence))
