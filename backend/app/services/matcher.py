from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from rapidfuzz import fuzz
from typing import Optional, List
from app.models import ThreatActorGroup, Industry
from config import settings


# Industry keyword mappings
INDUSTRY_KEYWORDS = {
    "Banking": ["bank", "banking", "financial institution", "credit union", "fintech", "retail bank"],
    "Insurance": ["insurance", "insurer", "underwriter", "actuary"],
    "Investment": ["investment", "asset management", "hedge fund", "private equity", "wealth management"],
    "Healthcare": ["hospital", "healthcare", "medical", "pharmaceutical", "health system", "clinic"],
    "Pharmaceuticals": ["pharmaceutical", "pharma", "drug manufacturer", "biotech"],
    "Medical Devices": ["medical device", "medical equipment", "diagnostic"],
    "Energy": ["energy", "power", "utility", "electric", "grid"],
    "Oil & Gas": ["oil", "gas", "petroleum", "refinery", "drilling"],
    "Utilities": ["utility", "water", "electric", "power grid"],
    "Technology": ["technology", "tech", "software", "saas", "cloud"],
    "Manufacturing": ["manufacturing", "factory", "production", "industrial"],
    "Retail": ["retail", "e-commerce", "store", "merchant"],
    "Government": ["government", "public sector", "municipal", "federal"],
    "Education": ["education", "university", "school", "academic"],
    "Transportation": ["transportation", "logistics", "shipping", "aviation"],
}


async def match_actor(name: str, db: AsyncSession) -> Optional[ThreatActorGroup]:
    """
    Match an actor name to an existing threat actor group
    Uses exact match first, then fuzzy matching
    """
    if not name or not name.strip():
        return None
    
    name_clean = name.strip()
    
    # 1. Exact match on name (case-insensitive)
    result = await db.execute(
        select(ThreatActorGroup).where(
            ThreatActorGroup.name.ilike(name_clean)
        )
    )
    actor = result.scalar_one_or_none()
    if actor:
        return actor
    
    # 2. Exact match on aliases
    result = await db.execute(select(ThreatActorGroup))
    all_actors = result.scalars().all()
    
    for actor in all_actors:
        if actor.aliases:
            for alias in actor.aliases:
                if alias and alias.lower() == name_clean.lower():
                    return actor
    
    # 3. Fuzzy match (threshold: 85%)
    best_match = None
    best_score = 0
    
    for actor in all_actors:
        # Check name
        score = fuzz.ratio(name_clean.lower(), actor.name.lower())
        if score > best_score and score >= 85:
            best_score = score
            best_match = actor
        
        # Check aliases
        if actor.aliases:
            for alias in actor.aliases:
                if alias:
                    score = fuzz.ratio(name_clean.lower(), alias.lower())
                    if score > best_score and score >= 85:
                        best_score = score
                        best_match = actor
    
    return best_match


async def match_industries(text: str, db: AsyncSession) -> List[Industry]:
    """
    Match industry keywords in text to industries
    Returns list of matched industries
    """
    if not text:
        return []
    
    text_lower = text.lower()
    matched_industry_names = set()
    
    # Check keyword mappings
    for industry_name, keywords in INDUSTRY_KEYWORDS.items():
        if any(keyword in text_lower for keyword in keywords):
            matched_industry_names.add(industry_name)
    
    # Query matched industries
    if not matched_industry_names:
        return []
    
    result = await db.execute(
        select(Industry).where(Industry.name.in_(matched_industry_names))
    )
    return list(result.scalars().all())


def extract_technique_ids(text: str) -> List[str]:
    """
    Extract MITRE technique IDs from text
    Pattern: T#### or T####.###
    """
    import re
    pattern = re.compile(r'T\d{4}(?:\.\d{3})?')
    return pattern.findall(text)
