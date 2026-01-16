"""
Create sample evidence items for testing
This links threat actors to industries based on known patterns
"""
import asyncio
import sys
from pathlib import Path
from datetime import date, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import AsyncSessionLocal
from app.models import ThreatActorGroup, Industry, Source, EvidenceItem, MitreTechnique
from sqlalchemy import select

# Known actor-industry associations for testing
SAMPLE_EVIDENCE = [
    {
        "actor_patterns": ["Lazarus", "APT38", "HIDDEN COBRA"],
        "industries": ["Financial Services", "Banking", "Technology"],
        "techniques": ["T1055", "T1071", "T1566"],
        "description": "Lazarus Group is known for targeting financial institutions and cryptocurrency exchanges"
    },
    {
        "actor_patterns": ["APT28", "Fancy Bear", "Sofacy"],
        "industries": ["Government", "Technology", "Energy"],
        "techniques": ["T1071", "T1566", "T1055"],
        "description": "APT28 targets government, defense, and energy sectors"
    },
    {
        "actor_patterns": ["APT29", "Cozy Bear", "The Dukes"],
        "industries": ["Government", "Technology", "Healthcare"],
        "techniques": ["T1071", "T1055", "T1021"],
        "description": "APT29 targets government and healthcare organizations"
    },
    {
        "actor_patterns": ["APT1", "Comment Crew"],
        "industries": ["Technology", "Software", "Manufacturing"],
        "techniques": ["T1055", "T1071", "T1021"],
        "description": "APT1 targets technology and manufacturing companies"
    },
    {
        "actor_patterns": ["Carbanak", "Anunak"],
        "industries": ["Financial Services", "Banking"],
        "techniques": ["T1055", "T1071", "T1566"],
        "description": "Carbanak specifically targets banks and financial institutions"
    },
]


async def create_sample_evidence():
    """Create sample evidence items"""
    async with AsyncSessionLocal() as db:
        # Get or create a sample source
        result = await db.execute(
            select(Source).where(Source.name == "Sample Test Data")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            source = Source(
                name="Sample Test Data",
                type="test",
                base_url="https://example.com",
                reliability_score=5,
                meta_data={"note": "Sample data for testing"}
            )
            db.add(source)
            await db.flush()
        
        # Get all actors and industries
        result = await db.execute(select(ThreatActorGroup))
        all_actors = result.scalars().all()
        
        result = await db.execute(select(Industry))
        all_industries = {ind.name: ind for ind in result.scalars().all()}
        
        # Get techniques for linking
        result = await db.execute(select(MitreTechnique))
        all_techniques = {tech.technique_id: tech for tech in result.scalars().all()}
        
        evidence_count = 0
        
        for sample in SAMPLE_EVIDENCE:
            # Find matching actors
            matching_actors = []
            for actor in all_actors:
                actor_lower = actor.name.lower()
                for pattern in sample["actor_patterns"]:
                    if pattern.lower() in actor_lower:
                        matching_actors.append(actor)
                        break
                # Also check aliases
                if actor.aliases:
                    for alias in actor.aliases:
                        if alias:
                            for pattern in sample["actor_patterns"]:
                                if pattern.lower() in alias.lower():
                                    if actor not in matching_actors:
                                        matching_actors.append(actor)
                                    break
            
            # Create evidence for each matching actor and industry
            for actor in matching_actors:
                for industry_name in sample["industries"]:
                    industry = all_industries.get(industry_name)
                    if industry:
                        # Check if evidence already exists
                        result = await db.execute(
                            select(EvidenceItem).where(
                                EvidenceItem.threat_actor_group_id == actor.id,
                                EvidenceItem.industry_id == industry.id,
                                EvidenceItem.source_id == source.id
                            )
                        )
                        existing = result.scalar_one_or_none()
                        
                        if not existing:
                            # Link techniques if available
                            technique = None
                            if sample.get("techniques"):
                                # Use first technique from the list
                                tech_id = sample["techniques"][0]
                                technique = all_techniques.get(tech_id)
                            
                            evidence = EvidenceItem(
                                threat_actor_group_id=actor.id,
                                industry_id=industry.id,
                                technique_id=technique.id if technique else None,
                                source_id=source.id,
                                source_url=f"https://example.com/sample/{actor.name}/{industry.name}",
                                source_title=f"Sample: {actor.name} targeting {industry.name}",
                                source_date=date.today() - timedelta(days=30),
                                excerpt=sample["description"],
                                confidence_score=5,
                                meta_data={"sample": True, "techniques": sample.get("techniques", [])}
                            )
                            db.add(evidence)
                            evidence_count += 1
                            
                            # Also create separate evidence items for each technique (for better technique scoring)
                            if sample.get("techniques") and len(sample["techniques"]) > 1:
                                for tech_id in sample["techniques"][1:]:  # Skip first, already added
                                    tech = all_techniques.get(tech_id)
                                    if tech:
                                        # Check if technique evidence exists
                                        tech_result = await db.execute(
                                            select(EvidenceItem).where(
                                                EvidenceItem.threat_actor_group_id == actor.id,
                                                EvidenceItem.industry_id == industry.id,
                                                EvidenceItem.technique_id == tech.id,
                                                EvidenceItem.source_id == source.id
                                            )
                                        )
                                        tech_existing = tech_result.scalar_one_or_none()
                                        
                                        if not tech_existing:
                                            tech_evidence = EvidenceItem(
                                                threat_actor_group_id=actor.id,
                                                industry_id=industry.id,
                                                technique_id=tech.id,
                                                source_id=source.id,
                                                source_url=f"https://example.com/sample/{actor.name}/{industry.name}",
                                                source_title=f"Sample: {actor.name} targeting {industry.name}",
                                                source_date=date.today() - timedelta(days=30),
                                                excerpt=sample["description"],
                                                confidence_score=5,
                                                meta_data={"sample": True}
                                            )
                                            db.add(tech_evidence)
                                            evidence_count += 1
        
        await db.commit()
        print(f"Created {evidence_count} sample evidence items")
        
        # Recalculate scores
        from app.services.calculator import CalculatorService
        calculator = CalculatorService(db)
        
        # Recalculate for all industries
        result = await db.execute(select(Industry))
        industries = result.scalars().all()
        
        for industry in industries:
            try:
                await calculator._calculate_actor_industry_scores(industry.id)
                print(f"Recalculated scores for {industry.name}")
            except Exception as e:
                print(f"Error recalculating for {industry.name}: {e}")


if __name__ == "__main__":
    asyncio.run(create_sample_evidence())
