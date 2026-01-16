"""
Production Data Setup Script
This script helps populate the database with real data from free sources
Run with: python scripts/production_data_setup.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import AsyncSessionLocal
from app.services.ingestion.mitre import MitreIngester
from app.services.ingestion.cisa_kev import CisaKevIngester
from app.services.ingestion.cisa import CisaIngester
from app.services.ingestion.fbi import FbiIngester
from app.services.calculator import CalculatorService


async def setup_production_data():
    """Set up production data from all available sources"""
    print("=" * 60)
    print("Production Data Setup")
    print("=" * 60)
    print()
    
    async with AsyncSessionLocal() as db:
        # 1. MITRE ATT&CK (if not already done)
        print("Step 1: Ingesting MITRE ATT&CK data...")
        mitre_ingester = MitreIngester(db)
        mitre_result = await mitre_ingester.ingest()
        print(f"  ✓ MITRE: {mitre_result.get('actors_created', 0)} actors, "
              f"{mitre_result.get('techniques_created', 0)} techniques")
        print()
        
        # 2. CISA KEV (Known Exploited Vulnerabilities)
        print("Step 2: Ingesting CISA KEV data...")
        kev_ingester = CisaKevIngester(db)
        kev_result = await kev_ingester.ingest()
        print(f"  ✓ CISA KEV: {kev_result.get('vulnerabilities_processed', 0)} vulnerabilities, "
              f"{kev_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 3. CISA Advisories (try to fix scraper)
        print("Step 3: Ingesting CISA Advisories...")
        cisa_ingester = CisaIngester(db)
        cisa_result = await cisa_ingester.ingest(limit=20)
        if "error" in cisa_result:
            print(f"  ⚠ CISA Advisories: {cisa_result['error']}")
            print("    (HTML structure may have changed - needs manual fix)")
        else:
            print(f"  ✓ CISA Advisories: {cisa_result.get('advisories_processed', 0)} advisories, "
                  f"{cisa_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 4. FBI Flash Reports
        print("Step 4: Ingesting FBI Flash Reports...")
        fbi_ingester = FbiIngester(db)
        fbi_result = await fbi_ingester.ingest(limit=20)
        if "error" in fbi_result:
            print(f"  ⚠ FBI Reports: {fbi_result['error']}")
            print("    (HTML structure may have changed - needs manual fix)")
        else:
            print(f"  ✓ FBI Reports: {fbi_result.get('reports_processed', 0)} reports, "
                  f"{fbi_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 5. Mandiant Reports
        print("Step 5: Ingesting Mandiant Reports...")
        from app.services.ingestion.mandiant import MandiantIngester
        mandiant_ingester = MandiantIngester(db)
        mandiant_result = await mandiant_ingester.ingest(limit=20)
        if "error" in mandiant_result:
            print(f"  ⚠ Mandiant Reports: {mandiant_result['error']}")
        else:
            print(f"  ✓ Mandiant Reports: {mandiant_result.get('reports_processed', 0)} reports, "
                  f"{mandiant_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 6. Microsoft Security Blog
        print("Step 6: Ingesting Microsoft Security Blog...")
        from app.services.ingestion.microsoft_security import MicrosoftSecurityIngester
        ms_ingester = MicrosoftSecurityIngester(db)
        ms_result = await ms_ingester.ingest(limit=20)
        if "error" in ms_result:
            print(f"  ⚠ Microsoft Security Blog: {ms_result['error']}")
        else:
            print(f"  ✓ Microsoft Security Blog: {ms_result.get('posts_processed', 0)} posts, "
                  f"{ms_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 7. CrowdStrike Blog
        print("Step 7: Ingesting CrowdStrike Blog...")
        from app.services.ingestion.crowdstrike import CrowdStrikeIngester
        cs_ingester = CrowdStrikeIngester(db)
        cs_result = await cs_ingester.ingest(limit=20)
        if "error" in cs_result:
            print(f"  ⚠ CrowdStrike Blog: {cs_result['error']}")
        else:
            print(f"  ✓ CrowdStrike Blog: {cs_result.get('posts_processed', 0)} posts, "
                  f"{cs_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 8. Unit 42 Reports
        print("Step 8: Ingesting Unit 42 Reports...")
        from app.services.ingestion.unit42 import Unit42Ingester
        u42_ingester = Unit42Ingester(db)
        u42_result = await u42_ingester.ingest(limit=20)
        if "error" in u42_result:
            print(f"  ⚠ Unit 42 Reports: {u42_result['error']}")
        else:
            print(f"  ✓ Unit 42 Reports: {u42_result.get('reports_processed', 0)} reports, "
                  f"{u42_result.get('evidence_created', 0)} evidence items")
        print()
        
        # 9. Recalculate all scores
        print("Step 9: Recalculating scores for all industries...")
        calculator = CalculatorService(db)
        from sqlalchemy import select
        from app.models import Industry
        
        result = await db.execute(select(Industry))
        industries = result.scalars().all()
        
        for industry in industries:
            try:
                await calculator._calculate_actor_industry_scores(industry.id)
                print(f"  ✓ Recalculated scores for {industry.name}")
            except Exception as e:
                print(f"  ⚠ Error recalculating {industry.name}: {e}")
        
        print()
        
        # 6. Summary
        print("=" * 60)
        print("Summary")
        print("=" * 60)
        
        from app.models import ThreatActorGroup, EvidenceItem
        from sqlalchemy import func
        
        result = await db.execute(select(func.count(ThreatActorGroup.id)))
        actor_count = result.scalar()
        
        result = await db.execute(select(func.count(EvidenceItem.id)))
        evidence_count = result.scalar()
        
        result = await db.execute(select(func.count(EvidenceItem.id)).where(EvidenceItem.industry_id.isnot(None)))
        evidence_with_industry = result.scalar()
        
        print(f"Total Actors: {actor_count}")
        print(f"Total Evidence Items: {evidence_count}")
        print(f"Evidence with Industry: {evidence_with_industry}")
        print()
        
        if evidence_count < 100:
            print("⚠ WARNING: Low evidence count. Consider:")
            print("  - Fixing CISA/FBI scrapers")
            print("  - Adding more data sources")
            print("  - Running historical data backfill")
        else:
            print("✓ Good evidence coverage!")
        
        print()
        print("Next steps:")
        print("  1. Test the calculator with various industries")
        print("  2. Monitor ingestion jobs (scheduler)")
        print("  3. Add more data sources as needed")


if __name__ == "__main__":
    asyncio.run(setup_production_data())
