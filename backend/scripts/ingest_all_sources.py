"""
Ingest from all available data sources
This script runs all working ingestion sources to build a comprehensive evidence base
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
from app.services.ingestion.mandiant import MandiantIngester
from app.services.ingestion.microsoft_security import MicrosoftSecurityIngester
from app.services.ingestion.crowdstrike import CrowdStrikeIngester
from app.services.ingestion.unit42 import Unit42Ingester
from app.services.ingestion.google_tag import GoogleTagIngester
from app.services.ingestion.cisa_ics import CisaIcsIngester
from app.services.ingestion.nist_nvd import NistNvdIngester
from app.services.ingestion.github_security import GitHubSecurityIngester
from app.services.calculator import CalculatorService
from sqlalchemy import select, func
from app.models import EvidenceItem, Source


async def ingest_all_sources():
    """Ingest from all available sources"""
    print("=" * 70)
    print("ATLAS - Comprehensive Data Ingestion")
    print("=" * 70)
    print()
    
    async with AsyncSessionLocal() as db:
        total_evidence_before = 0
        result = await db.execute(select(func.count(EvidenceItem.id)))
        total_evidence_before = result.scalar()
        
        print(f"Starting with {total_evidence_before} evidence items")
        print()
        
        # 1. MITRE ATT&CK (always run - creates actors and techniques)
        print("1. MITRE ATT&CK...")
        try:
            mitre_ingester = MitreIngester(db)
            mitre_result = await mitre_ingester.ingest()
            print(f"   ✓ {mitre_result.get('actors_created', 0)} actors, "
                  f"{mitre_result.get('techniques_created', 0)} techniques, "
                  f"{mitre_result.get('relationships_created', 0)} relationships")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 2. CISA KEV (working - high value)
        print("2. CISA KEV (Known Exploited Vulnerabilities)...")
        try:
            kev_ingester = CisaKevIngester(db)
            kev_result = await kev_ingester.ingest()
            print(f"   ✓ {kev_result.get('vulnerabilities_processed', 0)} vulnerabilities, "
                  f"{kev_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 3. CISA Advisories (may need fixing)
        print("3. CISA Advisories...")
        try:
            cisa_ingester = CisaIngester(db)
            cisa_result = await cisa_ingester.ingest(limit=30)
            if "error" in cisa_result:
                print(f"   ⚠ {cisa_result['error']}")
            else:
                print(f"   ✓ {cisa_result.get('advisories_processed', 0)} advisories, "
                      f"{cisa_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 4. FBI Flash Reports (may need fixing)
        print("4. FBI Flash Reports...")
        try:
            fbi_ingester = FbiIngester(db)
            fbi_result = await fbi_ingester.ingest(limit=30)
            if "error" in fbi_result:
                print(f"   ⚠ {fbi_result['error']}")
            else:
                print(f"   ✓ {fbi_result.get('reports_processed', 0)} reports, "
                      f"{fbi_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 5. Mandiant Reports (new)
        print("5. Mandiant Reports...")
        try:
            mandiant_ingester = MandiantIngester(db)
            mandiant_result = await mandiant_ingester.ingest(limit=30)
            if "error" in mandiant_result:
                print(f"   ⚠ {mandiant_result['error']}")
            else:
                print(f"   ✓ {mandiant_result.get('reports_processed', 0)} reports, "
                      f"{mandiant_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 6. Microsoft Security Blog (new)
        print("6. Microsoft Security Blog...")
        try:
            ms_ingester = MicrosoftSecurityIngester(db)
            ms_result = await ms_ingester.ingest(limit=30)
            if "error" in ms_result:
                print(f"   ⚠ {ms_result['error']}")
            else:
                print(f"   ✓ {ms_result.get('posts_processed', 0)} posts, "
                      f"{ms_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 7. CrowdStrike Blog (new)
        print("7. CrowdStrike Blog...")
        try:
            from app.services.ingestion.crowdstrike import CrowdStrikeIngester
            cs_ingester = CrowdStrikeIngester(db)
            cs_result = await cs_ingester.ingest(limit=30)
            if "error" in cs_result:
                print(f"   ⚠ {cs_result['error']}")
            else:
                print(f"   ✓ {cs_result.get('posts_processed', 0)} posts, "
                      f"{cs_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 8. Unit 42 Reports (new)
        print("8. Unit 42 Reports...")
        try:
            from app.services.ingestion.unit42 import Unit42Ingester
            u42_ingester = Unit42Ingester(db)
            u42_result = await u42_ingester.ingest(limit=30)
            if "error" in u42_result:
                print(f"   ⚠ {u42_result['error']}")
            else:
                print(f"   ✓ {u42_result.get('reports_processed', 0)} reports, "
                      f"{u42_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 9. Google Threat Analysis Group (new)
        print("9. Google Threat Analysis Group...")
        try:
            from app.services.ingestion.google_tag import GoogleTagIngester
            tag_ingester = GoogleTagIngester(db)
            tag_result = await tag_ingester.ingest(limit=30)
            if "error" in tag_result:
                print(f"   ⚠ {tag_result['error']}")
            else:
                print(f"   ✓ {tag_result.get('posts_processed', 0)} posts, "
                      f"{tag_result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # Summary
        result = await db.execute(select(func.count(EvidenceItem.id)))
        total_evidence_after = result.scalar()
        
        result = await db.execute(select(Source))
        sources = result.scalars().all()
        
        print("=" * 70)
        print("Summary")
        print("=" * 70)
        print(f"Total Evidence Items: {total_evidence_after} (+{total_evidence_after - total_evidence_before})")
        print()
        print("Sources:")
        for source in sources:
            result = await db.execute(
                select(func.count(EvidenceItem.id)).where(EvidenceItem.source_id == source.id)
            )
            count = result.scalar()
            print(f"  {source.name}: {count} items")
        print()
        
        # Recalculate scores
        print("Recalculating scores for all industries...")
        calculator = CalculatorService(db)
        from app.models import Industry
        
        result = await db.execute(select(Industry))
        industries = result.scalars().all()
        
        recalculated = 0
        for industry in industries:
            try:
                await calculator._calculate_actor_industry_scores(industry.id)
                recalculated += 1
            except Exception as e:
                print(f"  ⚠ Error recalculating {industry.name}: {e}")
        
        print(f"✓ Recalculated scores for {recalculated} industries")
        print()
        print("Done!")


if __name__ == "__main__":
    asyncio.run(ingest_all_sources())
