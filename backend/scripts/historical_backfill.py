"""
Historical Data Backfill Script
Downloads and processes historical data from various sources (last 2-3 years)
"""
import asyncio
import sys
from pathlib import Path
from datetime import date, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import AsyncSessionLocal
from app.services.ingestion.cisa import CisaIngester
from app.services.ingestion.fbi import FbiIngester
from app.services.ingestion.mandiant import MandiantIngester
from app.services.ingestion.microsoft_security import MicrosoftSecurityIngester
from app.services.ingestion.crowdstrike import CrowdStrikeIngester
from app.services.ingestion.unit42 import Unit42Ingester
from app.services.ingestion.google_tag import GoogleTagIngester
from app.services.ingestion.cisa_ics import CisaIcsIngester
from app.services.calculator import CalculatorService
from sqlalchemy import select, func
from app.models import EvidenceItem, Industry


async def backfill_historical_data(years_back: int = 2):
    """
    Backfill historical data from all sources
    Note: This may take a long time depending on data volume
    """
    print("=" * 70)
    print("ATLAS - Historical Data Backfill")
    print("=" * 70)
    print(f"Backfilling data from the last {years_back} years")
    print()
    
    async with AsyncSessionLocal() as db:
        # Get initial count
        result = await db.execute(select(func.count(EvidenceItem.id)))
        initial_count = result.scalar()
        print(f"Starting with {initial_count} evidence items")
        print()
        
        # Sources that support historical backfill
        # Note: Some sources may not have historical data available
        
        # 1. CISA Advisories (process more items)
        print("1. CISA Advisories (historical)...")
        try:
            ingester = CisaIngester(db)
            result = await ingester.ingest(limit=200)  # Process more for historical
            print(f"   ✓ {result.get('advisories_processed', 0)} advisories, "
                  f"{result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 2. CISA ICS Advisories
        print("2. CISA ICS Advisories (historical)...")
        try:
            from app.services.ingestion.cisa_ics import CisaIcsIngester
            ingester = CisaIcsIngester(db)
            result = await ingester.ingest(limit=100)
            print(f"   ✓ {result.get('items_processed', 0)} advisories processed")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 3. FBI Flash Reports (process more PDFs)
        print("3. FBI Flash Reports (historical)...")
        try:
            ingester = FbiIngester(db)
            result = await ingester.ingest(limit=100)  # Process more PDFs
            print(f"   ✓ {result.get('reports_processed', 0)} reports, "
                  f"{result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 4. Mandiant Reports (process more)
        print("4. Mandiant Reports (historical)...")
        try:
            ingester = MandiantIngester(db)
            result = await ingester.ingest(limit=100)
            print(f"   ✓ {result.get('reports_processed', 0)} reports processed")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 5. Microsoft Security Blog (process more)
        print("5. Microsoft Security Blog (historical)...")
        try:
            ingester = MicrosoftSecurityIngester(db)
            result = await ingester.ingest(limit=100)
            print(f"   ✓ {result.get('posts_processed', 0)} posts, "
                  f"{result.get('evidence_created', 0)} evidence items")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 6. CrowdStrike Blog (process more)
        print("6. CrowdStrike Blog (historical)...")
        try:
            ingester = CrowdStrikeIngester(db)
            result = await ingester.ingest(limit=100)
            print(f"   ✓ {result.get('posts_processed', 0)} posts processed")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 7. Unit 42 Reports (process more)
        print("7. Unit 42 Reports (historical)...")
        try:
            ingester = Unit42Ingester(db)
            result = await ingester.ingest(limit=100)
            print(f"   ✓ {result.get('reports_processed', 0)} reports processed")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # 8. Google TAG (process more)
        print("8. Google Threat Analysis Group (historical)...")
        try:
            ingester = GoogleTagIngester(db)
            result = await ingester.ingest(limit=100)
            print(f"   ✓ {result.get('posts_processed', 0)} posts processed")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        print()
        
        # Summary
        result = await db.execute(select(func.count(EvidenceItem.id)))
        final_count = result.scalar()
        
        print("=" * 70)
        print("Summary")
        print("=" * 70)
        print(f"Total Evidence Items: {final_count} (+{final_count - initial_count})")
        print()
        
        # Recalculate scores for all industries
        print("Recalculating scores for all industries...")
        calculator = CalculatorService(db)
        
        result = await db.execute(select(Industry))
        industries = result.scalars().all()
        
        recalculated = 0
        for industry in industries:
            try:
                await calculator._calculate_actor_industry_scores(industry.id)
                await calculator._calculate_actor_technique_scores(industry.id)
                recalculated += 1
            except Exception as e:
                print(f"  ⚠ Error recalculating {industry.name}: {e}")
        
        print(f"✓ Recalculated scores for {recalculated} industries")
        print()
        print("Done!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Backfill historical threat intelligence data")
    parser.add_argument("--years", type=int, default=2, help="Number of years to backfill (default: 2)")
    args = parser.parse_args()
    
    asyncio.run(backfill_historical_data(years_back=args.years))
