"""
Update existing industries with NAICS codes
This script adds NAICS codes to existing industries without breaking relationships
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import AsyncSessionLocal
from app.models import Industry
from app.services.ingestion.naics_full import get_industries_from_naics
from sqlalchemy import select

async def update_naics_codes():
    """Update existing industries with NAICS codes"""
    async with AsyncSessionLocal() as db:
        # Get all NAICS industries
        naics_industries = get_industries_from_naics()
        
        # Create mapping by name
        naics_by_name = {ind["name"]: ind for ind in naics_industries}
        
        # Get all existing industries
        result = await db.execute(select(Industry))
        existing = result.scalars().all()
        
        updated = 0
        for industry in existing:
            naics_data = naics_by_name.get(industry.name)
            if naics_data and naics_data.get("naics_code"):
                industry.naics_code = naics_data["naics_code"]
                updated += 1
        
        await db.commit()
        print(f"Updated {updated} industries with NAICS codes")
        print(f"Total industries: {len(existing)}")

if __name__ == "__main__":
    asyncio.run(update_naics_codes())
