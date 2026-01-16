"""
Seed script for industries
Uses NAICS (North American Industry Classification System) - a free public classification
Run with: python scripts/seed_industries.py
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import AsyncSessionLocal, engine
from app.models import Industry
from app.services.ingestion.naics_full import get_industries_from_naics
from sqlalchemy import select


# Get industries from NAICS-based classification
INDUSTRIES_DATA = get_industries_from_naics()


async def seed_industries(force: bool = False):
    """Seed industries into database"""
    async with AsyncSessionLocal() as session:
        # Check if industries already exist
        result = await session.execute(select(Industry))
        existing = result.scalars().all()
        
        if existing and not force:
            print(f"Industries already exist ({len(existing)} found). Use force=True to reseed.")
            return
        
        # Create industries
        industry_map = {}
        
        # First pass: create all industries (parents first)
        # Sort by level to ensure parents are created before children
        sorted_data = sorted(INDUSTRIES_DATA, key=lambda x: x.get("level", 0))
        
        for ind_data in sorted_data:
            # Skip if parent_name is set (will handle in second pass)
            if "parent_name" in ind_data and ind_data["parent_name"]:
                continue
                
            industry = Industry(
                name=ind_data["name"],
                code=ind_data["code"],
                naics_code=ind_data.get("naics_code"),
                parent_id=None
            )
            session.add(industry)
            industry_map[ind_data["name"]] = industry
        
        await session.flush()
        
        # Second pass: create children and set parent relationships
        for ind_data in sorted_data:
            if "parent_name" in ind_data and ind_data["parent_name"]:
                parent_name = ind_data["parent_name"]
                parent = industry_map.get(parent_name)
                
                if parent:
                    # Check if child already exists
                    if ind_data["name"] not in industry_map:
                        # Create child industry
                        industry = Industry(
                            name=ind_data["name"],
                            code=ind_data["code"],
                            naics_code=ind_data.get("naics_code"),
                            parent_id=parent.id
                        )
                        session.add(industry)
                        industry_map[ind_data["name"]] = industry
                    else:
                        # Update existing child's parent
                        industry_map[ind_data["name"]].parent_id = parent.id
        
        await session.commit()
        print(f"Successfully seeded {len(INDUSTRIES_DATA)} industries")


if __name__ == "__main__":
    asyncio.run(seed_industries())
