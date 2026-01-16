"""
Script to ingest MITRE ATT&CK data
Run with: python scripts/ingest_mitre.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import AsyncSessionLocal
from app.services.ingestion.mitre import MitreIngester


async def main():
    """Main ingestion function"""
    print("Starting MITRE ATT&CK ingestion...")
    
    async with AsyncSessionLocal() as db:
        ingester = MitreIngester(db)
        result = await ingester.ingest()
        print(f"\nIngestion complete!")
        print(f"Actors created/updated: {result.get('actors_created', 0)}")
        print(f"Techniques created/updated: {result.get('techniques_created', 0)}")
        print(f"Relationships created: {result.get('relationships_created', 0)}")
        
        if 'error' in result:
            print(f"\nError: {result['error']}")


if __name__ == "__main__":
    asyncio.run(main())
