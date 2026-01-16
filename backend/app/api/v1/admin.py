from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.utils.security import verify_admin
from app.services.ingestion.mitre import MitreIngester
from app.services.ingestion.cisa import CisaIngester
from app.services.ingestion.fbi import FbiIngester
from app.services.calculator import CalculatorService
from app.services.ingestion.data_validation import DataValidator
from typing import Dict

router = APIRouter()

@router.get("/data-quality")
async def get_data_quality_report(
    username: str = Depends(verify_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get data quality report"""
    validator = DataValidator(db)
    report = await validator.get_quality_report()
    return report

@router.get("/data-quality/duplicates")
async def get_duplicates(
    limit: int = 100,
    username: str = Depends(verify_admin),
    db: AsyncSession = Depends(get_db)
):
    """Find potential duplicate evidence items"""
    validator = DataValidator(db)
    duplicates = await validator.find_duplicates(limit=limit)
    return {"duplicates": duplicates, "count": len(duplicates)}

@router.get("/data-quality/sources")
async def get_source_statistics(
    username: str = Depends(verify_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get statistics for each data source"""
    validator = DataValidator(db)
    stats = await validator.get_source_statistics()
    return stats


@router.post("/admin/ingest/mitre")
async def ingest_mitre(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger MITRE ATT&CK ingestion"""
    ingester = MitreIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/cisa")
async def ingest_cisa(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger CISA advisories ingestion"""
    ingester = CisaIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/fbi")
async def ingest_fbi(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger FBI Flash Reports ingestion"""
    ingester = FbiIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/cisa-kev")
async def ingest_cisa_kev(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger CISA KEV (Known Exploited Vulnerabilities) ingestion"""
    from app.services.ingestion.cisa_kev import CisaKevIngester
    ingester = CisaKevIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/mandiant")
async def ingest_mandiant(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger Mandiant reports ingestion"""
    from app.services.ingestion.mandiant import MandiantIngester
    ingester = MandiantIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/microsoft")
async def ingest_microsoft(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger Microsoft Security Blog ingestion"""
    from app.services.ingestion.microsoft_security import MicrosoftSecurityIngester
    ingester = MicrosoftSecurityIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/crowdstrike")
async def ingest_crowdstrike(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger CrowdStrike Blog ingestion"""
    from app.services.ingestion.crowdstrike import CrowdStrikeIngester
    ingester = CrowdStrikeIngester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/ingest/unit42")
async def ingest_unit42(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Trigger Unit 42 reports ingestion"""
    from app.services.ingestion.unit42 import Unit42Ingester
    ingester = Unit42Ingester(db)
    result = await ingester.ingest()
    return {"status": "success", "result": result}


@router.post("/admin/setup-production-data")
async def setup_production_data(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Run full production data setup (all sources)"""
    import subprocess
    import sys
    
    # Run the production data setup script
    result = subprocess.run(
        [sys.executable, "-m", "scripts.production_data_setup"],
        capture_output=True,
        text=True,
        cwd="/app"
    )
    
    return {
        "status": "success" if result.returncode == 0 else "error",
        "output": result.stdout,
        "error": result.stderr if result.returncode != 0 else None
    }


@router.post("/admin/recalculate-scores")
async def recalculate_scores(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Recalculate all precomputed scores"""
    # This would iterate through all industries and recalculate
    # For MVP, we'll just return a placeholder
    return {
        "status": "success",
        "message": "Score recalculation triggered. This may take a while."
    }


@router.post("/admin/refresh-industries")
async def refresh_industries(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Refresh industries from NAICS classification (free public source)"""
    from app.services.ingestion.naics import get_industries_from_naics
    from app.models import Industry
    from sqlalchemy import select, delete
    
    # Get industries from NAICS
    industries_data = get_industries_from_naics()
    
    # Clear existing industries (optional - comment out to keep existing)
    # await db.execute(delete(Industry))
    # await db.commit()
    
    # Create industry map
    industry_map = {}
    
    # First pass: create/update parent industries
    for ind_data in industries_data:
        if ind_data.get("parent_id") is None:
            # Check if exists
            result = await db.execute(
                select(Industry).where(Industry.name == ind_data["name"])
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                industry_map[ind_data["name"]] = existing
            else:
                industry = Industry(
                    name=ind_data["name"],
                    code=ind_data["code"],
                    parent_id=None
                )
                db.add(industry)
                industry_map[ind_data["name"]] = industry
    
    await db.flush()
    
    # Second pass: create/update subsectors
    for ind_data in industries_data:
        if "parent_name" in ind_data:
            parent = industry_map.get(ind_data["parent_name"])
            if parent:
                result = await db.execute(
                    select(Industry).where(Industry.name == ind_data["name"])
                )
                existing = result.scalar_one_or_none()
                
                if existing:
                    existing.parent_id = parent.id
                else:
                    industry = Industry(
                        name=ind_data["name"],
                        code=ind_data["code"],
                        parent_id=parent.id
                    )
                    db.add(industry)
    
    await db.commit()
    
    return {
        "status": "success",
        "message": f"Refreshed {len(industries_data)} industries from NAICS classification",
        "industries_count": len(industries_data)
    }


@router.get("/admin/data-quality")
async def get_data_quality_report(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Get data quality report"""
    validator = DataValidator(db)
    report = await validator.get_quality_report()
    return report


@router.get("/admin/data-quality/duplicates")
async def get_duplicates(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Find potential duplicate evidence items"""
    validator = DataValidator(db)
    duplicates = await validator.find_duplicates(limit=limit)
    return {"duplicates": duplicates, "count": len(duplicates)}


@router.get("/admin/data-quality/sources")
async def get_source_statistics(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Get statistics for each data source"""
    validator = DataValidator(db)
    stats = await validator.get_source_statistics()
    return stats


@router.get("/admin/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    username: str = Depends(verify_admin)
):
    """Get system statistics"""
    from sqlalchemy import select, func
    from app.models import ThreatActorGroup, Industry, EvidenceItem, Source
    
    # Count actors
    result = await db.execute(select(func.count(ThreatActorGroup.id)))
    actor_count = result.scalar()
    
    # Count industries
    result = await db.execute(select(func.count(Industry.id)))
    industry_count = result.scalar()
    
    # Count evidence items
    result = await db.execute(select(func.count(EvidenceItem.id)))
    evidence_count = result.scalar()
    
    # Count sources
    result = await db.execute(select(func.count(Source.id)))
    source_count = result.scalar()
    
    # Get source status
    result = await db.execute(select(Source))
    sources = result.scalars().all()
    source_status = [
        {
            "name": s.name,
            "last_checked": s.last_checked_at.isoformat() if s.last_checked_at else None,
            "reliability": s.reliability_score
        }
        for s in sources
    ]
    
    return {
        "actors": actor_count,
        "industries": industry_count,
        "evidence_items": evidence_count,
        "sources": source_count,
        "source_status": source_status
    }
