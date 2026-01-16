"""
Scheduler service for automated ingestion jobs
Run with: python -m scheduler.main
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.db import AsyncSessionLocal
from app.services.ingestion.mitre import MitreIngester
from app.services.ingestion.cisa import CisaIngester
from app.services.ingestion.fbi import FbiIngester
from app.services.calculator import CalculatorService
from config import settings
from app.utils.logging import setup_logging

logger = setup_logging()


async def daily_ingestion():
    """Daily ingestion job (CISA advisories and KEV)"""
    logger.info("Starting daily ingestion job")
    
    async with AsyncSessionLocal() as db:
        # Ingest CISA KEV (Known Exploited Vulnerabilities)
        try:
            from app.services.ingestion.cisa_kev import CisaKevIngester
            kev_ingester = CisaKevIngester(db)
            result = await kev_ingester.ingest()
            logger.info(f"CISA KEV ingestion result: {result}")
        except Exception as e:
            logger.error(f"CISA KEV ingestion failed: {e}", exc_info=True)
        
        # Ingest CISA advisories
        try:
            ingester = CisaIngester(db)
            result = await ingester.ingest(limit=20)
            logger.info(f"CISA advisories ingestion result: {result}")
        except Exception as e:
            logger.error(f"CISA advisories ingestion failed: {e}", exc_info=True)
        
        # Ingest Mandiant reports
        try:
            from app.services.ingestion.mandiant import MandiantIngester
            mandiant_ingester = MandiantIngester(db)
            result = await mandiant_ingester.ingest(limit=10)
            logger.info(f"Mandiant ingestion result: {result}")
        except Exception as e:
            logger.error(f"Mandiant ingestion failed: {e}", exc_info=True)
        
        # Ingest Microsoft Security Blog
        try:
            from app.services.ingestion.microsoft_security import MicrosoftSecurityIngester
            ms_ingester = MicrosoftSecurityIngester(db)
            result = await ms_ingester.ingest(limit=10)
            logger.info(f"Microsoft Security Blog ingestion result: {result}")
        except Exception as e:
            logger.error(f"Microsoft Security Blog ingestion failed: {e}", exc_info=True)
        
        # Ingest CrowdStrike Blog
        try:
            from app.services.ingestion.crowdstrike import CrowdStrikeIngester
            cs_ingester = CrowdStrikeIngester(db)
            result = await cs_ingester.ingest(limit=10)
            logger.info(f"CrowdStrike Blog ingestion result: {result}")
        except Exception as e:
            logger.error(f"CrowdStrike Blog ingestion failed: {e}", exc_info=True)
        
        # Ingest Unit 42 reports
        try:
            from app.services.ingestion.unit42 import Unit42Ingester
            u42_ingester = Unit42Ingester(db)
            result = await u42_ingester.ingest(limit=10)
            logger.info(f"Unit 42 ingestion result: {result}")
        except Exception as e:
            logger.error(f"Unit 42 ingestion failed: {e}", exc_info=True)
        
        # Recalculate scores
        try:
            await recalculate_all_scores(db)
        except Exception as e:
            logger.error(f"Score recalculation failed: {e}", exc_info=True)
    
    logger.info("Daily ingestion job complete")


async def weekly_ingestion():
    """Weekly ingestion job (MITRE, FBI)"""
    logger.info("Starting weekly ingestion job")
    
    async with AsyncSessionLocal() as db:
        # Ingest MITRE
        try:
            ingester = MitreIngester(db)
            result = await ingester.ingest()
            logger.info(f"MITRE ingestion result: {result}")
        except Exception as e:
            logger.error(f"MITRE ingestion failed: {e}", exc_info=True)
        
        # Ingest FBI
        try:
            ingester = FbiIngester(db)
            result = await ingester.ingest(limit=20)
            logger.info(f"FBI ingestion result: {result}")
        except Exception as e:
            logger.error(f"FBI ingestion failed: {e}", exc_info=True)
        
        # Recalculate scores
        try:
            await recalculate_all_scores(db)
        except Exception as e:
            logger.error(f"Score recalculation failed: {e}", exc_info=True)
    
    logger.info("Weekly ingestion job complete")


async def recalculate_all_scores(db):
    """Recalculate scores for all industries"""
    from sqlalchemy import select
    from app.models import Industry
    
    result = await db.execute(select(Industry))
    industries = result.scalars().all()
    
    calculator = CalculatorService(db)
    
    for industry in industries:
        try:
            await calculator._calculate_actor_industry_scores(industry.id)
            logger.info(f"Recalculated scores for industry: {industry.name}")
        except Exception as e:
            logger.error(f"Failed to recalculate scores for {industry.name}: {e}")


def main():
    """Start the scheduler"""
    scheduler = AsyncIOScheduler()
    
    # Daily job (CISA) - runs at configured hour
    scheduler.add_job(
        daily_ingestion,
        trigger=CronTrigger(hour=settings.ingestion_schedule_hour, minute=0),
        id="daily_ingestion",
        name="Daily CISA Ingestion",
        replace_existing=True
    )
    
    # Weekly job (MITRE, FBI) - runs Monday at configured hour
    scheduler.add_job(
        weekly_ingestion,
        trigger=CronTrigger(day_of_week="mon", hour=settings.ingestion_schedule_hour, minute=0),
        id="weekly_ingestion",
        name="Weekly MITRE/FBI Ingestion",
        replace_existing=True
    )
    
    # Score recalculation - runs daily at configured hour
    async def score_recalc():
        async with AsyncSessionLocal() as db:
            await recalculate_all_scores(db)
    
    scheduler.add_job(
        score_recalc,
        trigger=CronTrigger(hour=settings.score_recalculation_schedule_hour, minute=0),
        id="score_recalculation",
        name="Score Recalculation",
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started")
    logger.info(f"Daily ingestion scheduled for {settings.ingestion_schedule_hour}:00 UTC")
    logger.info(f"Weekly ingestion scheduled for Monday {settings.ingestion_schedule_hour}:00 UTC")
    logger.info(f"Score recalculation scheduled for {settings.score_recalculation_schedule_hour}:00 UTC")
    
    # Keep running
    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler shutting down...")
        scheduler.shutdown()


if __name__ == "__main__":
    main()
