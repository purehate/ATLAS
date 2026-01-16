from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db import get_db
from app.models import Industry
from app.schemas import IndustryInfo
from typing import List

router = APIRouter()


@router.get("/industries", response_model=List[IndustryInfo])
async def list_industries(db: AsyncSession = Depends(get_db)):
    """List all industries"""
    result = await db.execute(select(Industry).order_by(Industry.name))
    industries = result.scalars().all()
    
    return [
        IndustryInfo(
            id=ind.id,
            name=ind.name,
            code=ind.code,
            parent_id=ind.parent_id
        )
        for ind in industries
    ]
