from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db import get_db
from app.models import ThreatActorGroup
from app.schemas import ActorInfo
from typing import List

router = APIRouter()


@router.get("/actors", response_model=List[ActorInfo])
async def list_actors(
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """List threat actor groups (paginated)"""
    result = await db.execute(
        select(ThreatActorGroup)
        .order_by(ThreatActorGroup.name)
        .limit(limit)
        .offset(offset)
    )
    actors = result.scalars().all()
    
    return [
        ActorInfo(
            id=actor.id,
            name=actor.name,
            aliases=actor.aliases or [],
            mitre_id=actor.mitre_id,
            description=actor.description
        )
        for actor in actors
    ]
