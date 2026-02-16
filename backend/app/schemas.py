from __future__ import annotations

from datetime import date
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# Request Schemas
class CalculateRequest(BaseModel):
    company_name: str = Field(..., description="Company name")
    business_vertical: str = Field(
        ..., description="Business vertical (e.g., Financial Services)"
    )
    sub_vertical: Optional[str] = Field(
        None, description="Sub-vertical (e.g., Banking)"
    )


# Response Schemas
class TechniqueInfo(BaseModel):
    id: UUID
    technique_id: str
    name: str
    tactic: str
    description: Optional[str] = None
    url: Optional[str] = None


class TechniqueScore(BaseModel):
    technique: TechniqueInfo
    score: float
    evidence_count: int


class ThreatActorInfo(BaseModel):
    id: UUID
    name: str
    aliases: List[str]
    mitre_id: Optional[str] = None


class Explanation(BaseModel):
    source_title: str
    source_url: str
    source_date: date
    excerpt: Optional[str] = None


class ActorResult(BaseModel):
    threat_actor_group: ThreatActorInfo
    confidence: str  # High, Medium, Low
    weighted_score: float
    top_techniques: List[TechniqueScore]
    explanations: List[Explanation]


class CalculateResponse(BaseModel):
    request_id: UUID
    industry_id: Optional[UUID] = None
    results: List[ActorResult]
    metadata: dict


class IndustryInfo(BaseModel):
    id: UUID
    name: str
    code: str
    parent_id: Optional[UUID] = None


class ActorInfo(BaseModel):
    id: UUID
    name: str
    aliases: List[str]
    mitre_id: Optional[str] = None
    description: Optional[str] = None
