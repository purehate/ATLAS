from sqlalchemy import Column, String, Text, Integer, Float, Date, ForeignKey, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.db import Base


class Industry(Base):
    __tablename__ = "industries"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False, index=True)
    code = Column(String(50), unique=True, nullable=False)
    naics_code = Column(String(50), nullable=True, index=True)  # NAICS classification code
    parent_id = Column(UUID(as_uuid=True), ForeignKey("industries.id"), nullable=True)
    created_at = Column(Date, default=datetime.utcnow)
    updated_at = Column(Date, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    parent = relationship("Industry", remote_side=[id], backref="sub_industries")


class ThreatActorGroup(Base):
    __tablename__ = "threat_actor_groups"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False, index=True)
    aliases = Column(ARRAY(String), default=[])
    mitre_id = Column(String(50), nullable=True, index=True)
    description = Column(Text, nullable=True)
    first_seen = Column(Date, nullable=True)
    last_seen = Column(Date, nullable=True)
    meta_data = Column(JSONB, default={})
    created_at = Column(Date, default=datetime.utcnow)
    updated_at = Column(Date, default=datetime.utcnow, onupdate=datetime.utcnow)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)
    meta_data = Column(JSONB, default={})
    created_at = Column(Date, default=datetime.utcnow)
    updated_at = Column(Date, default=datetime.utcnow, onupdate=datetime.utcnow)


class Source(Base):
    __tablename__ = "sources"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    type = Column(String(50), nullable=False)  # advisory, report, mitre, scraped
    base_url = Column(String(500), nullable=True)
    reliability_score = Column(Integer, nullable=False, default=5)  # 1-10
    last_checked_at = Column(Date, nullable=True)
    meta_data = Column(JSONB, default={})
    created_at = Column(Date, default=datetime.utcnow)
    updated_at = Column(Date, default=datetime.utcnow, onupdate=datetime.utcnow)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_actor_group_id = Column(UUID(as_uuid=True), ForeignKey("threat_actor_groups.id"), nullable=False)
    industry_id = Column(UUID(as_uuid=True), ForeignKey("industries.id"), nullable=True)
    technique_id = Column(UUID(as_uuid=True), ForeignKey("mitre_techniques.id"), nullable=True)
    source_id = Column(UUID(as_uuid=True), ForeignKey("sources.id"), nullable=False)
    source_url = Column(String(1000), nullable=False)
    source_title = Column(String(500), nullable=True)
    source_date = Column(Date, nullable=False, index=True)
    excerpt = Column(Text, nullable=True)
    confidence_score = Column(Integer, default=5)  # 1-10
    meta_data = Column(JSONB, default={})
    created_at = Column(Date, default=datetime.utcnow)
    updated_at = Column(Date, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    threat_actor_group = relationship("ThreatActorGroup", backref="evidence_items")
    industry = relationship("Industry", backref="evidence_items")
    technique = relationship("MitreTechnique", backref="evidence_items")
    source = relationship("Source", backref="evidence_items")
    
    # Indexes
    __table_args__ = (
        Index('idx_evidence_actor_industry_tech', 'threat_actor_group_id', 'industry_id', 'technique_id'),
        Index('idx_evidence_source_date', 'source_date'),
    )


class ActorIndustryScore(Base):
    __tablename__ = "actor_industry_scores"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_actor_group_id = Column(UUID(as_uuid=True), ForeignKey("threat_actor_groups.id"), nullable=False)
    industry_id = Column(UUID(as_uuid=True), ForeignKey("industries.id"), nullable=False)
    total_evidence_count = Column(Integer, default=0)
    weighted_score = Column(Float, nullable=False, default=0.0)
    last_calculated_at = Column(Date, default=datetime.utcnow)
    
    # Relationships
    threat_actor_group = relationship("ThreatActorGroup", backref="industry_scores")
    industry = relationship("Industry", backref="actor_scores")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('threat_actor_group_id', 'industry_id', name='uq_actor_industry'),
        Index('idx_actor_industry_score', 'industry_id', 'weighted_score'),
    )


class ActorTechniqueScore(Base):
    __tablename__ = "actor_technique_scores"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_actor_group_id = Column(UUID(as_uuid=True), ForeignKey("threat_actor_groups.id"), nullable=False)
    technique_id = Column(UUID(as_uuid=True), ForeignKey("mitre_techniques.id"), nullable=False)
    industry_id = Column(UUID(as_uuid=True), ForeignKey("industries.id"), nullable=True)
    evidence_count = Column(Integer, default=0)
    weighted_score = Column(Float, nullable=False, default=0.0)
    last_calculated_at = Column(Date, default=datetime.utcnow)
    
    # Relationships
    threat_actor_group = relationship("ThreatActorGroup", backref="technique_scores")
    technique = relationship("MitreTechnique", backref="actor_scores")
    industry = relationship("Industry", backref="technique_scores")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('threat_actor_group_id', 'technique_id', 'industry_id', name='uq_actor_technique_industry'),
        Index('idx_actor_technique_score', 'threat_actor_group_id', 'industry_id', 'weighted_score'),
    )
