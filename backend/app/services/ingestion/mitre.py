import httpx
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, date
from typing import Dict, List

from app.models import ThreatActorGroup, MitreTechnique, Source, EvidenceItem
from app.services.ingestion.normalizer import Normalizer
from app.utils.logging import setup_logging

logger = setup_logging()

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MitreIngester:
    """Ingest data from MITRE ATT&CK"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def ingest(self) -> Dict[str, int]:
        """
        Ingest MITRE ATT&CK data
        Returns stats: {actors_created, techniques_created, evidence_created}
        """
        logger.info("Starting MITRE ATT&CK ingestion")
        
        # Get or create MITRE source
        source = await self._get_or_create_source()
        
        # Download MITRE data
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(MITRE_ATTACK_URL)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                logger.error(f"Failed to download MITRE data: {e}")
                return {"error": str(e)}
        
        stats = {
            "actors_created": 0,
            "techniques_created": 0,
            "relationships_created": 0
        }
        
        # Process objects
        objects = data.get("objects", [])
        
        # First pass: create actors and techniques
        actors_by_id = {}
        techniques_by_id = {}
        
        for obj in objects:
            obj_type = obj.get("type")
            
            if obj_type == "intrusion-set":
                actor = await self._process_actor(obj)
                if actor:
                    actors_by_id[obj.get("id")] = actor
                    stats["actors_created"] += 1
            
            elif obj_type == "attack-pattern":
                technique = await self._process_technique(obj)
                if technique:
                    techniques_by_id[obj.get("id")] = technique
                    stats["techniques_created"] += 1
        
        # Second pass: process relationships (actor uses technique)
        for obj in objects:
            if obj.get("type") == "relationship":
                rel_type = obj.get("relationship_type")
                source_ref = obj.get("source_ref")
                target_ref = obj.get("target_ref")
                
                if rel_type == "uses":
                    actor = actors_by_id.get(source_ref)
                    technique = techniques_by_id.get(target_ref)
                    
                    if actor and technique:
                        # Create evidence item (MITRE relationship)
                        await self._create_relationship_evidence(
                            actor, technique, source, obj
                        )
                        stats["relationships_created"] += 1
        
        await self.db.commit()
        
        # Update source last_checked_at
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"MITRE ingestion complete: {stats}")
        return stats
    
    async def _get_or_create_source(self) -> Source:
        """Get or create MITRE source"""
        result = await self.db.execute(
            select(Source).where(Source.name == "MITRE ATT&CK")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            from config import settings
            source = Source(
                name="MITRE ATT&CK",
                type="mitre",
                base_url="https://attack.mitre.org",
                reliability_score=settings.source_reliability_mitre,
                meta_data={"url": MITRE_ATTACK_URL}
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    async def _process_actor(self, obj: Dict) -> ThreatActorGroup:
        """Process intrusion-set object"""
        name = obj.get("name")
        if not name:
            return None
        
        # Check if exists
        result = await self.db.execute(
            select(ThreatActorGroup).where(ThreatActorGroup.name == name)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            # Update aliases if new ones found
            aliases = obj.get("aliases", [])
            if aliases:
                existing.aliases = list(set((existing.aliases or []) + aliases))
            
            # Update MITRE ID
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    existing.mitre_id = ref.get("external_id")
                    break
            
            return existing
        
        # Create new actor
        aliases = obj.get("aliases", [])
        external_refs = obj.get("external_references", [])
        mitre_id = None
        
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break
        
        actor = ThreatActorGroup(
            name=name,
            aliases=aliases,
            mitre_id=mitre_id,
            description=obj.get("description", ""),
            meta_data={"mitre_id": obj.get("id")}
        )
        self.db.add(actor)
        await self.db.flush()
        return actor
    
    async def _process_technique(self, obj: Dict) -> MitreTechnique:
        """Process attack-pattern object"""
        # Try x_mitre_id first, then check external_references
        technique_id = obj.get("x_mitre_id")
        if not technique_id:
            # Try to get from external_references
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    if technique_id and technique_id.startswith("T"):
                        break
        
        if not technique_id or not technique_id.startswith("T"):
            return None
        
        # Check if exists
        result = await self.db.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == technique_id)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            return existing
        
        # Extract tactic
        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactic = "Unknown"
        if kill_chain_phases:
            # Map MITRE phase to tactic name
            phase_name = kill_chain_phases[0].get("phase_name", "")
            tactic = self._map_phase_to_tactic(phase_name)
        
        # Get URL
        url = None
        external_refs = obj.get("external_references", [])
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url")
                break
        
        technique = MitreTechnique(
            technique_id=technique_id,
            name=obj.get("name", ""),
            tactic=tactic,
            description=obj.get("description", ""),
            url=url,
            meta_data={"mitre_id": obj.get("id")}
        )
        self.db.add(technique)
        await self.db.flush()
        return technique
    
    def _map_phase_to_tactic(self, phase_name: str) -> str:
        """Map MITRE phase name to tactic"""
        mapping = {
            "reconnaissance": "Reconnaissance",
            "resource-development": "Resource Development",
            "initial-access": "Initial Access",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege-escalation": "Privilege Escalation",
            "defense-evasion": "Defense Evasion",
            "credential-access": "Credential Access",
            "discovery": "Discovery",
            "lateral-movement": "Lateral Movement",
            "collection": "Collection",
            "command-and-control": "Command and Control",
            "exfiltration": "Exfiltration",
            "impact": "Impact"
        }
        return mapping.get(phase_name, "Unknown")
    
    async def _create_relationship_evidence(
        self,
        actor: ThreatActorGroup,
        technique: MitreTechnique,
        source: Source,
        relationship_obj: Dict
    ):
        """Create evidence item for actor-technique relationship"""
        # Check if already exists
        result = await self.db.execute(
            select(EvidenceItem).where(
                EvidenceItem.threat_actor_group_id == actor.id,
                EvidenceItem.technique_id == technique.id,
                EvidenceItem.source_id == source.id,
                EvidenceItem.industry_id.is_(None)  # MITRE relationships are not industry-specific
            )
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            return
        
        evidence = EvidenceItem(
            threat_actor_group_id=actor.id,
            technique_id=technique.id,
            source_id=source.id,
            source_url=f"https://attack.mitre.org/groups/{actor.mitre_id}/",
            source_title=f"MITRE ATT&CK: {actor.name} uses {technique.name}",
            source_date=date.today(),  # Use today as default
            excerpt=f"MITRE ATT&CK relationship: {actor.name} uses {technique.technique_id}",
            confidence_score=source.reliability_score,
            meta_data={"relationship_id": relationship_obj.get("id")}
        )
        self.db.add(evidence)
