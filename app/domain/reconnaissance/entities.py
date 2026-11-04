"""Domain entities for reconnaissance."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from app.domain.common.entities import Entity, utc_now
from app.domain.reconnaissance.value_objects import ReconType, CollectionJobStatus


@dataclass
class CollectionJob(Entity):
    """Collection job dispatched by reconnaissance orchestrator."""
    id: str
    investigation_id: str
    target: str
    collector_name: str
    status: CollectionJobStatus = CollectionJobStatus.QUEUED
    started_at: datetime = field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    result_summary: Dict[str, Any] = field(default_factory=dict)
    error_category: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class ReconEntity(Entity):
    """Normalized cybersecurity OSINT entity with evidence provenance."""
    id: str
    investigation_id: str
    entity_type: str
    canonical_value: str
    original_value: str
    first_seen: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)
    evidence_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSHarvest(Entity):
    """DNS record harvest results."""
    id: str
    investigation_id: str
    domain: str
    record_type: str
    value: str
    ttl: Optional[int] = None
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass
class CertificateRecord(Entity):
    """TLS/SSL certificate record."""
    id: str
    investigation_id: str
    fingerprint_sha256: str
    subject_cn: str
    issuer_cn: str
    san_list: List[str] = field(default_factory=list)
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    discovered_at: datetime = field(default_factory=utc_now)

