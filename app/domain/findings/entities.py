"""Domain entities for security findings."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from app.domain.common.entities import Entity, utc_now
from app.domain.findings.value_objects import FindingSeverity


@dataclass
class ScanFindingHost(Entity):
    """Normalized host discovered during active reconnaissance."""
    id: str
    investigation_id: str
    job_id: str
    address: str
    address_type: str = "ipv4"
    status: str = "up"
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class ScanFindingPort(Entity):
    """Normalized open/filtered port finding."""
    id: str
    host_id: str
    job_id: str
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cpe: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class SecurityFinding(Entity):
    """Generic security finding entity."""
    id: str
    investigation_id: str
    title: str
    severity: FindingSeverity
    description: str
    target: str
    evidence_id: Optional[str] = None
    remediation: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)

