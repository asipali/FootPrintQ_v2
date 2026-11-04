"""Domain entities for vulnerability assessment."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from app.domain.common.entities import Entity, AggregateRoot, utc_now
from app.domain.vulnerabilities.value_objects import VulnerabilitySeverity, CVSSScore


@dataclass
class VulnerabilityFinding(Entity):
    """Normalized vulnerability finding with CVE and CVSS metrics."""
    id: str
    investigation_id: str
    job_id: str
    host: str
    name: str
    severity: VulnerabilitySeverity
    port: Optional[int] = None
    protocol: Optional[str] = "tcp"
    description: Optional[str] = None
    solution: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    cve_references: List[str] = field(default_factory=list)
    nvt_oid: Optional[str] = None
    threat_level: Optional[str] = None
    raw_response: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class VulnerabilityScanJob(Entity):
    """Vulnerability scan execution tracking."""
    id: str
    investigation_id: str
    target: str
    status: str
    scanner_type: str = "openvas"
    started_at: datetime = field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

