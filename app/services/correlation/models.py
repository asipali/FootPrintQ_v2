"""Data structures and enums for the FootprintIQ correlation engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class RelationshipStrength(str, Enum):
    """Transparent confidence / relationship strength classifications."""
    CONFIRMED_MATCH = "CONFIRMED_MATCH"  # Identifiers and attributes establish the same asset or observation
    STRONG_MATCH = "STRONG_MATCH"        # Multiple independent attributes support the relationship
    POSSIBLE_MATCH = "POSSIBLE_MATCH"    # Partial attributes support a potential relationship
    UNMATCHED = "UNMATCHED"              # Insufficient information for a reliable relationship


class FindingLifecycleState(str, Enum):
    """Vulnerability finding lifecycle states across scan history."""
    NEW = "NEW"                    # Observed for the first time in this investigation
    REOBSERVED = "REOBSERVED"      # Corroborated in multiple consecutive/recent scans
    CHANGED = "CHANGED"            # Reobserved but severity, solution, or CVSS changed
    RESOLVED = "RESOLVED"          # Confirmed absent by a subsequent successful scan
    UNCONFIRMED = "UNCONFIRMED"    # Scanner failed, timed out, or host down; cannot confirm absence


class EvidenceVerificationState(str, Enum):
    """Integrity verification status for supporting forensic evidence."""
    VERIFIED = "VERIFIED"                  # Evidence retrieved from storage and SHA-256 matched
    HASH_MISMATCH = "HASH_MISMATCH"        # Evidence payload hash does not match recorded digest
    UNAVAILABLE = "UNAVAILABLE"            # Evidence file cannot be retrieved from storage backend
    NOT_APPLICABLE = "NOT_APPLICABLE"      # No direct raw evidence file attached


class AssetType(str, Enum):
    """Normalized asset types."""
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    HOST = "HOST"
    PORT = "PORT"
    SERVICE = "SERVICE"
    URL = "URL"
    CERTIFICATE = "CERTIFICATE"
    EMAIL = "EMAIL"


@dataclass
class NormalizedAsset:
    """Canonical representation of an investigation asset with provenance."""
    identifier: str                     # e.g. "192.168.56.102", "portal.lab.example"
    asset_type: AssetType
    original_value: str
    investigation_id: str
    hostnames: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "asset_type": self.asset_type.value,
            "original_value": self.original_value,
            "investigation_id": self.investigation_id,
            "hostnames": sorted(list(self.hostnames)),
            "domains": sorted(list(self.domains)),
            "ips": sorted(list(self.ips)),
            "open_ports": sorted(self.open_ports, key=lambda p: (p.get("port", 0), p.get("protocol", ""))),
            "vulnerabilities": self.vulnerabilities,
            "evidence_ids": sorted(list(self.evidence_ids)),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata,
        }


@dataclass
class CorrelatedRelationship:
    """In-memory representation of an evaluated correlation decision."""
    correlation_id: str
    investigation_id: str
    correlation_rule_id: str
    rule_version: str
    relationship_type: RelationshipStrength
    confidence_score: float
    asset_identifier: str
    asset_type: AssetType
    source_modules: List[str]
    source_scanners: List[str]
    source_observation_ids: List[str]
    matching_attributes: List[str]
    related_vulnerability_id: Optional[str] = None
    evidence_references: List[str] = field(default_factory=list)
    evidence_verification_status: EvidenceVerificationState = EvidenceVerificationState.NOT_APPLICABLE
    lifecycle_status: FindingLifecycleState = FindingLifecycleState.NEW
    correlation_status: str = "ACTIVE"
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

