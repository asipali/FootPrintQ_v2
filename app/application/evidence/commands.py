"""Evidence application commands and queries."""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class StoreEvidenceCommand:
    """Command to persist forensic evidence."""
    investigation_id: str
    source_type: str
    source_name: str
    target: str
    content: bytes
    filename: str
    job_id: Optional[str] = None
    collection_status: str = "SUCCESS"
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    use_seaweedfs: bool = False


@dataclass
class VerifyEvidenceIntegrityCommand:
    """Command to verify checksum and payload existence."""
    evidence_id: str


@dataclass
class GetEvidenceQuery:
    """Query to retrieve an evidence item."""
    evidence_id: str
    user_id: str
    is_admin: bool = False


@dataclass
class ListEvidenceQuery:
    """Query to list evidence for an investigation."""
    investigation_id: str
    user_id: str
    is_admin: bool = False

