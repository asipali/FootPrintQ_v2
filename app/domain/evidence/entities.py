"""Domain entities for forensic evidence."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from app.domain.common.entities import AggregateRoot, utc_now
from app.domain.common.value_objects import SHA256Checksum
from app.domain.evidence.value_objects import EvidenceStorageBackend, EvidenceCollectionStatus


@dataclass
class EvidenceItem(AggregateRoot):
    """Forensic evidence item representing raw artifacts and metadata."""
    id: str
    investigation_id: str
    source_type: str
    source_name: str
    target: str
    content_hash: SHA256Checksum
    storage_backend: EvidenceStorageBackend = EvidenceStorageBackend.FILESYSTEM
    raw_content_path: Optional[str] = None
    content_size_bytes: int = 0
    job_id: Optional[str] = None
    collection_status: str = "SUCCESS"
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=utc_now)

    def is_metadata_only(self) -> bool:
        """Check if record represents metadata-only evidence without stored payload."""
        return self.raw_content_path is None or self.raw_content_path == ""

    def is_seaweedfs(self) -> bool:
        """Check if stored in SeaweedFS."""
        return self.storage_backend == EvidenceStorageBackend.SEAWEEDFS

