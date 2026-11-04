"""Domain value objects for evidence management."""

from enum import Enum


class EvidenceStorageBackend(str, Enum):
    """Storage backends supported for forensic evidence."""
    FILESYSTEM = "filesystem"
    SEAWEEDFS = "seaweedfs"


class EvidenceCollectionStatus(str, Enum):
    """Collection status for evidence."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"

