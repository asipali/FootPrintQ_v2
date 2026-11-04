"""Storage port interface for forensic evidence."""

from abc import ABC, abstractmethod
from typing import Optional, BinaryIO, Tuple


class IEvidenceStoragePort(ABC):
    """Port defining evidence payload storage operations."""

    @abstractmethod
    def store_evidence(
        self,
        investigation_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None
    ) -> str:
        """Store evidence payload and return authoritative location path or key."""
        pass

    @abstractmethod
    def retrieve_evidence(self, path: str) -> bytes:
        """Retrieve stored evidence payload as raw bytes."""
        pass

    @abstractmethod
    def delete_evidence(self, path: str) -> bool:
        """Delete stored evidence payload if present."""
        pass

    @abstractmethod
    def verify_integrity(self, path: str, expected_sha256: str) -> Tuple[bool, str]:
        """Verify SHA-256 integrity of stored evidence payload."""
        pass

