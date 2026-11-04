"""Forensic evidence storage abstraction interfaces and metadata models."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
import re
from typing import BinaryIO, Dict, Generator, Optional, Tuple, Union
from pydantic import BaseModel, Field


class StorageObjectMetadata(BaseModel):
    """Immutable metadata representing an object in forensic storage."""
    key: str
    size_bytes: int
    content_hash: str  # Hex-encoded SHA-256 digest
    content_type: str = "application/octet-stream"
    backend: str
    created_at: Optional[datetime] = None
    custom_metadata: Dict[str, str] = Field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "size_bytes": self.size_bytes,
            "content_hash": self.content_hash,
            "content_type": self.content_type,
            "backend": self.backend,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "custom_metadata": self.custom_metadata,
        }


class StorageHealthStatus(BaseModel):
    """Health and operational diagnostic report for a storage backend."""
    is_healthy: bool
    backend: str
    details: str
    latency_ms: Optional[float] = None


class StorageError(Exception):
    """Base exception for all storage abstraction operations."""
    pass


class StorageKeyExistsError(StorageError, FileExistsError):
    """Raised when an object key already exists and immutability blocks overwriting."""
    pass


class StorageObjectNotFoundError(StorageError, FileNotFoundError):
    """Raised when the requested object key does not exist in storage."""
    pass


class StorageIntegrityError(StorageError):
    """Raised when object content hash verification fails."""
    pass


class StorageConnectionError(StorageError):
    """Raised when backend storage connection or network communication fails."""
    pass


class StorageSecurityError(StorageError, ValueError):
    """Raised when an invalid, malicious, or path-traversing key is detected."""
    pass


class StoragePayloadTooLargeError(StorageError, ValueError):
    """Raised when an object payload exceeds maximum permitted storage size."""
    pass


MAX_EVIDENCE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB standard evidence payload limit


SAFE_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+(/[a-zA-Z0-9_\.\-]+)+$")


def validate_and_normalize_key(key: str) -> str:
    """Validates and normalizes an object storage key.
    
    Keys must follow the hierarchical pattern '{investigation_id}/{filename}'.
    Disallows path traversal sequences ('..'), absolute paths, backslashes,
    hidden files, and unsafe characters.
    """
    if not key or not isinstance(key, str):
        raise StorageSecurityError("Storage key cannot be empty or non-string.")

    raw = key.strip()
    if raw.startswith("/") or raw.startswith("\\") or (len(raw) >= 2 and raw[1] == ":"):
        raise StorageSecurityError(f"Absolute paths are forbidden in storage keys: '{key}'")

    normalized = raw.replace("\\", "/")

    parts = normalized.split("/")
    if len(parts) < 2:
        raise StorageSecurityError(
            f"Storage key must include at least an investigation namespace and filename, got: '{key}'"
        )

    for part in parts:
        if not part or part == "." or part == ".." or ".." in part:
            raise StorageSecurityError(f"Path traversal sequence detected in storage key component: '{part}'")
        # Ensure only alphanumeric, hyphen, underscore, or dot (for extensions)
        if not all(c.isalnum() or c in ("-", "_", ".") for c in part):
            raise StorageSecurityError(f"Unsafe characters detected in storage key component: '{part}'")
        if part.startswith("."):
            raise StorageSecurityError(f"Hidden file components are forbidden: '{part}'")

    if not SAFE_KEY_PATTERN.match(normalized):
        raise StorageSecurityError(f"Storage key does not match safe key pattern: '{normalized}'")

    return normalized


def compute_sha256(data: bytes) -> str:
    """Computes standard hex-encoded SHA-256 digest over bytes."""
    return hashlib.sha256(data).hexdigest()


class BaseStorageAdapter(ABC):
    """Abstract Base Class defining the contract for evidence storage providers."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Name identifying the storage provider ('filesystem', 'seaweedfs')."""
        pass

    @abstractmethod
    def put_object(
        self,
        key: str,
        data: Union[bytes, BinaryIO, str],
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageObjectMetadata:
        """Persists object bytes with cryptographic immutability.
        
        Args:
            key: Hierarchical storage key '{investigation_id}/{filename}'.
            data: Binary payload or string to store.
            content_type: MIME type of the payload.
            metadata: Optional key-value metadata to attach to the object.
            
        Returns:
            StorageObjectMetadata with size, SHA-256 hash, and backend metadata.
            
        Raises:
            StorageKeyExistsError: If an object already exists at the specified key.
            StorageSecurityError: If the key violates path or character security rules.
            StorageConnectionError: If network or I/O failure occurs during persistence.
        """
        pass

    @abstractmethod
    def get_object(self, key: str) -> Tuple[bytes, StorageObjectMetadata]:
        """Retrieves complete object payload and its metadata.
        
        Returns:
            Tuple of (raw_bytes, StorageObjectMetadata).
            
        Raises:
            StorageObjectNotFoundError: If the object does not exist.
            StorageConnectionError: If network or I/O failure occurs during retrieval.
        """
        pass

    @abstractmethod
    def get_object_stream(self, key: str, chunk_size: int = 65536) -> Generator[bytes, None, None]:
        """Streams object payload in fixed-size chunks for memory efficiency.
        
        Yields:
            Byte chunks of length <= chunk_size.
            
        Raises:
            StorageObjectNotFoundError: If the object does not exist.
            StorageConnectionError: If streaming fails mid-transfer.
        """
        pass

    @abstractmethod
    def delete_object(self, key: str) -> bool:
        """Deletes object from storage backend (used for compensation on failed DB commit).
        
        Returns:
            True if object was deleted, False if object did not exist.
            
        Raises:
            StorageConnectionError: If deletion fails due to connection or I/O errors.
        """
        pass

    @abstractmethod
    def object_exists(self, key: str) -> bool:
        """Checks whether an object exists at the specified key.
        
        Returns:
            True if object exists, False otherwise.
        """
        pass

    @abstractmethod
    def get_object_metadata(self, key: str) -> StorageObjectMetadata:
        """Retrieves object metadata without downloading the complete payload.
        
        Returns:
            StorageObjectMetadata instance.
            
        Raises:
            StorageObjectNotFoundError: If the object does not exist.
            StorageConnectionError: If metadata retrieval fails.
        """
        pass

    @abstractmethod
    def verify_object_integrity(self, key: str, expected_hash: str) -> bool:
        """Verifies that the object in storage matches the expected SHA-256 hash.
        
        Returns:
            True if computed hash matches expected_hash.
            
        Raises:
            StorageIntegrityError: If computed hash differs from expected_hash.
            StorageObjectNotFoundError: If object is missing.
        """
        pass

    @abstractmethod
    def health_check(self) -> StorageHealthStatus:
        """Verifies operational health and connectivity to the storage backend.
        
        Returns:
            StorageHealthStatus report.
        """
        pass

    def close(self) -> None:
        """Performs clean shutdown and releases connections, sockets, and client pools."""
        pass

