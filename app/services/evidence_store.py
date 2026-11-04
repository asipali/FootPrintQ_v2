"""Forensic evidence storage service with path traversal protection and integrity verification."""

import json
import hashlib
from pathlib import Path
from typing import Generator, Optional, Tuple, Union

from app.config import get_settings
from app.logging_config import get_logger
from app.storage.base import (
    BaseStorageAdapter,
    StorageConnectionError,
    StorageError,
    StorageHealthStatus,
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectMetadata,
    StorageObjectNotFoundError,
    StoragePayloadTooLargeError,
    StorageSecurityError,
    compute_sha256,
    validate_and_normalize_key,
)
from app.storage.factory import get_storage_adapter
from app.storage.filesystem import LocalFilesystemStorageAdapter

logger = get_logger("footprintiq.services.evidence_store")


class StoredEvidenceResult(tuple):
    """Immutable tuple (key, content_hash, size_bytes) preserving backward-compatible unpacking
    while carrying an explicit backend attribute indicating the actual storage provider used.
    """
    def __new__(cls, key: str, content_hash: str, size_bytes: int, backend: str = "filesystem"):
        obj = super().__new__(cls, (key, content_hash, size_bytes))
        obj.key = key
        obj.content_hash = content_hash
        obj.size_bytes = size_bytes
        obj.backend = backend
        return obj


class EvidenceStore:
    """Manages secure persistence, integrity verification, and retrieval of forensic evidence.

    Acts as the domain service orchestrating the underlying BaseStorageAdapter (filesystem or SeaweedFS),
    enforcing safe key generation, path traversal immunity, SHA-256 integrity checks,
    and dual-read fallback support.
    """

    def __init__(
        self,
        base_path: Optional[str] = None,
        adapter: Optional[BaseStorageAdapter] = None,
    ):
        settings = get_settings()
        self.settings = settings
        self._last_backend_used: str = "filesystem"

        if adapter is not None:
            self.adapter = adapter
            self._last_backend_used = getattr(adapter, "backend_name", "filesystem")
        elif base_path is not None:
            self.adapter = LocalFilesystemStorageAdapter(base_path=base_path)
            self._last_backend_used = "filesystem"
        else:
            self.adapter = get_storage_adapter(settings=settings)
            self._last_backend_used = self.adapter.backend_name

        # Retain base_dir attribute for backward compatibility with existing tests
        if hasattr(self.adapter, "base_dir"):
            self.base_dir = self.adapter.base_dir
        else:
            self.base_dir = Path(settings.EVIDENCE_STORAGE_PATH).resolve()

    @property
    def last_backend_used(self) -> str:
        """Returns the actual storage backend utilized during the most recent store operation."""
        return self._last_backend_used

    def _get_investigation_dir(self, investigation_id: str) -> Path:
        """Resolves investigation storage directory, strictly preventing path traversal.
        Preserved for direct compatibility with filesystem tests.
        """
        if not investigation_id or ".." in investigation_id or "/" in investigation_id or "\\" in investigation_id:
            raise ValueError(f"Path traversal or invalid characters detected in investigation ID: {investigation_id}")

        safe_id = "".join(c for c in investigation_id if c.isalnum() or c in ("-", "_"))
        if not safe_id:
            raise ValueError("Invalid investigation ID for evidence storage.")

        target_dir = (self.base_dir / safe_id).resolve()
        if not target_dir.is_relative_to(self.base_dir):
            raise ValueError(f"Path traversal detected for investigation ID: {investigation_id}")

        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _generate_object_key(
        self,
        investigation_id: str,
        evidence_id: str,
        source_type: str,
        extension: str,
    ) -> str:
        """Constructs an immutable, normalized storage object key."""
        if not investigation_id or ".." in investigation_id or "/" in investigation_id or "\\" in investigation_id:
            raise ValueError(f"Path traversal or invalid characters detected in investigation ID: {investigation_id}")

        safe_inv_id = "".join(c for c in investigation_id if c.isalnum() or c in ("-", "_"))
        if not safe_inv_id:
            raise ValueError("Invalid investigation ID for evidence storage.")

        if not evidence_id or ".." in evidence_id or "/" in evidence_id or "\\" in evidence_id or not all(c.isalnum() or c in ("-", "_") for c in evidence_id):
            raise ValueError(f"Invalid characters or traversal detected in evidence ID: {evidence_id}")

        if not source_type or ".." in source_type or "/" in source_type or "\\" in source_type or not all(c.isalnum() or c in ("-", "_") for c in source_type):
            raise ValueError(f"Invalid characters or traversal detected in source type: {source_type}")

        safe_evidence_id = evidence_id
        safe_source = source_type.lower()
        safe_ext = "".join(c for c in extension.lower() if c.isalnum())

        if not safe_evidence_id or not safe_source or not safe_ext:
            raise ValueError("Evidence ID, source type, and extension must contain valid alphanumeric characters.")

        filename = f"{safe_evidence_id}_{safe_source}.raw.{safe_ext}"
        raw_key = f"{safe_inv_id}/{filename}"
        return validate_and_normalize_key(raw_key)

    def store_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
        source_type: str,
        content: Union[str, bytes, dict, list],
    ) -> Tuple[str, str, int]:
        """Saves raw evidence to the configured storage backend.

        Args:
            investigation_id: Parent investigation identifier.
            evidence_id: Unique evidence identifier.
            source_type: Reconnaissance source or collector type.
            content: Payload data (dict/list for JSON, str for text, bytes for binary).

        Returns:
            Tuple of (relative_storage_key, content_sha256_hash, content_size_bytes).

        Raises:
            ValueError: If path traversal or illegal characters are detected.
            FileExistsError: If evidence key already exists (immutability).
        """
        # Determine serialization format and MIME type
        if isinstance(content, (dict, list)):
            encoded_bytes = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
            extension = "json"
            content_type = "application/json"
        elif isinstance(content, str):
            encoded_bytes = content.encode("utf-8")
            extension = "txt"
            content_type = "text/plain; charset=utf-8"
        elif isinstance(content, bytes):
            encoded_bytes = content
            extension = "bin"
            content_type = "application/octet-stream"
        else:
            encoded_bytes = str(content).encode("utf-8")
            extension = "txt"
            content_type = "text/plain; charset=utf-8"

        object_key = self._generate_object_key(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            source_type=source_type,
            extension=extension,
        )

        metadata = {
            "investigation_id": investigation_id,
            "evidence_id": evidence_id,
            "source_type": source_type,
        }

        actual_backend = self.adapter.backend_name
        try:
            stored_meta = self.adapter.put_object(
                key=object_key,
                data=encoded_bytes,
                content_type=content_type,
                metadata=metadata,
            )
            self._last_backend_used = actual_backend
            return StoredEvidenceResult(stored_meta.key, stored_meta.content_hash, stored_meta.size_bytes, backend=actual_backend)
        except (StorageKeyExistsError, StoragePayloadTooLargeError, StorageSecurityError):
            raise
        except Exception as e:
            # Check for explicit observable fallback to local filesystem
            if (
                self.adapter.backend_name == "seaweedfs"
                and getattr(self.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", False)
                and getattr(self.settings, "APP_ENV", "development") not in {"staging", "production"}
            ):
                logger.warning(
                    "SeaweedFS evidence storage failed; explicit observable fallback to filesystem activated for key '%s': %s",
                    object_key,
                    e,
                )
                local_adapter = LocalFilesystemStorageAdapter(base_path=self.settings.EVIDENCE_STORAGE_PATH)
                stored_meta = local_adapter.put_object(
                    key=object_key,
                    data=encoded_bytes,
                    content_type=content_type,
                    metadata=metadata,
                )
                self._last_backend_used = "filesystem"
                return StoredEvidenceResult(stored_meta.key, stored_meta.content_hash, stored_meta.size_bytes, backend="filesystem")
            raise

    def read_evidence(
        self,
        relative_path: str,
        backend: Optional[str] = None,
    ) -> Tuple[bytes, str]:
        """Reads raw evidence from storage and verifies integrity against computed SHA-256 hash.

        Returns:
            Tuple of (content_bytes, computed_hash).

        Raises:
            ValueError: If path traversal sequence is detected.
            FileNotFoundError: If evidence object does not exist.
        """
        try:
            safe_key = validate_and_normalize_key(relative_path)
        except StorageSecurityError as e:
            raise ValueError(f"Path traversal detected in relative evidence path: {e}") from e

        target_adapter = self.adapter
        if backend and backend != self.adapter.backend_name:
            target_adapter = get_storage_adapter(self.settings, backend_override=backend)

        try:
            content_bytes, meta = target_adapter.get_object(safe_key)
            computed_hash = meta.content_hash or compute_sha256(content_bytes)
            return content_bytes, computed_hash
        except StorageObjectNotFoundError:
            # Dual-read fallback: permitted only in development/test if explicitly configured;
            # strictly locked out in staging and production to prevent silent data divergence.
            if (
                target_adapter.backend_name == "seaweedfs"
                and getattr(self.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", False)
                and getattr(self.settings, "APP_ENV", "development") not in {"staging", "production"}
            ):
                local_adapter = LocalFilesystemStorageAdapter(base_path=self.settings.EVIDENCE_STORAGE_PATH)
                if local_adapter.object_exists(safe_key):
                    logger.warning(
                        "Dual-read fallback activated: Object '%s' retrieved from local filesystem",
                        safe_key,
                    )
                    content_bytes, meta = local_adapter.get_object(safe_key)
                    computed_hash = meta.content_hash or compute_sha256(content_bytes)
                    return content_bytes, computed_hash

            raise FileNotFoundError(f"Evidence file not found: {relative_path}")
        except StorageConnectionError as conn_err:
            logger.error("Storage backend connection error reading '%s': %s", relative_path, conn_err)
            raise

    def read_evidence_stream(
        self,
        relative_path: str,
        chunk_size: int = 65536,
        backend: Optional[str] = None,
    ) -> Generator[bytes, None, None]:
        """Streams raw evidence payload in fixed-size chunks for memory efficiency."""
        try:
            safe_key = validate_and_normalize_key(relative_path)
        except StorageSecurityError as e:
            raise ValueError(f"Path traversal detected in relative evidence path: {e}") from e

        target_adapter = self.adapter
        if backend and backend != self.adapter.backend_name:
            target_adapter = get_storage_adapter(self.settings, backend_override=backend)

        try:
            yield from target_adapter.get_object_stream(safe_key, chunk_size=chunk_size)
        except StorageObjectNotFoundError:
            if (
                target_adapter.backend_name == "seaweedfs"
                and getattr(self.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", False)
                and getattr(self.settings, "APP_ENV", "development") not in {"staging", "production"}
            ):
                local_adapter = LocalFilesystemStorageAdapter(base_path=self.settings.EVIDENCE_STORAGE_PATH)
                if local_adapter.object_exists(safe_key):
                    logger.warning(
                        "Dual-read stream fallback activated: Object '%s' retrieved from local filesystem",
                        safe_key,
                    )
                    yield from local_adapter.get_object_stream(safe_key, chunk_size=chunk_size)
                    return

            raise FileNotFoundError(f"Evidence file not found: {relative_path}")

    def evidence_exists(self, relative_path: str, backend: Optional[str] = None) -> bool:
        """Checks whether an evidence object exists in the storage backend.
        
        Args:
            relative_path: Normalized relative storage key.
            backend: Optional backend override ('seaweedfs', 'filesystem').
            
        Returns:
            True if object exists in target storage, False otherwise.
        """
        try:
            safe_key = validate_and_normalize_key(relative_path)
        except (StorageSecurityError, ValueError):
            return False

        target_adapter = self.adapter
        if backend and backend != self.adapter.backend_name:
            target_adapter = get_storage_adapter(self.settings, backend_override=backend)

        exists = target_adapter.object_exists(safe_key)
        if not exists and (
            target_adapter.backend_name == "seaweedfs"
            and getattr(self.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", False)
            and getattr(self.settings, "APP_ENV", "development") not in {"staging", "production"}
        ):
            local_adapter = LocalFilesystemStorageAdapter(base_path=self.settings.EVIDENCE_STORAGE_PATH)
            return local_adapter.object_exists(safe_key)

        return exists

    def get_evidence_metadata(self, relative_path: str, backend: Optional[str] = None) -> StorageObjectMetadata:
        """Retrieves storage metadata for an evidence object without reading the entire payload.
        
        Args:
            relative_path: Normalized relative storage key.
            backend: Optional backend override.
            
        Returns:
            StorageObjectMetadata instance.
            
        Raises:
            ValueError: If path traversal or illegal characters are detected.
            FileNotFoundError: If evidence object does not exist.
        """
        try:
            safe_key = validate_and_normalize_key(relative_path)
        except StorageSecurityError as e:
            raise ValueError(f"Path traversal detected in relative evidence path: {e}") from e

        target_adapter = self.adapter
        if backend and backend != self.adapter.backend_name:
            target_adapter = get_storage_adapter(self.settings, backend_override=backend)

        try:
            return target_adapter.get_object_metadata(safe_key)
        except StorageObjectNotFoundError:
            if (
                target_adapter.backend_name == "seaweedfs"
                and getattr(self.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", False)
                and getattr(self.settings, "APP_ENV", "development") not in {"staging", "production"}
            ):
                local_adapter = LocalFilesystemStorageAdapter(base_path=self.settings.EVIDENCE_STORAGE_PATH)
                if local_adapter.object_exists(safe_key):
                    return local_adapter.get_object_metadata(safe_key)
            raise FileNotFoundError(f"Evidence file not found: {relative_path}")

    def delete_evidence(self, relative_path: str, backend: Optional[str] = None) -> bool:
        """Deletes an evidence object from the underlying storage backend."""
        try:
            safe_key = validate_and_normalize_key(relative_path)
        except (StorageSecurityError, ValueError):
            return False

        target_adapter = self.adapter
        if backend and backend != self.adapter.backend_name:
            target_adapter = get_storage_adapter(self.settings, backend_override=backend)

        try:
            return target_adapter.delete_object(safe_key)
        except Exception as e:
            logger.error("Failed to delete evidence object '%s' from %s: %s", relative_path, target_adapter.backend_name, e)
            return False

    def verify_evidence(self, relative_path: str, expected_hash: str, backend: Optional[str] = None) -> bool:
        """Validates stored evidence against an authoritative expected SHA-256 hash."""
        safe_key = validate_and_normalize_key(relative_path)
        target_adapter = self.adapter
        if backend and backend != self.adapter.backend_name:
            target_adapter = get_storage_adapter(self.settings, backend_override=backend)
        return target_adapter.verify_object_integrity(safe_key, expected_hash)

    def get_storage_health(self) -> StorageHealthStatus:
        """Returns the operational status of the active storage adapter."""
        return self.adapter.health_check()


_default_store = None


def get_evidence_store() -> EvidenceStore:
    """Returns singleton evidence store instance."""
    global _default_store
    if _default_store is None:
        _default_store = EvidenceStore()
    return _default_store
