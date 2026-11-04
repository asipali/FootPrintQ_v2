"""Local filesystem implementation of the BaseStorageAdapter interface."""

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import BinaryIO, Dict, Generator, Optional, Tuple, Union

from app.config import get_settings
from app.storage.base import (
    BaseStorageAdapter,
    StorageHealthStatus,
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectMetadata,
    StorageObjectNotFoundError,
    StoragePayloadTooLargeError,
    StorageSecurityError,
    compute_sha256,
    validate_and_normalize_key,
    MAX_EVIDENCE_SIZE_BYTES,
)


class LocalFilesystemStorageAdapter(BaseStorageAdapter):
    """Forensic storage adapter backed by the local filesystem."""

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        settings = get_settings()
        self.base_dir = Path(base_path or settings.EVIDENCE_STORAGE_PATH).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def backend_name(self) -> str:
        return "filesystem"

    def _resolve_file_path(self, key: str) -> Path:
        """Resolves storage key to absolute Path within base_dir, strictly blocking traversal."""
        safe_key = validate_and_normalize_key(key)
        resolved_base = self.base_dir.resolve()
        resolved_path = (resolved_base / safe_key).resolve()

        is_safe = False
        try:
            if resolved_path.is_relative_to(resolved_base):
                is_safe = True
        except ValueError:
            pass

        if not is_safe:
            try:
                base_str = os.path.normcase(os.path.abspath(str(resolved_base)))
                path_str = os.path.normcase(os.path.abspath(str(resolved_path)))
                if base_str.startswith("\\\\?\\"):
                    base_str = base_str[4:]
                if path_str.startswith("\\\\?\\"):
                    path_str = path_str[4:]
                if path_str.startswith(base_str + os.sep) or path_str == base_str:
                    is_safe = True
            except Exception:
                pass

        if not is_safe:
            raise StorageSecurityError(f"Path traversal detected for storage key: '{key}'")

        return resolved_path

    def put_object(
        self,
        key: str,
        data: Union[bytes, BinaryIO, str],
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageObjectMetadata:
        file_path = self._resolve_file_path(key)

        # Encode input to raw bytes
        if isinstance(data, str):
            payload_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            payload_bytes = data
        elif hasattr(data, "read"):
            payload_bytes = data.read()
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8")
        else:
            payload_bytes = str(data).encode("utf-8")

        content_hash = compute_sha256(payload_bytes)
        size_bytes = len(payload_bytes)

        if size_bytes > MAX_EVIDENCE_SIZE_BYTES:
            raise StoragePayloadTooLargeError(
                f"Payload size ({size_bytes} bytes) exceeds maximum limit of {MAX_EVIDENCE_SIZE_BYTES} bytes."
            )

        # Immutability and Idempotency check
        if file_path.exists():
            existing_bytes = file_path.read_bytes()
            existing_hash = compute_sha256(existing_bytes)
            if existing_hash.lower() == content_hash.lower():
                stat = file_path.stat()
                return StorageObjectMetadata(
                    key=key,
                    size_bytes=len(existing_bytes),
                    content_hash=existing_hash,
                    content_type=content_type,
                    backend=self.backend_name,
                    created_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                    custom_metadata=metadata or {},
                )
            raise StorageKeyExistsError(f"Evidence storage key already exists with different content: '{key}'")

        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic exclusive write with race-condition idempotency check
        try:
            with file_path.open("xb") as f:
                f.write(payload_bytes)
        except FileExistsError:
            # Race condition: another concurrent writer completed between existence check and exclusive open.
            # Perform idempotency check on the newly written file.
            existing_bytes = file_path.read_bytes()
            existing_hash = compute_sha256(existing_bytes)
            if existing_hash.lower() == content_hash.lower():
                stat = file_path.stat()
                return StorageObjectMetadata(
                    key=key,
                    size_bytes=len(existing_bytes),
                    content_hash=existing_hash,
                    content_type=content_type,
                    backend=self.backend_name,
                    created_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                    custom_metadata=metadata or {},
                )
            raise StorageKeyExistsError(f"Evidence storage key already exists with different content: '{key}'")

        created_at = datetime.now(timezone.utc)
        meta = StorageObjectMetadata(
            key=key,
            size_bytes=size_bytes,
            content_hash=content_hash,
            content_type=content_type,
            backend=self.backend_name,
            created_at=created_at,
            custom_metadata=metadata or {},
        )

        return meta

    def get_object(self, key: str) -> Tuple[bytes, StorageObjectMetadata]:
        file_path = self._resolve_file_path(key)
        if not file_path.is_file():
            raise StorageObjectNotFoundError(f"Storage object '{key}' not found on filesystem.")

        payload_bytes = file_path.read_bytes()
        computed_hash = compute_sha256(payload_bytes)
        stat = file_path.stat()

        created_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        metadata = StorageObjectMetadata(
            key=key,
            size_bytes=len(payload_bytes),
            content_hash=computed_hash,
            content_type=self._guess_content_type(key),
            backend=self.backend_name,
            created_at=created_at,
        )

        return payload_bytes, metadata

    def get_object_stream(self, key: str, chunk_size: int = 65536) -> Generator[bytes, None, None]:
        file_path = self._resolve_file_path(key)
        if not file_path.is_file():
            raise StorageObjectNotFoundError(f"Storage object '{key}' not found on filesystem.")

        with file_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def delete_object(self, key: str) -> bool:
        file_path = self._resolve_file_path(key)
        if not file_path.exists():
            return False

        if file_path.is_file():
            file_path.unlink()
            return True
        return False

    def object_exists(self, key: str) -> bool:
        try:
            file_path = self._resolve_file_path(key)
            return file_path.is_file()
        except (StorageSecurityError, ValueError):
            return False

    def get_object_metadata(self, key: str) -> StorageObjectMetadata:
        file_path = self._resolve_file_path(key)
        if not file_path.is_file():
            raise StorageObjectNotFoundError(f"Storage object '{key}' not found on filesystem.")

        payload_bytes = file_path.read_bytes()
        stat = file_path.stat()
        computed_hash = compute_sha256(payload_bytes)

        return StorageObjectMetadata(
            key=key,
            size_bytes=stat.st_size,
            content_hash=computed_hash,
            content_type=self._guess_content_type(key),
            backend=self.backend_name,
            created_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
        )

    def verify_object_integrity(self, key: str, expected_hash: str) -> bool:
        payload_bytes, _ = self.get_object(key)
        computed_hash = compute_sha256(payload_bytes)

        if computed_hash.lower() != expected_hash.lower():
            raise StorageIntegrityError(
                f"Integrity check failed for '{key}': expected {expected_hash}, computed {computed_hash}"
            )
        return True

    def health_check(self) -> StorageHealthStatus:
        start_time = time.perf_counter()
        try:
            if not self.base_dir.exists():
                return StorageHealthStatus(
                    is_healthy=False,
                    backend=self.backend_name,
                    details=f"Storage root '{self.base_dir}' does not exist.",
                )

            # Verify read/write permissions
            import os
            can_read = os.access(self.base_dir, os.R_OK)
            can_write = os.access(self.base_dir, os.W_OK)

            if not (can_read and can_write):
                return StorageHealthStatus(
                    is_healthy=False,
                    backend=self.backend_name,
                    details=f"Insufficient permissions on storage root (read={can_read}, write={can_write}).",
                )

            latency = (time.perf_counter() - start_time) * 1000.0
            return StorageHealthStatus(
                is_healthy=True,
                backend=self.backend_name,
                details=f"Local storage root '{self.base_dir}' operational (read/write confirmed).",
                latency_ms=round(latency, 2),
            )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return StorageHealthStatus(
                is_healthy=False,
                backend=self.backend_name,
                details=f"Local filesystem probe failed: {str(e)}",
                latency_ms=round(latency, 2),
            )

    @staticmethod
    def _guess_content_type(key: str) -> str:
        lower = key.lower()
        if lower.endswith(".json"):
            return "application/json"
        elif lower.endswith(".xml"):
            return "application/xml"
        elif lower.endswith(".txt") or lower.endswith(".raw"):
            return "text/plain; charset=utf-8"
        elif lower.endswith(".bin"):
            return "application/octet-stream"
        return "application/octet-stream"
