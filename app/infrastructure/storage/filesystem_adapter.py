"""Filesystem storage adapter implementing IEvidenceStoragePort."""

from typing import Optional, Tuple
from app.application.common.interfaces.storage import IEvidenceStoragePort
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.factory import get_storage_adapter


class FilesystemStorageAdapter(IEvidenceStoragePort):
    """Adapts LocalFilesystemStorageAdapter to application storage port."""

    def __init__(self, storage: Optional[LocalFilesystemStorageAdapter] = None):
        self.storage = storage or get_storage_adapter(backend_override="filesystem")

    def store_evidence(
        self,
        investigation_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None
    ) -> str:
        key = f"{investigation_id}/{filename}"
        meta = self.storage.put_object(key=key, data=content, content_type=mime_type or "application/octet-stream")
        return meta.path or key

    def retrieve_evidence(self, path: str) -> bytes:
        data, _ = self.storage.get_object(path)
        return data

    def delete_evidence(self, path: str) -> bool:
        return self.storage.delete_object(path)

    def verify_integrity(self, path: str, expected_sha256: str) -> Tuple[bool, str]:
        valid = self.storage.verify_object_integrity(path, expected_sha256)
        if valid:
            return True, "Filesystem payload matches expected checksum."
        return False, "Filesystem payload checksum mismatch or file missing."
