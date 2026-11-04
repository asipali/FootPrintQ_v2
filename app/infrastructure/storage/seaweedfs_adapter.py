"""SeaweedFS storage adapter implementing IEvidenceStoragePort."""

from typing import Optional, Tuple
from app.application.common.interfaces.storage import IEvidenceStoragePort
from app.storage.seaweedfs import SeaweedFSStorageAdapter as RawSeaweedFSStorageAdapter
from app.storage.factory import get_storage_adapter


class SeaweedFSStorageAdapter(IEvidenceStoragePort):
    """Adapts SeaweedFSStorageAdapter to application storage port."""

    def __init__(self, storage: Optional[RawSeaweedFSStorageAdapter] = None):
        try:
            self.storage = storage or get_storage_adapter(backend_override="seaweedfs")
        except Exception:
            self.storage = None

    def store_evidence(
        self,
        investigation_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None
    ) -> str:
        if not self.storage:
            raise RuntimeError("SeaweedFS adapter is not configured or unavailable.")
        key = f"{investigation_id}/{filename}"
        meta = self.storage.put_object(key=key, data=content, content_type=mime_type or "application/octet-stream")
        return meta.path or key

    def retrieve_evidence(self, path: str) -> bytes:
        if not self.storage:
            raise RuntimeError("SeaweedFS adapter is not configured or unavailable.")
        data, _ = self.storage.get_object(path)
        return data

    def delete_evidence(self, path: str) -> bool:
        if not self.storage:
            return False
        return self.storage.delete_object(path)

    def verify_integrity(self, path: str, expected_sha256: str) -> Tuple[bool, str]:
        if not self.storage:
            return False, "SeaweedFS storage adapter not configured."
        valid = self.storage.verify_object_integrity(path, expected_sha256)
        if valid:
            return True, "SeaweedFS object matches expected checksum."
        return False, "SeaweedFS object checksum mismatch or object missing."
