"""Evidence application service coordinating evidence capture, retrieval, and verification."""

import hashlib
import uuid
from typing import List, Optional, Tuple
from app.application.common.interfaces.uow import IUnitOfWork
from app.application.common.interfaces.storage import IEvidenceStoragePort
from app.application.evidence.commands import (
    StoreEvidenceCommand,
    VerifyEvidenceIntegrityCommand,
    GetEvidenceQuery,
    ListEvidenceQuery,
)
from app.domain.evidence.entities import EvidenceItem
from app.domain.evidence.value_objects import EvidenceStorageBackend
from app.domain.common.value_objects import SHA256Checksum
from app.domain.common.exceptions import EntityNotFoundException, UnauthorizedOperationException
from app.domain.audit.entities import SecurityAuditEvent
from app.domain.audit.value_objects import AuditAction


class EvidenceApplicationService:
    """Manages forensic evidence lifecycle, integrity checks, and storage."""

    def __init__(
        self,
        uow: IUnitOfWork,
        filesystem_storage: IEvidenceStoragePort,
        seaweedfs_storage: Optional[IEvidenceStoragePort] = None,
    ):
        self.uow = uow
        self.fs_storage = filesystem_storage
        self.seaweedfs_storage = seaweedfs_storage

    def store_evidence(self, cmd: StoreEvidenceCommand) -> EvidenceItem:
        """Store evidence payload in adapter and persist metadata in database."""
        content_hash = hashlib.sha256(cmd.content).hexdigest()
        size_bytes = len(cmd.content)
        evidence_id = f"ev-{uuid.uuid4().hex[:12]}"

        # Choose adapter
        if cmd.use_seaweedfs and self.seaweedfs_storage:
            storage_adapter = self.seaweedfs_storage
            backend = EvidenceStorageBackend.SEAWEEDFS
        else:
            storage_adapter = self.fs_storage
            backend = EvidenceStorageBackend.FILESYSTEM

        # Store payload
        storage_path = storage_adapter.store_evidence(
            investigation_id=cmd.investigation_id,
            filename=cmd.filename,
            content=cmd.content,
        )

        item = EvidenceItem(
            id=evidence_id,
            investigation_id=cmd.investigation_id,
            source_type=cmd.source_type,
            source_name=cmd.source_name,
            target=cmd.target,
            content_hash=SHA256Checksum(content_hash),
            storage_backend=backend,
            raw_content_path=storage_path,
            content_size_bytes=size_bytes,
            job_id=cmd.job_id,
            collection_status=cmd.collection_status,
            source_metadata=cmd.source_metadata,
        )

        with self.uow:
            saved = self.uow.evidence.save(item)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.EVIDENCE_CREATE.value,
                    actor_id=None,
                    details={"evidence_id": evidence_id, "investigation_id": cmd.investigation_id, "backend": backend.value},
                )
            )
            self.uow.commit()

        return saved

    def get_evidence_content(self, query: GetEvidenceQuery) -> Tuple[EvidenceItem, bytes]:
        """Fetch evidence metadata and payload with authorization check."""
        with self.uow:
            item = self.uow.evidence.get_by_id(query.evidence_id)
            if not item:
                raise EntityNotFoundException(f"Evidence item '{query.evidence_id}' not found.")
            inv = self.uow.investigations.get_by_id(item.investigation_id)
            if not inv or not inv.is_user_authorized(query.user_id, query.is_admin):
                raise UnauthorizedOperationException("Unauthorized to access this evidence.")

            if item.is_metadata_only():
                return item, b""

            adapter = self.seaweedfs_storage if (item.is_seaweedfs() and self.seaweedfs_storage) else self.fs_storage
            content = adapter.retrieve_evidence(item.raw_content_path or "")
            return item, content

    def verify_integrity(self, cmd: VerifyEvidenceIntegrityCommand) -> Tuple[bool, str]:
        """Verify hash integrity of stored evidence against database metadata."""
        with self.uow:
            item = self.uow.evidence.get_by_id(cmd.evidence_id)
            if not item:
                raise EntityNotFoundException(f"Evidence item '{cmd.evidence_id}' not found.")
            if item.is_metadata_only():
                return True, "Metadata-only evidence; no payload to verify."

            adapter = self.seaweedfs_storage if (item.is_seaweedfs() and self.seaweedfs_storage) else self.fs_storage
            return adapter.verify_integrity(item.raw_content_path or "", item.content_hash.value)

