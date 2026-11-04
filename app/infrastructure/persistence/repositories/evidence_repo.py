"""SQLAlchemy implementation of IEvidenceRepository."""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.application.common.interfaces.repositories import IEvidenceRepository
from app.domain.evidence.entities import EvidenceItem
from app.domain.evidence.value_objects import EvidenceStorageBackend
from app.domain.common.value_objects import SHA256Checksum
from app.models.recon import EvidenceModel


class SqlAlchemyEvidenceRepository(IEvidenceRepository):
    """Concrete repository mapping between EvidenceItem domain aggregate and SQLAlchemy model."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, evidence_id: str) -> Optional[EvidenceItem]:
        model = self.session.get(EvidenceModel, evidence_id)
        return self._to_domain(model) if model else None

    def list_by_investigation(self, investigation_id: str) -> List[EvidenceItem]:
        models = self.session.query(EvidenceModel).filter(
            EvidenceModel.investigation_id == investigation_id
        ).all()
        return [self._to_domain(m) for m in models]

    def save(self, item: EvidenceItem) -> EvidenceItem:
        model = self.session.get(EvidenceModel, item.id)
        if not model:
            model = EvidenceModel(id=item.id)
            self.session.add(model)

        model.investigation_id = item.investigation_id
        model.job_id = item.job_id
        model.source_type = item.source_type
        model.source_name = item.source_name
        model.target = item.target
        model.collection_status = item.collection_status
        model.raw_content_path = item.raw_content_path
        model.storage_backend = item.storage_backend.value
        model.content_hash = item.content_hash.value
        model.content_size_bytes = item.content_size_bytes
        model.source_metadata = dict(item.source_metadata or {})

        self.session.flush()
        return self._to_domain(model)

    @staticmethod
    def _to_domain(model: EvidenceModel) -> EvidenceItem:
        try:
            backend = EvidenceStorageBackend(model.storage_backend)
        except (ValueError, AttributeError):
            backend = EvidenceStorageBackend.FILESYSTEM

        return EvidenceItem(
            id=model.id,
            investigation_id=model.investigation_id,
            source_type=model.source_type,
            source_name=model.source_name,
            target=model.target,
            content_hash=SHA256Checksum(model.content_hash),
            storage_backend=backend,
            raw_content_path=model.raw_content_path,
            content_size_bytes=model.content_size_bytes,
            job_id=model.job_id,
            collection_status=model.collection_status,
            source_metadata=dict(model.source_metadata or {}),
            collected_at=model.collected_at,
        )

