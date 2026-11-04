"""SQLAlchemy implementation of ITargetAuthorizationRepository."""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.application.common.interfaces.repositories import ITargetAuthorizationRepository
from app.domain.authorization.entities import TargetAuthorization
from app.domain.authorization.value_objects import TargetType
from app.models.recon import TargetAuthorizationModel


class SqlAlchemyTargetAuthorizationRepository(ITargetAuthorizationRepository):
    """Concrete repository mapping between TargetAuthorization domain entity and SQLAlchemy model."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, auth_id: str) -> Optional[TargetAuthorization]:
        model = self.session.get(TargetAuthorizationModel, auth_id)
        return self._to_domain(model) if model else None

    def list_by_investigation(self, investigation_id: str) -> List[TargetAuthorization]:
        models = self.session.query(TargetAuthorizationModel).filter(
            TargetAuthorizationModel.investigation_id == investigation_id
        ).all()
        return [self._to_domain(m) for m in models]

    def find_active(self, investigation_id: str, target: str) -> Optional[TargetAuthorization]:
        models = self.session.query(TargetAuthorizationModel).filter(
            TargetAuthorizationModel.investigation_id == investigation_id,
            TargetAuthorizationModel.target == target.strip().lower(),
            TargetAuthorizationModel.is_revoked == False,
        ).all()
        for m in models:
            domain_entity = self._to_domain(m)
            valid, _ = domain_entity.is_valid_for("ALL")
            if valid:
                return domain_entity
        return None

    def save(self, auth: TargetAuthorization) -> TargetAuthorization:
        model = self.session.get(TargetAuthorizationModel, auth.id)
        if not model:
            model = TargetAuthorizationModel(id=auth.id)
            self.session.add(model)

        model.investigation_id = auth.investigation_id
        model.target = auth.target
        model.target_type = auth.target_type
        model.allowed_operations = list(auth.allowed_operations or [])
        model.authorization_reference = auth.authorization_reference
        model.approved_by = auth.approved_by
        model.valid_from = auth.valid_from
        model.valid_to = auth.valid_to
        model.is_revoked = auth.is_revoked
        model.notes = auth.notes

        self.session.flush()
        return self._to_domain(model)

    @staticmethod
    def _to_domain(model: TargetAuthorizationModel) -> TargetAuthorization:
        return TargetAuthorization(
            id=model.id,
            investigation_id=model.investigation_id,
            target=model.target,
            target_type=model.target_type,
            allowed_operations=list(model.allowed_operations or []),
            authorization_reference=model.authorization_reference,
            approved_by=model.approved_by,
            valid_from=model.valid_from,
            valid_to=model.valid_to,
            is_revoked=model.is_revoked,
            notes=model.notes,
            created_at=model.created_at,
        )

