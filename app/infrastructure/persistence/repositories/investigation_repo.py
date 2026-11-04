"""SQLAlchemy implementation of IInvestigationRepository."""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.application.common.interfaces.repositories import IInvestigationRepository
from app.domain.investigations.entities import Investigation
from app.domain.investigations.value_objects import InvestigationState, InvestigationScope
from app.models.investigation import InvestigationModel


class SqlAlchemyInvestigationRepository(IInvestigationRepository):
    """Concrete repository mapping between Investigation domain aggregate and SQLAlchemy model."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, investigation_id: str) -> Optional[Investigation]:
        model = self.session.get(InvestigationModel, investigation_id)
        if not model:
            return None
        return self._to_domain(model)

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Investigation]:
        models = self.session.query(InvestigationModel).offset(offset).limit(limit).all()
        return [self._to_domain(m) for m in models]

    def save(self, investigation: Investigation) -> Investigation:
        model = self.session.get(InvestigationModel, investigation.id)
        if not model:
            model = InvestigationModel(id=investigation.id)
            self.session.add(model)

        model.name = investigation.name
        model.organization_name = investigation.organization_name
        model.description = investigation.description
        model.lead_investigator = investigation.lead_investigator
        model.owner_user_id = investigation.owner_user_id
        model.team_members = list(investigation.team_members or [])
        model.status = investigation.status.value
        model.owned_domains = list(investigation.scope.owned_domains or [])
        model.approved_ips = list(investigation.scope.approved_ips or [])
        model.approved_cidrs = list(investigation.scope.approved_cidrs or [])
        model.active_targets = list(investigation.scope.active_targets or [])
        model.active_scanning_enabled = investigation.active_scanning_enabled
        model.authorization_reference = investigation.authorization_reference
        model.authorization_expiry = investigation.authorization_expiry

        self.session.flush()
        return self._to_domain(model)

    def delete(self, investigation_id: str) -> bool:
        model = self.session.get(InvestigationModel, investigation_id)
        if not model:
            return False
        self.session.delete(model)
        self.session.flush()
        return True

    @staticmethod
    def _to_domain(model: InvestigationModel) -> Investigation:
        try:
            status_enum = InvestigationState(model.status.lower())
        except (ValueError, AttributeError):
            status_enum = InvestigationState.ACTIVE

        scope = InvestigationScope(
            owned_domains=list(model.owned_domains or []),
            approved_ips=list(model.approved_ips or []),
            approved_cidrs=list(model.approved_cidrs or []),
            active_targets=list(model.active_targets or []),
        )

        return Investigation(
            id=model.id,
            name=model.name,
            organization_name=model.organization_name,
            description=model.description,
            lead_investigator=model.lead_investigator,
            owner_user_id=model.owner_user_id,
            team_members=list(model.team_members or []),
            status=status_enum,
            scope=scope,
            active_scanning_enabled=model.active_scanning_enabled,
            authorization_reference=model.authorization_reference,
            authorization_expiry=model.authorization_expiry,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

