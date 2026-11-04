"""Investigation application service coordinating use cases."""

import uuid
from typing import List, Optional
from app.application.common.interfaces.uow import IUnitOfWork
from app.application.investigations.commands import CreateInvestigationCommand, TransitionInvestigationStatusCommand
from app.application.investigations.queries import GetInvestigationQuery, ListInvestigationsQuery, InvestigationDTO
from app.domain.investigations.entities import Investigation
from app.domain.investigations.value_objects import InvestigationState, InvestigationScope
from app.domain.common.exceptions import (
    EntityNotFoundException,
    UnauthorizedOperationException,
    InvalidStateTransitionException,
)
from app.domain.audit.entities import SecurityAuditEvent
from app.domain.audit.value_objects import AuditAction


class InvestigationApplicationService:
    """Orchestrates investigation lifecycle use cases."""

    def __init__(self, uow: IUnitOfWork):
        self.uow = uow

    def create_investigation(self, cmd: CreateInvestigationCommand) -> InvestigationDTO:
        """Create and persist a new investigation."""
        inv_id = cmd.custom_id or f"inv-{uuid.uuid4().hex[:8]}"
        scope = InvestigationScope(
            owned_domains=cmd.owned_domains,
            approved_ips=cmd.approved_ips,
            approved_cidrs=cmd.approved_cidrs,
            active_targets=cmd.active_targets,
        )
        inv = Investigation(
            id=inv_id,
            name=cmd.name,
            organization_name=cmd.organization_name,
            description=cmd.description,
            lead_investigator=cmd.lead_investigator,
            owner_user_id=cmd.owner_user_id,
            team_members=cmd.team_members,
            status=InvestigationState.ACTIVE,
            scope=scope,
            active_scanning_enabled=cmd.active_scanning_enabled,
            authorization_reference=cmd.authorization_reference,
            authorization_expiry=cmd.authorization_expiry,
        )

        with self.uow:
            saved = self.uow.investigations.save(inv)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.INVESTIGATION_CREATE.value,
                    actor_id=cmd.owner_user_id,
                    details={"investigation_id": inv_id, "name": cmd.name},
                )
            )
            self.uow.commit()

        return self._to_dto(saved)

    def get_investigation(self, query: GetInvestigationQuery) -> InvestigationDTO:
        """Retrieve investigation by ID with RBAC check."""
        with self.uow:
            inv = self.uow.investigations.get_by_id(query.investigation_id)
            if not inv:
                raise EntityNotFoundException(f"Investigation '{query.investigation_id}' not found.")
            if not inv.is_user_authorized(query.user_id, query.is_admin):
                raise UnauthorizedOperationException("Access to this investigation is unauthorized.")
            return self._to_dto(inv)

    def list_investigations(self, query: ListInvestigationsQuery) -> List[InvestigationDTO]:
        """List investigations accessible to user."""
        with self.uow:
            all_invs = self.uow.investigations.list_all(limit=query.limit, offset=query.offset)
            filtered = [
                self._to_dto(inv) for inv in all_invs
                if inv.is_user_authorized(query.user_id, query.is_admin)
            ]
            return filtered

    def transition_status(self, cmd: TransitionInvestigationStatusCommand) -> InvestigationDTO:
        """Transition investigation state."""
        with self.uow:
            inv = self.uow.investigations.get_by_id(cmd.investigation_id)
            if not inv:
                raise EntityNotFoundException(f"Investigation '{cmd.investigation_id}' not found.")
            if not inv.is_user_authorized(cmd.user_id, cmd.is_admin):
                raise UnauthorizedOperationException("Unauthorized to modify this investigation.")

            try:
                target_state = InvestigationState(cmd.new_status.lower())
            except ValueError:
                raise InvalidStateTransitionException(f"Invalid investigation status: '{cmd.new_status}'.")

            inv.transition_to(target_state)
            saved = self.uow.investigations.save(inv)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.INVESTIGATION_UPDATE.value,
                    actor_id=cmd.user_id,
                    details={"investigation_id": cmd.investigation_id, "new_status": target_state.value, "reason": cmd.reason},
                )
            )
            self.uow.commit()
            return self._to_dto(saved)

    @staticmethod
    def _to_dto(inv: Investigation) -> InvestigationDTO:
        return InvestigationDTO(
            id=inv.id,
            name=inv.name,
            organization_name=inv.organization_name,
            description=inv.description,
            lead_investigator=inv.lead_investigator,
            status=inv.status.value,
            owner_user_id=inv.owner_user_id,
            team_members=list(inv.team_members or []),
            owned_domains=list(inv.scope.owned_domains or []),
            approved_ips=list(inv.scope.approved_ips or []),
            approved_cidrs=list(inv.scope.approved_cidrs or []),
            active_targets=list(inv.scope.active_targets or []),
            active_scanning_enabled=inv.active_scanning_enabled,
            authorization_reference=inv.authorization_reference,
            authorization_expiry=inv.authorization_expiry.isoformat() if inv.authorization_expiry else None,
            created_at=inv.created_at.isoformat() if inv.created_at else None,
            updated_at=inv.updated_at.isoformat() if inv.updated_at else None,
        )

