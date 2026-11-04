"""Target authorization application service."""

import uuid
from typing import Optional, List, Tuple
from app.application.common.interfaces.uow import IUnitOfWork
from app.application.authorization.commands import CreateAuthorizationCommand, RevokeAuthorizationCommand
from app.domain.authorization.entities import TargetAuthorization
from app.domain.common.exceptions import EntityNotFoundException, UnauthorizedOperationException
from app.domain.audit.entities import SecurityAuditEvent
from app.domain.audit.value_objects import AuditAction


class TargetAuthorizationService:
    """Manages target scope authorization records and boundary checks."""

    def __init__(self, uow: IUnitOfWork):
        self.uow = uow

    def create_authorization(self, cmd: CreateAuthorizationCommand) -> TargetAuthorization:
        """Create and store target authorization."""
        auth_id = f"auth-{uuid.uuid4().hex[:8]}"
        auth = TargetAuthorization(
            id=auth_id,
            investigation_id=cmd.investigation_id,
            target=cmd.target,
            target_type=cmd.target_type,
            allowed_operations=cmd.allowed_operations,
            authorization_reference=cmd.authorization_reference,
            approved_by=cmd.approved_by,
            valid_to=cmd.valid_to,
            valid_from=cmd.valid_from or TargetAuthorization.__dataclass_fields__["valid_from"].default_factory(),
            notes=cmd.notes,
        )

        with self.uow:
            saved = self.uow.authorizations.save(auth)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.TARGET_AUTHORIZE.value,
                    actor_id=cmd.approved_by,
                    details={"authorization_id": auth_id, "target": cmd.target, "investigation_id": cmd.investigation_id},
                )
            )
            self.uow.commit()

        return saved

    def verify_authorization(self, investigation_id: str, target: str, operation: str) -> Tuple[bool, str]:
        """Verify whether an active authorization covers the target and operation."""
        with self.uow:
            auth = self.uow.authorizations.find_active(investigation_id, target)
            if not auth:
                return False, f"Target '{target}' does not have an active authorization record for this investigation."
            return auth.is_valid_for(operation)

    def revoke_authorization(self, cmd: RevokeAuthorizationCommand) -> None:
        """Revoke an existing authorization record."""
        with self.uow:
            auth = self.uow.authorizations.get_by_id(cmd.authorization_id)
            if not auth:
                raise EntityNotFoundException(f"Authorization record '{cmd.authorization_id}' not found.")
            auth.revoke(cmd.reason)
            self.uow.authorizations.save(auth)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.TARGET_REVOKE.value,
                    actor_id=cmd.revoked_by,
                    details={"authorization_id": cmd.authorization_id, "reason": cmd.reason},
                )
            )
            self.uow.commit()

