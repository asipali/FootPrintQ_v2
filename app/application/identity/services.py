"""Identity application service coordinating user authentication and accounts."""

import uuid
from typing import Optional, Tuple
from app.application.common.interfaces.uow import IUnitOfWork
from app.application.identity.commands import RegisterUserCommand, AuthenticateUserCommand
from app.domain.identity.entities import User
from app.domain.identity.value_objects import UserRole, AccountStatus, Username, EmailAddress
from app.domain.common.exceptions import (
    EntityNotFoundException,
    InvariantViolationException,
    UnauthorizedOperationException,
)
from app.domain.audit.entities import SecurityAuditEvent
from app.domain.audit.value_objects import AuditAction


class IdentityApplicationService:
    """Coordinates user registration, authentication, and session handling."""

    def __init__(self, uow: IUnitOfWork):
        self.uow = uow

    def register_user(self, cmd: RegisterUserCommand) -> User:
        """Register a new user account."""
        username_vo = Username(cmd.username)
        email_vo = EmailAddress(cmd.email)

        with self.uow:
            existing = self.uow.users.get_by_username(username_vo.value)
            if existing:
                raise InvariantViolationException(f"Username '{username_vo.value}' already exists.")

            user_id = f"usr-{uuid.uuid4().hex[:12]}"
            # Note: caller or presentation hashes password; here we store securely
            user = User(
                id=user_id,
                username=username_vo,
                email=email_vo,
                hashed_password=cmd.password,
                full_name=cmd.full_name,
                role=UserRole(cmd.role.lower()),
                status=AccountStatus.ACTIVE,
            )
            saved = self.uow.users.save(user)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.USER_REGISTER.value,
                    actor_id=user_id,
                    details={"username": username_vo.value},
                )
            )
            self.uow.commit()

        return saved

