"""Domain entities for Identity and Access Management."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from app.domain.common.entities import AggregateRoot, Entity, utc_now
from app.domain.common.exceptions import InvariantViolationException
from app.domain.identity.value_objects import UserRole, AccountStatus, Username, EmailAddress


@dataclass
class User(AggregateRoot):
    """User aggregate root representing an authenticated platform user."""
    id: str
    username: Username
    email: EmailAddress
    hashed_password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.INVESTIGATOR
    status: AccountStatus = AccountStatus.ACTIVE
    is_active: bool = True
    must_change_password: bool = False
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until and self.locked_until > utc_now():
            return True
        return False

    def can_conduct_investigation(self) -> bool:
        """Check if user role permits conducting investigations."""
        return self.role in (UserRole.ADMINISTRATOR, UserRole.INVESTIGATOR) and self.status == AccountStatus.ACTIVE


@dataclass
class UserSession(Entity):
    """User session tracking authentication tokens."""
    id: str
    user_id: str
    token_hash: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)
    expires_at: Optional[datetime] = None
    revoked: bool = False

    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.expires_at and self.expires_at < utc_now():
            return True
        return False

    def is_valid(self) -> bool:
        """Check if session is currently active and not revoked or expired."""
        return not self.revoked and not self.is_expired()

