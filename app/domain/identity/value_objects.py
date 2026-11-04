"""Domain value objects for user identity and role-based access control."""

from enum import Enum
from dataclasses import dataclass
from app.domain.common.value_objects import ValueObject
from app.domain.common.exceptions import InvariantViolationException


class UserRole(str, Enum):
    """User authorization roles."""
    ADMINISTRATOR = "administrator"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AccountStatus(str, Enum):
    """Lifecycle status for user accounts."""
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REJECTED = "rejected"


@dataclass(frozen=True)
class Username(ValueObject):
    """Validated username."""
    value: str

    def __post_init__(self):
        cleaned = self.value.strip().lower()
        if not cleaned or len(cleaned) < 3 or len(cleaned) > 64:
            raise InvariantViolationException("Username must be between 3 and 64 characters.")
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class EmailAddress(ValueObject):
    """Validated email address."""
    value: str

    def __post_init__(self):
        cleaned = self.value.strip().lower()
        if "@" not in cleaned or "." not in cleaned.split("@")[-1]:
            raise InvariantViolationException("Invalid email address format.")
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value

