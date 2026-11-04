"""Authorization domain package."""

from app.domain.authorization.value_objects import TargetType, OperationType
from app.domain.authorization.entities import TargetAuthorization

__all__ = [
    "TargetType",
    "OperationType",
    "TargetAuthorization",
]

