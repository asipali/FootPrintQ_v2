"""Domain entities for target authorization."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple
from app.domain.common.entities import AggregateRoot, utc_now
from app.domain.authorization.value_objects import TargetType, OperationType


@dataclass
class TargetAuthorization(AggregateRoot):
    """Target authorization record establishing legal boundaries for assessment."""
    id: str
    investigation_id: str
    target: str
    target_type: str
    allowed_operations: List[str]
    authorization_reference: str
    approved_by: str
    valid_to: datetime
    valid_from: datetime = field(default_factory=utc_now)
    is_revoked: bool = False
    notes: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)

    def is_valid_for(self, operation: str) -> Tuple[bool, str]:
        """Validate if authorization record covers the specified operation."""
        if self.is_revoked:
            return False, "Target authorization has been revoked."
        now = utc_now()
        if self.valid_from and self.valid_from > now:
            return False, "Authorization is not yet active."
        if self.valid_to and self.valid_to < now:
            return False, "Authorization has expired."
        
        op_norm = operation.strip().upper()
        allowed_norm = [op.strip().upper() for op in (self.allowed_operations or [])]
        if "*" not in allowed_norm and op_norm not in allowed_norm and "ALL" not in allowed_norm:
            return False, f"Operation '{operation}' is not permitted by this authorization."

        return True, "Authorization is valid."

    def revoke(self, reason: Optional[str] = None) -> None:
        """Revoke authorization."""
        self.is_revoked = True
        if reason:
            self.notes = f"{self.notes or ''} [REVOKED: {reason}]".strip()

