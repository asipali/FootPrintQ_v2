"""Target authorization commands."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class CreateAuthorizationCommand:
    """Command to grant authorization for reconnaissance on a target."""
    investigation_id: str
    target: str
    target_type: str
    allowed_operations: List[str]
    authorization_reference: str
    approved_by: str
    valid_to: datetime
    valid_from: Optional[datetime] = None
    notes: Optional[str] = None


@dataclass
class RevokeAuthorizationCommand:
    """Command to revoke a target authorization."""
    authorization_id: str
    revoked_by: str
    reason: Optional[str] = None

