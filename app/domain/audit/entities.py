"""Domain entities for security audit trails."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from app.domain.common.entities import Entity, utc_now
from app.domain.audit.value_objects import AuditAction


@dataclass
class SecurityAuditEvent(Entity):
    """Immutable audit record for security events."""
    id: str
    event_type: str
    outcome: str = "SUCCESS"
    actor_id: Optional[str] = None
    target_user_id: Optional[str] = None
    request_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utc_now)

