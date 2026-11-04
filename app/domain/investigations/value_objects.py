"""Domain value objects for investigations."""

from enum import Enum
from dataclasses import dataclass, field
from typing import List
from app.domain.common.value_objects import ValueObject


class InvestigationState(str, Enum):
    """Formal lifecycle states of an investigation."""
    DRAFT = "draft"
    PENDING_AUTHORIZATION = "pending_authorization"
    READY = "ready"
    ACTIVE = "active"
    QUEUED = "queued"
    RUNNING = "running"
    PARTIALLY_COMPLETED = "partially_completed"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


@dataclass(frozen=True)
class InvestigationScope(ValueObject):
    """Target scope specification for an investigation."""
    owned_domains: List[str] = field(default_factory=list)
    approved_ips: List[str] = field(default_factory=list)
    approved_cidrs: List[str] = field(default_factory=list)
    active_targets: List[str] = field(default_factory=list)

    def contains_target(self, target: str) -> bool:
        """Check if target string is within any scope category."""
        target_clean = target.strip().lower()
        if any(d.lower() == target_clean for d in self.owned_domains):
            return True
        if any(ip.strip() == target_clean for ip in self.approved_ips):
            return True
        if any(c.strip() == target_clean for c in self.approved_cidrs):
            return True
        if any(at.strip() == target_clean for at in self.active_targets):
            return True
        return False

