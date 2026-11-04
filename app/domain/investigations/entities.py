"""Domain entities for investigations."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from app.domain.common.entities import AggregateRoot, utc_now
from app.domain.common.exceptions import InvalidStateTransitionException, InvariantViolationException
from app.domain.investigations.value_objects import InvestigationState, InvestigationScope


# Allowed transitions in state machine
VALID_TRANSITIONS = {
    InvestigationState.DRAFT: {InvestigationState.PENDING_AUTHORIZATION, InvestigationState.READY, InvestigationState.ACTIVE, InvestigationState.CANCELLED},
    InvestigationState.PENDING_AUTHORIZATION: {InvestigationState.READY, InvestigationState.ACTIVE, InvestigationState.CANCELLED, InvestigationState.DRAFT},
    InvestigationState.READY: {InvestigationState.QUEUED, InvestigationState.RUNNING, InvestigationState.ACTIVE, InvestigationState.CANCELLED, InvestigationState.ARCHIVED},
    InvestigationState.ACTIVE: {InvestigationState.QUEUED, InvestigationState.RUNNING, InvestigationState.PARTIALLY_COMPLETED, InvestigationState.COMPLETED, InvestigationState.FAILED, InvestigationState.CANCELLED, InvestigationState.ARCHIVED},
    InvestigationState.QUEUED: {InvestigationState.RUNNING, InvestigationState.CANCELLED, InvestigationState.FAILED},
    InvestigationState.RUNNING: {InvestigationState.PARTIALLY_COMPLETED, InvestigationState.COMPLETED, InvestigationState.FAILED, InvestigationState.CANCELLED},
    InvestigationState.PARTIALLY_COMPLETED: {InvestigationState.QUEUED, InvestigationState.RUNNING, InvestigationState.COMPLETED, InvestigationState.ARCHIVED, InvestigationState.CANCELLED},
    InvestigationState.COMPLETED: {InvestigationState.ARCHIVED},
    InvestigationState.FAILED: {InvestigationState.QUEUED, InvestigationState.READY, InvestigationState.ARCHIVED, InvestigationState.CANCELLED},
    InvestigationState.CANCELLED: {InvestigationState.ARCHIVED, InvestigationState.DRAFT},
    InvestigationState.ARCHIVED: set(),  # Terminal read-only
}


@dataclass
class Investigation(AggregateRoot):
    """Investigation aggregate root managing target scope, lifecycle, and access control."""
    id: str
    name: str
    organization_name: str
    description: str
    lead_investigator: str
    owner_user_id: Optional[str] = None
    team_members: List[str] = field(default_factory=list)
    status: InvestigationState = InvestigationState.ACTIVE
    scope: InvestigationScope = field(default_factory=InvestigationScope)
    active_scanning_enabled: bool = False
    authorization_reference: Optional[str] = None
    authorization_expiry: Optional[datetime] = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def transition_to(self, new_state: InvestigationState) -> None:
        """Validate and apply a lifecycle transition."""
        allowed = VALID_TRANSITIONS.get(self.status, set())
        if new_state not in allowed:
            raise InvalidStateTransitionException(
                f"Cannot transition investigation '{self.id}' from '{self.status.value}' to '{new_state.value}'."
            )
        self.status = new_state
        self.updated_at = utc_now()

    def can_execute_workflows(self) -> bool:
        """Check if investigation status permits executing workflows."""
        return self.status in (
            InvestigationState.READY,
            InvestigationState.ACTIVE,
            InvestigationState.QUEUED,
            InvestigationState.RUNNING,
            InvestigationState.PARTIALLY_COMPLETED,
        )

    def is_user_authorized(self, user_id: str, is_admin: bool = False) -> bool:
        """Check if user has access to this investigation."""
        if is_admin:
            return True
        if self.owner_user_id == user_id:
            return True
        if user_id in self.team_members:
            return True
        return False

