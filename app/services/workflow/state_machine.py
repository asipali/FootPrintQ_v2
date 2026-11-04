"""Investigation Lifecycle State Machine for FootprintIQ.

Enforces deterministic transitions across all formal investigation lifecycle states:
- DRAFT: Initial investigation creation and scope definition.
- PENDING_AUTHORIZATION: Scope configured, awaiting required target authorization records.
- READY: Scope authorized and verified; ready for workflow execution.
- QUEUED: Workflow dispatched into the durable job queue.
- RUNNING: Actively executing reconnaissance or assessment stages.
- PARTIALLY_COMPLETED: One or more stages finished, but optional/unavailable stages were skipped.
- COMPLETED: All authorized workflow stages executed successfully.
- FAILED: Fatal error interrupted execution.
- CANCELLED: Aborted by an authorized investigator or administrator.
- ARCHIVED: Non-destructive closed/archived state (read-only).

Also retains backward compatibility with existing legacy records ('active' and 'CREATED').
"""

from typing import Set, Dict, Optional
from fastapi import HTTPException, status


# Formal Lifecycle State Identifiers
STATUS_DRAFT = "draft"
STATUS_PENDING_AUTHORIZATION = "pending_authorization"
STATUS_READY = "ready"
STATUS_ACTIVE = "active"  # Retained as legacy operational state equivalent to READY/RUNNING
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_PARTIALLY_COMPLETED = "partially_completed"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_ARCHIVED = "archived"

VALID_INVESTIGATION_STATUSES: Set[str] = {
    STATUS_DRAFT,
    STATUS_PENDING_AUTHORIZATION,
    STATUS_READY,
    STATUS_ACTIVE,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_PARTIALLY_COMPLETED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_ARCHIVED,
}

# States where stage execution or scanning is permissible
EXECUTION_PERMITTED_STATUSES: Set[str] = {
    STATUS_READY,
    STATUS_ACTIVE,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_PARTIALLY_COMPLETED,
}

# Terminal states where modifications and job dispatch are prohibited
TERMINAL_STATUSES: Set[str] = {
    STATUS_COMPLETED,
    STATUS_ARCHIVED,
}

# Deterministic transition matrix: current_state -> set of allowed next_states
ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    STATUS_DRAFT: {
        STATUS_PENDING_AUTHORIZATION,
        STATUS_READY,
        STATUS_ACTIVE,
        STATUS_CANCELLED,
        STATUS_ARCHIVED,
    },
    STATUS_PENDING_AUTHORIZATION: {
        STATUS_READY,
        STATUS_ACTIVE,
        STATUS_DRAFT,
        STATUS_CANCELLED,
        STATUS_ARCHIVED,
    },
    STATUS_READY: {
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_CANCELLED,
        STATUS_ARCHIVED,
        STATUS_DRAFT,
    },
    STATUS_ACTIVE: {  # Legacy operational state
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_PARTIALLY_COMPLETED,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
        STATUS_ARCHIVED,
    },
    STATUS_QUEUED: {
        STATUS_RUNNING,
        STATUS_CANCELLED,
        STATUS_FAILED,
    },
    STATUS_RUNNING: {
        STATUS_PARTIALLY_COMPLETED,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
    },
    STATUS_PARTIALLY_COMPLETED: {
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_COMPLETED,
        STATUS_ARCHIVED,
    },
    STATUS_COMPLETED: {
        STATUS_QUEUED,
        STATUS_RUNNING,  # Re-scan capability
        STATUS_ARCHIVED,
    },
    STATUS_FAILED: {
        STATUS_QUEUED,
        STATUS_RUNNING,  # Retry capability
        STATUS_ARCHIVED,
    },
    STATUS_CANCELLED: {
        STATUS_READY,
        STATUS_QUEUED,
        STATUS_ARCHIVED,
    },
    STATUS_ARCHIVED: set(),  # Terminal state: strictly no outgoing transitions
}


def normalize_status(value: Optional[str]) -> str:
    """Normalizes arbitrary status string into canonical lowercase identifier."""
    if not value or not isinstance(value, str):
        return STATUS_ACTIVE
    v = value.strip().lower()
    if v == "created":
        return STATUS_DRAFT
    if v == "in_progress":
        return STATUS_RUNNING
    if v == "partial":
        return STATUS_PARTIALLY_COMPLETED
    if v in VALID_INVESTIGATION_STATUSES:
        return v
    return v


def can_transition(current_status: str, target_status: str) -> bool:
    """Evaluates whether transitioning from current_status to target_status is permitted."""
    curr = normalize_status(current_status)
    target = normalize_status(target_status)

    if curr == target:
        return True  # Idempotent state assignment is always safe

    allowed_next = ALLOWED_TRANSITIONS.get(curr, set())
    return target in allowed_next


def validate_transition(current_status: str, target_status: str) -> None:
    """Validates transition, raising an HTTP 409 Conflict if prohibited."""
    curr = normalize_status(current_status)
    target = normalize_status(target_status)

    if not can_transition(curr, target):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Invalid investigation status transition: '{curr}' -> '{target}'.",
        )

