"""Unit tests for the Investigation Lifecycle State Machine."""

import pytest
from fastapi import HTTPException

from app.services.workflow.state_machine import (
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
    can_transition,
    validate_transition,
    normalize_status,
)


def test_state_normalization():
    assert normalize_status("draft") == STATUS_DRAFT
    assert normalize_status("DRAFT") == STATUS_DRAFT
    assert normalize_status("CREATED") == STATUS_DRAFT
    assert normalize_status("in_progress") == STATUS_RUNNING
    assert normalize_status("partial") == STATUS_PARTIALLY_COMPLETED
    assert normalize_status("active") == STATUS_ACTIVE


def test_valid_forward_transitions():
    # Draft -> Pending Auth -> Ready -> Queued -> Running -> Completed
    assert can_transition(STATUS_DRAFT, STATUS_PENDING_AUTHORIZATION)
    assert can_transition(STATUS_PENDING_AUTHORIZATION, STATUS_READY)
    assert can_transition(STATUS_READY, STATUS_QUEUED)
    assert can_transition(STATUS_QUEUED, STATUS_RUNNING)
    assert can_transition(STATUS_RUNNING, STATUS_COMPLETED)

    # Running -> Partially Completed -> Completed
    assert can_transition(STATUS_RUNNING, STATUS_PARTIALLY_COMPLETED)
    assert can_transition(STATUS_PARTIALLY_COMPLETED, STATUS_COMPLETED)

    # Running -> Failed -> Retry (Queued)
    assert can_transition(STATUS_RUNNING, STATUS_FAILED)
    assert can_transition(STATUS_FAILED, STATUS_QUEUED)

    # Completed -> Re-scan (Queued)
    assert can_transition(STATUS_COMPLETED, STATUS_QUEUED)

    # Idempotent state is always permitted
    assert can_transition(STATUS_RUNNING, STATUS_RUNNING)


def test_invalid_transitions_rejected():
    # Cannot jump directly from draft to running
    assert not can_transition(STATUS_DRAFT, STATUS_RUNNING)
    with pytest.raises(HTTPException) as exc:
        validate_transition(STATUS_DRAFT, STATUS_RUNNING)
    assert exc.value.status_code == 409

    # Archived is strictly terminal; cannot transition anywhere
    assert not can_transition(STATUS_ARCHIVED, STATUS_READY)
    assert not can_transition(STATUS_ARCHIVED, STATUS_DRAFT)
    assert not can_transition(STATUS_ARCHIVED, STATUS_ACTIVE)
    with pytest.raises(HTTPException) as exc:
        validate_transition(STATUS_ARCHIVED, STATUS_ACTIVE)
    assert exc.value.status_code == 409

