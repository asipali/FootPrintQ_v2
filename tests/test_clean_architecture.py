"""Tests for Clean Architecture domain, application, and infrastructure layers."""

import pytest
from app.bootstrap import bootstrap_application
from app.domain.investigations.value_objects import InvestigationState, InvestigationScope
from app.domain.investigations.entities import Investigation
from app.domain.common.exceptions import InvalidStateTransitionException, InvariantViolationException
from app.domain.common.value_objects import SHA256Checksum, DomainName, IPAddress
from app.domain.identity.value_objects import Username, EmailAddress, UserRole
from app.domain.identity.entities import User
from app.application.investigations.commands import CreateInvestigationCommand
from app.application.investigations.queries import GetInvestigationQuery, ListInvestigationsQuery


def test_domain_investigation_state_transitions():
    """Test domain state machine rules in pure entity."""
    inv = Investigation(
        id="inv-test-1",
        name="Test Inv",
        organization_name="Org",
        description="Desc",
        lead_investigator="Lead",
        status=InvestigationState.ACTIVE,
    )
    assert inv.status == InvestigationState.ACTIVE
    assert inv.can_execute_workflows() is True

    # Transition to QUEUED
    inv.transition_to(InvestigationState.QUEUED)
    assert inv.status == InvestigationState.QUEUED

    # Transition to RUNNING
    inv.transition_to(InvestigationState.RUNNING)
    assert inv.status == InvestigationState.RUNNING

    # Invalid transition directly to DRAFT from RUNNING
    with pytest.raises(InvalidStateTransitionException):
        inv.transition_to(InvestigationState.DRAFT)


def test_domain_value_objects():
    """Test validation in pure domain value objects."""
    domain = DomainName("EXAMPLE.COM")
    assert domain.value == "example.com"

    with pytest.raises(InvariantViolationException):
        DomainName("not-a-domain")

    ip = IPAddress("192.168.1.1")
    assert ip.value == "192.168.1.1"

    with pytest.raises(InvariantViolationException):
        IPAddress("999.999.999.999")

    checksum = SHA256Checksum("a" * 64)
    assert checksum.value == "a" * 64

    with pytest.raises(InvariantViolationException):
        SHA256Checksum("short")


def test_bootstrap_container():
    """Test application container bootstrap and service resolution."""
    container = bootstrap_application()
    assert container is not None
    assert container.investigation_service is not None
    assert container.authorization_service is not None
    assert container.evidence_service is not None
    assert container.workflow_service is not None
    assert container.identity_service is not None
    assert container.reporting_service is not None

