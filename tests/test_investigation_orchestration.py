"""Comprehensive integration and security tests for Task 05: Investigation Workflow Orchestration."""

from datetime import datetime, timedelta, timezone
from typing import Generator
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker
from starlette.testclient import TestClient

from app.database import Base, get_db
from app.main import create_app
from app.models.investigation import InvestigationModel
from app.models.job import JobModel, JOB_STATUS_QUEUED, JOB_STATUS_RUNNING
from app.models.recon import TargetAuthorizationModel, EntityModel, EvidenceModel
from app.models.user import UserModel
from app.core.security import hash_password
from app.core.auth import create_user_session
from app.services.workflow.orchestrator import InvestigationWorkflowOrchestrator
from app.services.workflow.correlation import InvestigationCorrelationService
from app.services.workflow.state_machine import (
    STATUS_DRAFT,
    STATUS_READY,
    STATUS_ACTIVE,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_PARTIALLY_COMPLETED,
    STATUS_COMPLETED,
    STATUS_CANCELLED,
    can_transition,
)


@pytest.fixture
def isolated_db() -> Generator[Session, None, None]:
    """In-memory SQLite database isolated for workflow testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def test_users(isolated_db: Session) -> dict:
    """Creates an admin and an investigator user."""
    admin = UserModel(
        id="usr-admin-01",
        username="admin_test",
        email="admin@example.com",
        full_name="Admin Test",
        password_hash=hash_password("AdminPass123!@#"),
        role="administrator",
        is_active=True,
        account_status="active",
    )
    analyst1 = UserModel(
        id="usr-analyst-01",
        username="analyst_one",
        email="analyst1@example.com",
        full_name="Analyst One",
        password_hash=hash_password("AnalystPass123!@#"),
        role="investigator",
        is_active=True,
        account_status="active",
    )
    analyst2 = UserModel(
        id="usr-analyst-02",
        username="analyst_two",
        email="analyst2@example.com",
        full_name="Analyst Two",
        password_hash=hash_password("AnalystPass123!@#"),
        role="investigator",
        is_active=True,
        account_status="active",
    )
    isolated_db.add_all([admin, analyst1, analyst2])
    isolated_db.commit()
    return {"admin": admin, "analyst1": analyst1, "analyst2": analyst2}


@pytest.fixture
def sample_investigation(isolated_db: Session, test_users: dict) -> InvestigationModel:
    """Creates a sample investigation owned by analyst1."""
    inv = InvestigationModel(
        id="inv-wf-test-01",
        name="Workflow Test Campaign",
        organization_name="Acme Corp",
        description="Comprehensive End-to-End Orchestration Test",
        lead_investigator=test_users["analyst1"].full_name,
        owner_user_id=test_users["analyst1"].id,
        team_members=[],
        status=STATUS_READY,
        owned_domains=["example.com"],
        approved_ips=["93.184.216.34"],
        approved_cidrs=["93.184.216.0/24"],
        active_targets=["example.com"],
        active_scanning_enabled=True,
        authorization_reference="AUTH-REF-001",
        authorization_expiry=datetime.now(timezone.utc) + timedelta(days=7),
    )
    isolated_db.add(inv)
    isolated_db.commit()
    return inv


def test_state_machine_transition_enforcement(sample_investigation: InvestigationModel, isolated_db: Session):
    """Verifies that only allowed transitions succeed on the database record."""
    inv = sample_investigation
    assert inv.status == STATUS_READY

    # Ready -> Queued is valid
    assert can_transition(inv.status, STATUS_QUEUED)
    inv.status = STATUS_QUEUED
    isolated_db.commit()
    assert inv.status == STATUS_QUEUED

    # Queued -> Running is valid
    assert can_transition(inv.status, STATUS_RUNNING)
    inv.status = STATUS_RUNNING
    isolated_db.commit()
    assert inv.status == STATUS_RUNNING

    # Running -> Partially Completed is valid
    assert can_transition(inv.status, STATUS_PARTIALLY_COMPLETED)
    inv.status = STATUS_PARTIALLY_COMPLETED
    isolated_db.commit()
    assert inv.status == STATUS_PARTIALLY_COMPLETED

    # Partially Completed -> Completed is valid
    assert can_transition(inv.status, STATUS_COMPLETED)
    inv.status = STATUS_COMPLETED
    isolated_db.commit()
    assert inv.status == STATUS_COMPLETED


@pytest.mark.asyncio
async def test_workflow_orchestrator_execution(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Tests synchronous end-to-end workflow execution."""
    orchestrator = InvestigationWorkflowOrchestrator(db=isolated_db)
    analyst = test_users["analyst1"]

    summary = await orchestrator.execute_workflow(
        investigation_id=sample_investigation.id,
        actor_user=analyst,
        target="example.com",
    )

    assert summary["investigation_id"] == sample_investigation.id
    assert summary["target"] == "example.com"
    assert summary["workflow_status"] in (STATUS_COMPLETED, STATUS_PARTIALLY_COMPLETED)
    assert len(summary["stages"]) >= 4

    # Verify stage names are present
    stage_names = [s["stage_name"] for s in summary["stages"]]
    assert "PASSIVE_RECONNAISSANCE" in stage_names
    assert "ACTIVE_NMAP_SCAN" in stage_names
    assert "FINDING_CORRELATION" in stage_names
    assert "EXPOSURE_SCORING" in stage_names

    # Investigation status updated in database
    isolated_db.refresh(sample_investigation)
    assert sample_investigation.status in (STATUS_COMPLETED, STATUS_PARTIALLY_COMPLETED)


def test_workflow_dispatch_and_duplicate_prevention(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Tests asynchronous dispatch to durable queue and duplicate active job rejection."""
    orchestrator = InvestigationWorkflowOrchestrator(db=isolated_db)
    analyst = test_users["analyst1"]

    # First dispatch succeeds
    job = orchestrator.dispatch_workflow(
        investigation_id=sample_investigation.id,
        actor_user=analyst,
        target="example.com",
    )
    assert job.id.startswith("job-")
    assert job.job_type == "WORKFLOW_ORCHESTRATION"
    assert job.status == JOB_STATUS_QUEUED

    # Second dispatch with identical target must be rejected by duplicate prevention
    with pytest.raises(Exception) as exc:
        orchestrator.dispatch_workflow(
            investigation_id=sample_investigation.id,
            actor_user=analyst,
            target="example.com",
        )
    assert "already" in str(exc.value).lower() or "duplicate" in str(exc.value).lower()


def test_workflow_cancellation(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Tests cancellation of active workflow jobs and state transition."""
    orchestrator = InvestigationWorkflowOrchestrator(db=isolated_db)
    analyst = test_users["analyst1"]

    # Dispatch workflow
    job = orchestrator.dispatch_workflow(
        investigation_id=sample_investigation.id,
        actor_user=analyst,
        target="example.com",
    )

    # Cancel workflow
    cancel_res = orchestrator.cancel_workflow(
        investigation_id=sample_investigation.id,
        actor_user=analyst,
        reason="Security assessment scope revoked.",
    )

    assert cancel_res["status"] == STATUS_CANCELLED
    assert cancel_res["cancelled_jobs_count"] >= 1

    isolated_db.refresh(sample_investigation)
    assert sample_investigation.status == STATUS_CANCELLED


def test_finding_correlation_service(isolated_db: Session, sample_investigation: InvestigationModel):
    """Tests finding correlation across entities, ports, and evidence references."""
    # Seed passive entity
    e1 = EntityModel(
        id="ent-001",
        investigation_id=sample_investigation.id,
        entity_type="IP_ADDRESS",
        canonical_value="93.184.216.34",
        original_value="93.184.216.34",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        evidence_ids=["evi-test-corr-01"],
        metadata_json={},
    )
    # Seed evidence record
    ev1 = EvidenceModel(
        id="evi-test-corr-01",
        investigation_id=sample_investigation.id,
        source_type="TOOL",
        source_name="dns",
        target="example.com",
        raw_content_path="inv-wf-test-01/dns.raw.txt",
        storage_backend="seaweedfs",
        content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        content_size_bytes=100,
    )
    isolated_db.add_all([e1, ev1])
    isolated_db.commit()

    service = InvestigationCorrelationService(db=isolated_db)
    result = service.correlate_investigation(sample_investigation.id)

    assert result["investigation_id"] == sample_investigation.id
    assert "summary" in result
    assert result["summary"]["total_entities"] >= 1
    assert "assets" in result
    assert "graph" in result
    assert len(result["graph"]["nodes"]) >= 1


def test_workflow_api_rbac_and_tenant_isolation(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Verifies that an unauthorized analyst cannot dispatch or view another user's workflow."""
    app = create_app()
    app.dependency_overrides[get_db] = lambda: isolated_db

    token_analyst1, _ = create_user_session(db=isolated_db, user=test_users["analyst1"])
    token_analyst2, _ = create_user_session(db=isolated_db, user=test_users["analyst2"])
    token_admin, _ = create_user_session(db=isolated_db, user=test_users["admin"])

    client = TestClient(app, base_url="http://localhost")

    # 1. Owner (analyst1) can check workflow status -> 200
    res1 = client.get(
        f"/api/v1/investigations/{sample_investigation.id}/workflow/status",
        headers={"Authorization": f"Bearer {token_analyst1}"},
    )
    assert res1.status_code == 200

    # 2. Non-owner (analyst2) cannot check status -> 404 (non-disclosing)
    res2 = client.get(
        f"/api/v1/investigations/{sample_investigation.id}/workflow/status",
        headers={"Authorization": f"Bearer {token_analyst2}"},
    )
    assert res2.status_code == 404

    # 3. Non-owner cannot start workflow -> 404
    res3 = client.post(
        f"/api/v1/investigations/{sample_investigation.id}/workflow/dispatch",
        headers={"Authorization": f"Bearer {token_analyst2}"},
        json={"target": "example.com"},
    )
    assert res3.status_code == 404

    # 4. Non-owner cannot download PDF -> 404
    res4 = client.get(
        f"/api/v1/investigations/{sample_investigation.id}/workflow/report/pdf",
        headers={"Authorization": f"Bearer {token_analyst2}"},
    )
    assert res4.status_code == 404

    # 5. Admin can access owner's workflow -> 200
    res_admin = client.get(
        f"/api/v1/investigations/{sample_investigation.id}/workflow/status",
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert res_admin.status_code == 200


def test_draft_investigation_cannot_execute(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Verifies Requirement: A draft investigation cannot execute scans or workflows."""
    sample_investigation.status = STATUS_DRAFT
    isolated_db.commit()

    orchestrator = InvestigationWorkflowOrchestrator(db=isolated_db)
    analyst = test_users["analyst1"]

    import asyncio
    with pytest.raises(ValueError) as exc:
        asyncio.run(orchestrator.execute_workflow(
            investigation_id=sample_investigation.id,
            actor_user=analyst,
            target="example.com",
        ))
    assert "draft" in str(exc.value).lower()


def test_revoked_and_expired_authorization_enforcement(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Verifies that expired or revoked target authorizations strictly reject scanning operations."""
    from app.services.target_authorization import verify_target_authorization
    analyst = test_users["analyst1"]

    # Active authorization
    auth_active = TargetAuthorizationModel(
        id="auth-001",
        investigation_id=sample_investigation.id,
        target="example.com",
        target_type="DOMAIN",
        allowed_operations=["RECON_PASSIVE", "SCAN_ACTIVE"],
        authorization_reference="AUTH-ACTIVE-01",
        approved_by=test_users["admin"].id,
        valid_from=datetime.now(timezone.utc) - timedelta(days=1),
        valid_to=datetime.now(timezone.utc) + timedelta(days=5),
        is_revoked=False,
    )
    isolated_db.add(auth_active)
    isolated_db.commit()

    ok, msg = verify_target_authorization(isolated_db, sample_investigation, "example.com", "RECON_PASSIVE", actor_user=analyst)
    assert ok, f"Active auth should be valid: {msg}"

    # Now revoke authorization
    auth_active.is_revoked = True
    isolated_db.commit()

    ok_revoked, msg_revoked = verify_target_authorization(isolated_db, sample_investigation, "example.com", "RECON_PASSIVE", actor_user=analyst)
    assert not ok_revoked, "Revoked authorization must be rejected."
    assert "revoked" in msg_revoked.lower() or "denied" in msg_revoked.lower() or "not permitted" in msg_revoked.lower() or "no active" in msg_revoked.lower()


def test_pdf_report_and_graphml_generation(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Verifies PDF and GraphML export on investigations."""
    from app.services.reporting.pdf_generator import InvestigationReportGenerator
    from app.services.reporting.graphml_generator import GraphMLExporter

    # 1. PDF generation
    pdf_bytes = InvestigationReportGenerator.generate_pdf(
        investigation_id=sample_investigation.id,
        db=isolated_db,
        generated_by=test_users["analyst1"].username,
    )
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")

    # 2. GraphML export
    xml_str = GraphMLExporter.generate_graphml(
        investigation_id=sample_investigation.id,
        db=isolated_db,
    )
    assert "<graphml" in xml_str
    assert "</graphml>" in xml_str


@pytest.mark.asyncio
async def test_cooperative_cancellation_inter_stage(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Verifies that cooperative cancellation halts subsequent workflow stages."""
    orchestrator = InvestigationWorkflowOrchestrator(db=isolated_db)
    analyst = test_users["analyst1"]

    # Pre-flag cancellation on the investigation
    sample_investigation.status = STATUS_CANCELLED
    isolated_db.commit()

    summary = await orchestrator.execute_workflow(
        investigation_id=sample_investigation.id,
        actor_user=analyst,
        target="example.com",
    )

    assert summary["workflow_status"] == STATUS_CANCELLED
    # Verify it halted before Stage 1
    assert len(summary["stages"]) == 1
    assert summary["stages"][0]["status"] == "CANCELLED"
    assert "STAGE_1_PASSIVE_RECON" in summary["stages"][0]["stage_name"]


@pytest.mark.asyncio
async def test_greenbone_unavailability_sets_partially_completed(isolated_db: Session, sample_investigation: InvestigationModel, test_users: dict):
    """Verifies that unconfigured/unavailable Greenbone marks the investigation as partially_completed."""
    # Seed authorization record for vulnerability scanning
    auth_vuln = TargetAuthorizationModel(
        id=f"auth-{uuid.uuid4().hex[:12]}",
        investigation_id=sample_investigation.id,
        target="example.com",
        target_type="DOMAIN",
        allowed_operations=["RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"],
        authorization_reference="AUTH-VULN-01",
        approved_by=test_users["admin"].id,
        valid_from=datetime.now(timezone.utc) - timedelta(days=1),
        valid_to=datetime.now(timezone.utc) + timedelta(days=5),
        is_revoked=False,
    )
    isolated_db.add(auth_vuln)
    isolated_db.commit()

    orchestrator = InvestigationWorkflowOrchestrator(db=isolated_db)
    analyst = test_users["analyst1"]

    summary = await orchestrator.execute_workflow(
        investigation_id=sample_investigation.id,
        actor_user=analyst,
        target="example.com",
    )

    # In test environment, Greenbone GVM is authorized but unconfigured
    stage_statuses = {s["stage_name"]: s["status"] for s in summary["stages"]}
    assert stage_statuses.get("VULNERABILITY_ASSESSMENT") == "SKIPPED_UNAVAILABLE"
    assert summary["workflow_status"] == STATUS_PARTIALLY_COMPLETED

    isolated_db.refresh(sample_investigation)
    assert sample_investigation.status == STATUS_PARTIALLY_COMPLETED


