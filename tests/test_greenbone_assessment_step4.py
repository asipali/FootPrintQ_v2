"""Step 4 Automated Unit & Integration Tests: Greenbone Vulnerability Assessment Workflow."""

import asyncio
from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_context
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel, EntityModel
from app.models.user import UserModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.services.vuln.profiles import list_vuln_profiles, validate_vuln_profile
from app.services.vuln.orchestrator import (
    VulnerabilityAssessmentOrchestrator,
    VulnerabilityAssessmentError,
)
from app.services.vuln.xml_parser import (
    parse_greenbone_xml_report,
    MalformedReportError,
    ReportSecurityError,
    ReportNotCompletedError,
)
from app.integrations.greenbone_client import GreenboneClient, GreenboneOperationError
from app.integrations.greenbone_adapter import GreenboneAdapter
from app.services.evidence_store import get_evidence_store


@pytest.fixture
def lab_setup():
    """Sets up an isolated test investigation, target authorizations, and users."""
    suffix = uuid.uuid4().hex[:8]
    inv_id = f"inv-step4-lab-{suffix}"
    target_ip = "192.168.56.107"
    now = datetime.now(timezone.utc)

    with get_db_context() as db:
        admin = UserModel(
            id=f"usr-adm-{suffix}",
            username=f"admin_{suffix}",
            email=f"admin_{suffix}@example.com",
            password_hash="mockhash",
            role="administrator",
            is_active=True,
        )
        db.add(admin)

        analyst = UserModel(
            id=f"usr-ana-{suffix}",
            username=f"analyst_{suffix}",
            email=f"analyst_{suffix}@example.com",
            password_hash="mockhash",
            role="analyst",
            is_active=True,
        )
        db.add(analyst)

        inv = InvestigationModel(
            id=inv_id,
            name="Step 4 Vulnerability Test Lab",
            description="Integration test suite for GVM vulnerability assessment",
            organization_name="Security Testing Lab",
            lead_investigator="Lead Investigator",
            status="active",
            owned_domains=["lab.local"],
            approved_ips=[target_ip, "192.168.56.108", "192.168.56.109"],
            active_targets=[target_ip, "192.168.56.108", "192.168.56.109"],
            active_scanning_enabled=True,
            created_at=now,
        )
        db.add(inv)

        # Valid authorization for target_ip (192.168.56.107) with SCAN_VULN
        authz_valid = TargetAuthorizationModel(
            id=f"authz-valid-{suffix}",
            investigation_id=inv_id,
            target=target_ip,
            target_type="IP",
            allowed_operations=["SCAN_VULN"],
            authorization_reference=f"REF-{suffix}",
            approved_by=admin.id,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=2),
            is_revoked=False,
        )
        db.add(authz_valid)

        # Authorization missing SCAN_VULN (SCAN_ACTIVE only) for 192.168.56.108
        authz_no_vuln = TargetAuthorizationModel(
            id=f"authz-novuln-{suffix}",
            investigation_id=inv_id,
            target="192.168.56.108",
            target_type="IP",
            allowed_operations=["SCAN_ACTIVE"],
            authorization_reference=f"REF-NOVULN-{suffix}",
            approved_by=admin.id,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=2),
            is_revoked=False,
        )
        db.add(authz_no_vuln)

        # Revoked authorization for 192.168.56.109
        authz_revoked = TargetAuthorizationModel(
            id=f"authz-rev-{suffix}",
            investigation_id=inv_id,
            target="192.168.56.109",
            target_type="IP",
            allowed_operations=["SCAN_VULN"],
            authorization_reference=f"REF-REV-{suffix}",
            approved_by=admin.id,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=2),
            is_revoked=True,
        )
        db.add(authz_revoked)

        db.commit()

        return {
            "inv_id": inv_id,
            "target_ip": target_ip,
            "admin_id": admin.id,
            "analyst_id": analyst.id,
            "suffix": suffix,
        }


def test_vulnerability_profile_validation():
    """Verifies that approved profiles and aliases validate correctly and unknown profiles fail."""
    profiles = list_vuln_profiles()
    assert len(profiles) >= 4
    profile_ids = [p.id for p in profiles]
    assert "openvas-basic" in profile_ids
    assert "openvas-discovery" in profile_ids
    assert "openvas-host-discovery" in profile_ids
    assert "openvas-full-and-fast" in profile_ids

    # Test alias resolution
    p1 = validate_vuln_profile("basic")
    assert p1.id == "openvas-basic"
    p2 = validate_vuln_profile("discovery")
    assert p2.id == "openvas-discovery"
    p3 = validate_vuln_profile("full_and_fast")
    assert p3.id == "openvas-full-and-fast"

    with pytest.raises(ValueError, match="Unknown vulnerability scan profile"):
        validate_vuln_profile("nonexistent-profile-xyz")


def test_authorization_scope_rejection(lab_setup):
    """Verifies that out-of-scope, missing-op, and revoked targets are strictly rejected."""
    orchestrator = VulnerabilityAssessmentOrchestrator()

    with get_db_context() as db:
        inv = db.get(InvestigationModel, lab_setup["inv_id"])
        admin = db.get(UserModel, lab_setup["admin_id"])

        # 1. Target not in investigation scope
        with pytest.raises(VulnerabilityAssessmentError, match="Target authorization rejected"):
            orchestrator.create_assessment_job(
                db=db,
                investigation=inv,
                target="10.200.200.200",
                profile_id="openvas-discovery",
                actor_user=admin,
            )

        # 2. Target lacks SCAN_VULN operation
        with pytest.raises(VulnerabilityAssessmentError, match="Target authorization rejected"):
            orchestrator.create_assessment_job(
                db=db,
                investigation=inv,
                target="192.168.56.108",
                profile_id="openvas-discovery",
                actor_user=admin,
            )

        # 3. Target authorization is revoked
        with pytest.raises(VulnerabilityAssessmentError, match="Target authorization rejected"):
            orchestrator.create_assessment_job(
                db=db,
                investigation=inv,
                target="192.168.56.109",
                profile_id="openvas-discovery",
                actor_user=admin,
            )


@pytest.mark.asyncio
async def test_full_assessment_orchestration_with_findings(lab_setup):
    """Tests the full assessment lifecycle with a multi-finding fixture report."""
    fixture_path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "scans"
        / "greenbone"
        / "inv-test-vuln-01"
        / "gvm-imp-31efbea759.xml"
    )
    assert fixture_path.exists(), "Sample GVM report fixture must exist"
    report_xml = fixture_path.read_text(encoding="utf-8")

    mock_adapter = MagicMock()
    mock_adapter.check_availability.return_value = {
        "status": "READY",
        "configured": True,
        "endpoint": "127.0.0.1:9390",
        "version": "22.7",
        "authenticated": True,
        "error": None,
    }
    mock_adapter.create_scan_target.return_value = "gvm-tgt-test-1111"
    mock_adapter.create_scan_task.return_value = "gvm-tsk-test-2222"
    mock_adapter.start_scan_task.return_value = "gvm-rep-test-3333"
    mock_adapter.poll_scan_status.return_value = {
        "status": "Done",
        "progress": 100,
        "report_id": "gvm-rep-test-3333",
    }
    mock_adapter.retrieve_report.return_value = report_xml

    orchestrator = VulnerabilityAssessmentOrchestrator(adapter=mock_adapter)

    with get_db_context() as db:
        inv = db.get(InvestigationModel, lab_setup["inv_id"])
        admin = db.get(UserModel, lab_setup["admin_id"])
        target_ip = lab_setup["target_ip"]

        job = orchestrator.create_assessment_job(
            db=db,
            investigation=inv,
            target=target_ip,
            profile_id="openvas-basic",
            actor_user=admin,
        )
        job_id = job.id
        assert job.status == "QUEUED"

    # Execute workflow
    await orchestrator.execute_assessment_job(
        job_id=job_id,
        investigation_id=lab_setup["inv_id"],
        target=target_ip,
        profile_id="openvas-basic",
        requested_by=lab_setup["admin_id"],
    )

    # Verify database persistence
    with get_db_context() as db:
        completed_job = db.get(VulnerabilityScanJobModel, job_id)
        assert completed_job is not None
        assert completed_job.status == "COMPLETED"
        assert completed_job.progress == 100
        assert completed_job.evidence_id is not None
        assert completed_job.duration_seconds is not None
        assert completed_job.gvm_target_id == "gvm-tgt-test-1111"
        assert completed_job.gvm_task_id == "gvm-tsk-test-2222"
        assert completed_job.gvm_report_id == "gvm-rep-test-3333"

        # Check evidence record
        evidence = db.get(EvidenceModel, completed_job.evidence_id)
        assert evidence is not None
        assert evidence.source_type == "greenbone_openvas"
        assert evidence.collection_status == "SUCCESS"
        assert evidence.content_size_bytes == len(report_xml.encode("utf-8"))
        expected_hash = hashlib.sha256(report_xml.encode("utf-8")).hexdigest()
        assert evidence.content_hash == expected_hash

        # Verify findings persisted
        findings = db.query(VulnerabilityFindingModel).filter(
            VulnerabilityFindingModel.job_id == job_id
        ).all()
        assert len(findings) == 4

        severities = {f.severity.lower() for f in findings}
        assert "critical" in severities or "high" in severities

        # Check CVEs and solutions
        cve_findings = [f for f in findings if f.cve_references]
        assert len(cve_findings) > 0
        for cf in cve_findings:
            assert cf.cvss_score is not None
            assert cf.solution is not None

        # Verify correlated entities
        entities = db.query(EntityModel).filter(
            EntityModel.investigation_id == lab_setup["inv_id"],
            EntityModel.entity_type == "vulnerability",
        ).all()
        assert len(entities) == 4


@pytest.mark.asyncio
async def test_assessment_truthful_zero_findings(lab_setup):
    """Verifies that an assessment returning 0 findings completes truthfully without fabrication."""
    zero_xml = """<get_reports_response status="200" status_text="OK">
  <report id="rep-zero-findings" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5">
    <scan_run_status>Done</scan_run_status>
    <results></results>
  </report>
</get_reports_response>"""

    mock_adapter = MagicMock()
    mock_adapter.check_availability.return_value = {
        "status": "HEALTHY",
        "configured": True,
        "endpoint": "127.0.0.1:9390",
        "version": "22.7",
        "authenticated": True,
        "error": None,
    }
    mock_adapter.create_scan_target.return_value = "gvm-tgt-zero"
    mock_adapter.create_scan_task.return_value = "gvm-tsk-zero"
    mock_adapter.start_scan_task.return_value = "rep-zero-findings"
    mock_adapter.poll_scan_status.return_value = {
        "status": "Done",
        "progress": 100,
        "report_id": "rep-zero-findings",
    }
    mock_adapter.retrieve_report.return_value = zero_xml

    orchestrator = VulnerabilityAssessmentOrchestrator(adapter=mock_adapter)

    with get_db_context() as db:
        inv = db.get(InvestigationModel, lab_setup["inv_id"])
        admin = db.get(UserModel, lab_setup["admin_id"])
        target_ip = lab_setup["target_ip"]

        job = orchestrator.create_assessment_job(
            db=db,
            investigation=inv,
            target=target_ip,
            profile_id="openvas-discovery",
            actor_user=admin,
        )
        job_id = job.id

    await orchestrator.execute_assessment_job(
        job_id=job_id,
        investigation_id=lab_setup["inv_id"],
        target=target_ip,
        profile_id="openvas-discovery",
        requested_by=lab_setup["admin_id"],
    )

    with get_db_context() as db:
        job = db.get(VulnerabilityScanJobModel, job_id)
        assert job.status == "COMPLETED"
        assert job.progress == 100
        assert job.evidence_id is not None

        findings = db.query(VulnerabilityFindingModel).filter(
            VulnerabilityFindingModel.job_id == job_id
        ).all()
        # Strictly zero findings - zero fabrication
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_assessment_cancellation_workflow(lab_setup):
    """Verifies that an in-progress scan can be cancelled cleanly."""
    mock_adapter = MagicMock()
    mock_adapter.check_availability.return_value = {"status": "HEALTHY", "configured": True}
    mock_adapter.create_scan_target.return_value = "gvm-tgt-cancel"
    mock_adapter.create_scan_task.return_value = "gvm-tsk-cancel"
    mock_adapter.start_scan_task.return_value = "gvm-rep-cancel"
    mock_adapter.stop_scan_task.return_value = True

    orchestrator = VulnerabilityAssessmentOrchestrator(adapter=mock_adapter)

    with get_db_context() as db:
        inv = db.get(InvestigationModel, lab_setup["inv_id"])
        admin = db.get(UserModel, lab_setup["admin_id"])
        target_ip = lab_setup["target_ip"]

        job = orchestrator.create_assessment_job(
            db=db,
            investigation=inv,
            target=target_ip,
            profile_id="openvas-basic",
            actor_user=admin,
        )
        job_id = job.id

        # Signal cancellation
        orchestrator.cancel_job(
            db=db,
            job_id=job_id,
            actor_user=admin,
            reason="Investigator abort request",
        )

    # When execution starts, cancellation is recognized immediately
    await orchestrator.execute_assessment_job(
        job_id=job_id,
        investigation_id=lab_setup["inv_id"],
        target=target_ip,
        profile_id="openvas-basic",
        requested_by=lab_setup["admin_id"],
    )

    with get_db_context() as db:
        job = db.get(VulnerabilityScanJobModel, job_id)
        assert job.status == "CANCELLED"
        assert job.cancellation_reason == "Investigator abort request"


def test_xml_security_defenses():
    """Verifies that DOCTYPE and ENTITY declarations (XXE / Billion Laughs) are rejected."""
    xxe_xml = """<?xml version="1.0"?>
    <!DOCTYPE report [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <report><results>&xxe;</results></report>"""

    with pytest.raises(ReportSecurityError, match="rejected for security"):
        parse_greenbone_xml_report(xxe_xml)

    malformed_xml = "<report><unclosed>"
    with pytest.raises(MalformedReportError):
        parse_greenbone_xml_report(malformed_xml)

    running_xml = """<report>
      <scan_run_status>Running</scan_run_status>
      <results></results>
    </report>"""
    with pytest.raises(ReportNotCompletedError):
        parse_greenbone_xml_report(running_xml)
