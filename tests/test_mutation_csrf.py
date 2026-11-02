"""CSRF coverage for REST mutation routes that also accept session cookies."""

import uuid
from pathlib import Path

from sqlalchemy import select

from app.models.investigation import InvestigationModel
from app.models.scan import ActiveScanJobModel
from app.models.user import UserModel
from app.models.vulnerability import VulnerabilityScanJobModel
from app.core.security import generate_csrf_token


def test_admin_user_mutations_reject_missing_and_invalid_csrf_without_changes(
    admin_client, db_session, viewer_user
):
    before_count = len(db_session.scalars(select(UserModel)).all())
    admin_client.cookies.set("footprintiq_csrf", "expected-token")

    create_response = admin_client.post(
        "/api/v1/users",
        json={
            "username": "csrf_new_user",
            "email": "csrf-new@lab.example",
            "password": "SecureTestPass123!",
            "role": "viewer",
        },
    )
    role_response = admin_client.patch(
        f"/api/v1/users/{viewer_user.id}/role", json={"role": "analyst"}
    )
    status_response = admin_client.patch(
        f"/api/v1/users/{viewer_user.id}/status", json={"is_active": False}
    )

    assert all(r.status_code == 403 for r in (create_response, role_response, status_response))
    db_session.expire_all()
    assert len(db_session.scalars(select(UserModel)).all()) == before_count
    assert db_session.get(UserModel, viewer_user.id).role == "viewer"
    assert db_session.get(UserModel, viewer_user.id).is_active is True


def test_admin_user_mutation_accepts_valid_cookie_csrf(admin_client, db_session):
    csrf = generate_csrf_token()
    admin_client.cookies.set("footprintiq_csrf", csrf)

    response = admin_client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "csrf_valid_user",
            "email": "csrf-valid@lab.example",
            "password": "SecureTestPass123!",
            "role": "viewer",
        },
    )

    assert response.status_code == 201
    assert db_session.scalar(
        select(UserModel).where(UserModel.username == "csrf_valid_user")
    ) is not None


def test_untrusted_bearer_header_does_not_bypass_cookie_csrf(
    admin_client, db_session
):
    before_count = len(db_session.scalars(select(UserModel)).all())
    response = admin_client.post(
        "/api/v1/users",
        headers={"Authorization": "Bearer attacker-controlled-not-a-session"},
        json={
            "username": "csrf_forged_bearer",
            "email": "csrf-forged@lab.example",
            "password": "SecureTestPass123!",
            "role": "viewer",
        },
    )

    assert response.status_code in (401, 403)
    assert len(db_session.scalars(select(UserModel)).all()) == before_count


def test_unauthenticated_admin_mutation_is_rejected_without_creating_user(
    client, db_session
):
    before_count = len(db_session.scalars(select(UserModel)).all())
    response = client.post(
        "/api/v1/users",
        json={
            "username": "csrf_unauth_user",
            "email": "csrf-unauth@lab.example",
            "password": "SecureTestPass123!",
            "role": "viewer",
        },
    )

    assert response.status_code == 401
    assert len(db_session.scalars(select(UserModel)).all()) == before_count


def test_non_admin_cannot_mutate_administrative_user_routes(
    authenticated_client, analyst_user, viewer_user, db_session
):
    csrf = generate_csrf_token()
    authenticated_client.cookies.set("footprintiq_csrf", csrf)
    response = authenticated_client.patch(
        f"/api/v1/users/{viewer_user.id}/role",
        headers={"X-CSRF-Token": csrf},
        json={"role": "administrator"},
    )

    assert response.status_code == 403
    db_session.refresh(viewer_user)
    assert viewer_user.role == "viewer"


def _authorized_investigation(db_session, owner_id: str) -> InvestigationModel:
    investigation = InvestigationModel(
        id=f"inv-csrf-{uuid.uuid4().hex[:10]}",
        name="CSRF scanner test",
        organization_name="Lab",
        description="Temporary fixture for route security regression tests",
        lead_investigator="Admin",
        owner_user_id=owner_id,
        status="active",
        approved_ips=["127.0.0.1"],
        active_targets=["127.0.0.1"],
        active_scanning_enabled=True,
    )
    db_session.add(investigation)
    db_session.commit()
    return investigation


def test_cookie_csrf_blocks_nmap_and_greenbone_dispatch_before_job_creation(
    admin_client, admin_user, db_session, isolated_evidence_storage
):
    investigation = _authorized_investigation(db_session, admin_user.id)
    nmap_response = admin_client.post(
        f"/api/v1/investigations/{investigation.id}/nmap-scans",
        json={"target": "127.0.0.1", "profile_id": "basic_tcp"},
    )
    gvm_response = admin_client.post(
        f"/api/v1/investigations/{investigation.id}/vulnerability-assessments",
        json={"target": "127.0.0.1", "profile_id": "openvas-basic"},
    )

    assert nmap_response.status_code == 403
    assert gvm_response.status_code == 403
    assert db_session.scalars(
        select(ActiveScanJobModel).where(
            ActiveScanJobModel.investigation_id == investigation.id
        )
    ).all() == []
    assert not any(Path(isolated_evidence_storage).rglob("*.raw.*"))
    assert db_session.scalars(
        select(VulnerabilityScanJobModel).where(
            VulnerabilityScanJobModel.investigation_id == investigation.id
        )
    ).all() == []


def test_cookie_csrf_blocks_nmap_and_greenbone_cancellation_without_job_changes(
    admin_client, admin_user, db_session
):
    investigation = _authorized_investigation(db_session, admin_user.id)
    nmap_job = ActiveScanJobModel(
        id=f"scan-csrf-{uuid.uuid4().hex[:8]}",
        investigation_id=investigation.id,
        requested_by=admin_user.id,
        target="127.0.0.1",
        resolved_ips=["127.0.0.1"],
        scan_profile="basic_tcp",
        status="RUNNING",
    )
    gvm_job = VulnerabilityScanJobModel(
        id=f"vjob-csrf-{uuid.uuid4().hex[:8]}",
        investigation_id=investigation.id,
        requested_by=admin_user.id,
        target="127.0.0.1",
        profile_id="openvas-basic",
        scan_config_id="fixture-config",
        status="RUNNING",
        progress=20,
    )
    db_session.add_all([nmap_job, gvm_job])
    db_session.commit()

    nmap_response = admin_client.post(
        f"/api/v1/nmap-scans/{nmap_job.id}/cancel", json={"reason": "test"}
    )
    gvm_response = admin_client.post(
        f"/api/v1/vulnerability-assessments/{gvm_job.id}/cancel",
        json={"reason": "test"},
    )

    assert nmap_response.status_code == 403
    assert gvm_response.status_code == 403
    db_session.refresh(nmap_job)
    db_session.refresh(gvm_job)
    assert nmap_job.status == "RUNNING"
    assert gvm_job.status == "RUNNING"


def test_cookie_csrf_blocks_passive_recon_and_target_validation(
    admin_client, isolated_evidence_storage
):
    recon_response = admin_client.post(
        "/api/v1/investigations/nonexistent/passive-recon",
        json={"target": "example.invalid", "collectors": []},
    )
    validation_response = admin_client.post(
        "/api/v1/investigations/nonexistent/validate-target",
        json={"target": "example.invalid", "operation": "RECON_PASSIVE"},
    )

    assert recon_response.status_code == 403
    assert validation_response.status_code == 403
    assert not any(Path(isolated_evidence_storage).rglob("*.raw.*"))
