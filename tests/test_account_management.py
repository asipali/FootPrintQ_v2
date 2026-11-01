"""Tests for approval-gated investigator accounts and password lifecycle."""

import pytest
from sqlalchemy import select

from app.config import Settings
from app.core.auth import (
    change_user_password,
    create_pending_investigator,
    create_user_session,
    provision_demo_accounts,
)
from app.core.security import (
    ROLE_ADMINISTRATOR,
    ROLE_INVESTIGATOR,
    hash_password,
    verify_password,
)
from app.models.audit import AuditLogModel
from app.models.user import UserModel, UserSessionModel


def test_registration_cannot_choose_role_or_status(client):
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "username": "cannot_escalate",
            "email": "cannot-escalate@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
            "role": "administrator",
            "account_status": "active",
        },
    )
    assert response.status_code == 422


def test_pending_investigator_cannot_login(client, db_session):
    user = create_pending_investigator(
        db_session,
        "pending@example.com",
        "PendingPassword123!",
        "Pending User",
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": user.email, "password": "PendingPassword123!"},
    )
    assert response.status_code == 403
    assert "pending administrator approval" in response.json()["error"]["message"]


def test_admin_approval_dashboard_renders(admin_client):
    response = admin_client.get("/admin/investigators")
    assert response.status_code == 200
    assert "Investigator Approval Management" in response.text
    assert "no investigator registrations awaiting approval" in response.text.lower()


def test_admin_can_approve_pending_investigator(client, db_session, admin_token, admin_user):
    user = create_pending_investigator(
        db_session,
        "approve@example.com",
        "ApprovePassword123!",
        "Approve User",
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    pending = client.get("/api/v1/users/pending-investigators", headers=headers)
    assert pending.status_code == 200
    assert [item["id"] for item in pending.json()] == [user.id]

    approved = client.post(f"/api/v1/users/{user.id}/approve", headers=headers)
    assert approved.status_code == 200
    assert approved.json()["account_status"] == "active"
    assert approved.json()["approved_by_id"] == admin_user.id
    assert user.is_active is True
    approval_event = db_session.scalar(
        select(AuditLogModel).where(
            AuditLogModel.event_type == "INVESTIGATOR_APPROVED",
            AuditLogModel.target_user_id == user.id,
        )
    )
    assert approval_event is not None

    login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": user.email, "password": "ApprovePassword123!"},
    )
    assert login.status_code == 200

    repeated = client.post(f"/api/v1/users/{user.id}/approve", headers=headers)
    assert repeated.status_code == 409


def test_investigator_cannot_access_approval_or_admin_endpoints(client, db_session):
    investigator = create_pending_investigator(
        db_session,
        "investigator@example.com",
        "InvestigatorPassword123!",
        "Investigator User",
    )
    investigator.account_status = "active"
    investigator.is_active = True
    db_session.commit()
    token, _ = create_user_session(db_session, investigator)
    headers = {"Authorization": f"Bearer {token}"}

    pending = client.get("/api/v1/users/pending-investigators", headers=headers)
    assert pending.status_code == 403
    approve = client.post(f"/api/v1/users/{investigator.id}/approve", headers=headers)
    assert approve.status_code == 403


def test_admin_can_reject_and_rejected_investigator_cannot_login(client, db_session, admin_token):
    user = create_pending_investigator(
        db_session,
        "reject@example.com",
        "RejectPassword123!",
        "Reject User",
    )
    headers = {"Authorization": f"Bearer {admin_token}"}
    rejected = client.post(f"/api/v1/users/{user.id}/reject", headers=headers)
    assert rejected.status_code == 200
    assert rejected.json()["account_status"] == "rejected"
    assert rejected.json()["rejected_by_id"] is not None

    login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": user.email, "password": "RejectPassword123!"},
    )
    assert login.status_code == 403
    repeated = client.post(f"/api/v1/users/{user.id}/reject", headers=headers)
    assert repeated.status_code == 409


def test_admin_cannot_activate_pending_investigator_via_status_api(
    client, db_session, admin_token
):
    user = create_pending_investigator(
        db_session,
        "status-bypass@example.com",
        "StatusPassword123!",
        "Status Bypass",
    )
    response = client.patch(
        f"/api/v1/users/{user.id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": True},
    )
    assert response.status_code == 409
    db_session.refresh(user)
    assert user.account_status == "pending"
    assert user.is_active is False


def test_password_change_revokes_all_sessions_and_audits_without_secrets(
    client, db_session, admin_user, admin_token
):
    other_token, _ = create_user_session(db_session, admin_user)
    response = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "current_password": "AdminSecure123!#",
            "new_password": "ChangedPassword123!",
            "confirm_password": "ChangedPassword123!",
        },
    )
    assert response.status_code == 200
    assert all(session.is_revoked for session in admin_user.sessions)
    assert client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"}
    ).status_code == 401
    assert client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {other_token}"}
    ).status_code == 401
    assert verify_password("ChangedPassword123!", admin_user.password_hash)
    assert not verify_password("AdminSecure123!#", admin_user.password_hash)
    old_login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": admin_user.email, "password": "AdminSecure123!#"},
    )
    new_login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": admin_user.email, "password": "ChangedPassword123!"},
    )
    assert old_login.status_code == 401
    assert new_login.status_code == 200

    events = db_session.scalars(
        select(AuditLogModel).where(AuditLogModel.event_type == "PASSWORD_CHANGED")
    ).all()
    assert len(events) == 1
    assert "ChangedPassword123!" not in str(events[0].details)


@pytest.mark.parametrize(
    ("current_password", "new_password", "confirm_password", "expected_status"),
    [
        ("wrong-current", "StrongPassword123!", "StrongPassword123!", 400),
        ("AdminSecure123!#", "weak", "weak", 422),
        ("AdminSecure123!#", "StrongPassword123!", "OtherPassword123!", 422),
        ("AdminSecure123!#", "AdminSecure123!#", "AdminSecure123!#", 422),
    ],
)
def test_password_change_rejects_invalid_values(
    client,
    admin_token,
    current_password,
    new_password,
    confirm_password,
    expected_status,
):
    response = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "current_password": current_password,
            "new_password": new_password,
            "confirm_password": confirm_password,
        },
    )
    assert response.status_code == expected_status


def test_demo_provisioning_is_idempotent_and_does_not_reset_password(db_session):
    settings = Settings(
        APP_ENV="test",
        DEBUG=True,
        SECRET_KEY="test-secret-key-for-unit-testing-only-12345",
        DEMO_ACCOUNTS_ENABLED=True,
        DEMO_ADMIN_PASSWORD="DemoAdminPassword123!",
        DEMO_INVESTIGATOR_PASSWORD="DemoInvestigator123!",
    )
    first = provision_demo_accounts(db_session, settings)
    admin = db_session.scalar(select(UserModel).where(UserModel.email == "admin@footprint.org"))
    investigator = db_session.scalar(
        select(UserModel).where(UserModel.email == "investigator@footprint.org")
    )
    admin.password_hash = hash_password("ChangedDemoPassword123!")
    db_session.commit()

    second = provision_demo_accounts(db_session, settings)
    db_session.refresh(admin)
    assert first["created"] == ["admin@footprint.org", "investigator@footprint.org"]
    assert second["created"] == []
    assert len(second["existing"]) == 2
    assert verify_password("ChangedDemoPassword123!", admin.password_hash)
    assert admin.role == ROLE_ADMINISTRATOR
    assert investigator.role == ROLE_INVESTIGATOR
    assert verify_password("DemoInvestigator123!", investigator.password_hash)
    assert admin.password_hash.startswith("$argon2id$")


def test_investigator_can_change_own_password(client, db_session):
    investigator = create_pending_investigator(
        db_session,
        "password-owner@example.com",
        "InvestigatorPassword123!",
        "Password Owner",
    )
    investigator.account_status = "active"
    investigator.is_active = True
    db_session.commit()
    token, _ = create_user_session(db_session, investigator)
    response = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "InvestigatorPassword123!",
            "new_password": "InvestigatorChanged123!",
            "confirm_password": "InvestigatorChanged123!",
        },
    )
    assert response.status_code == 200
    assert all(session.is_revoked for session in investigator.sessions)


def test_settings_password_form_revokes_browser_session(admin_client, admin_user):
    csrf_token = "test-csrf-token"
    admin_client.cookies.set("footprintiq_csrf", csrf_token)
    page = admin_client.get("/settings")
    assert page.status_code == 200
    assert "Account Security" in page.text

    response = admin_client.post(
        "/settings/password",
        data={
            "csrf_token": csrf_token,
            "current_password": "AdminSecure123!#",
            "new_password": "AdminChanged123!#",
            "confirm_password": "AdminChanged123!#",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?password_changed=1"
    assert all(session.is_revoked for session in admin_user.sessions)


def test_demo_provisioning_can_be_disabled(db_session):
    settings = Settings(
        APP_ENV="test",
        DEBUG=True,
        SECRET_KEY="test-secret-key-for-unit-testing-only-12345",
        DEMO_ACCOUNTS_ENABLED=False,
    )
    assert provision_demo_accounts(db_session, settings) == {
        "created": [],
        "existing": [],
        "enabled": False,
    }
    assert db_session.scalar(select(UserModel)) is None


def test_production_settings_reject_demo_provisioning():
    with pytest.raises(ValueError, match="cannot be enabled in production"):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="production-secret-key-that-is-at-least-32-chars",
            DEMO_ACCOUNTS_ENABLED=True,
            DEMO_ADMIN_PASSWORD="DemoAdminPassword123!",
            DEMO_INVESTIGATOR_PASSWORD="DemoInvestigator123!",
        )
