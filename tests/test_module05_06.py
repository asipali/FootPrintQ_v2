"""Focused regression coverage for investigation ownership and authorization integrity."""

from datetime import datetime, timedelta, timezone

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel
from app.services.target_authorization import verify_target_authorization


def _investigation(db_session, owner_id, inv_id="inv-m05m06"):
    record = InvestigationModel(
        id=inv_id,
        name="Module 05 and 06 lab",
        organization_name="FootprintIQ Test Lab",
        description="Isolated application test scope",
        lead_investigator="Test lead",
        owner_user_id=owner_id,
        owned_domains=["lab.example"],
        approved_ips=["127.0.0.1"],
        approved_cidrs=["127.0.0.0/8"],
        active_targets=["lab.example", "127.0.0.1"],
    )
    db_session.add(record)
    db_session.commit()
    return record


def _authorization(db_session, investigation, **overrides):
    now = datetime.now(timezone.utc)
    values = {
        "id": "auth-m05m06",
        "investigation_id": investigation.id,
        "target": "lab.example",
        "target_type": "DOMAIN",
        "allowed_operations": ["RECON_PASSIVE"],
        "authorization_reference": "TEST-APPROVAL-01",
        "approved_by": "test_admin",
        "valid_from": now - timedelta(minutes=1),
        "valid_to": now + timedelta(days=1),
        "is_revoked": False,
    }
    values.update(overrides)
    auth = TargetAuthorizationModel(**values)
    db_session.add(auth)
    db_session.commit()
    return auth


def test_investigation_create_owner_list_update_and_archive(client, analyst_headers, analyst_user, viewer_headers):
    payload = {
        "name": "  Owned campaign  ",
        "organization_name": "Example Org",
        "description": "Authorized test campaign",
        "lead_investigator": "spoofed lead",
        "scope": {"owned_domains": ["LAB.EXAMPLE."]},
    }
    response = client.post("/api/v1/investigations", json=payload, headers=analyst_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["owner_user_id"] == analyst_user.id
    assert data["lead_investigator"] == analyst_user.username
    assert data["name"] == "Owned campaign"
    assert data["status"] == "active"

    assert any(row["id"] == data["id"] for row in client.get("/api/v1/investigations", headers=analyst_headers).json())
    assert all(row["id"] != data["id"] for row in client.get("/api/v1/investigations", headers=viewer_headers).json())
    assert client.get(f"/api/v1/investigations/{data['id']}", headers=viewer_headers).status_code == 404
    assert client.patch(f"/api/v1/investigations/{data['id']}", json={"name": "stolen"}, headers=viewer_headers).status_code == 403

    updated = client.patch(
        f"/api/v1/investigations/{data['id']}",
        json={"name": "Updated name"},
        headers=analyst_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Updated name"
    assert updated.json()["owner_user_id"] == analyst_user.id

    completed = client.patch(
        f"/api/v1/investigations/{data['id']}", json={"status": "completed"}, headers=analyst_headers
    )
    assert completed.status_code == 200
    assert client.patch(
        f"/api/v1/investigations/{data['id']}", json={"status": "active"}, headers=analyst_headers
    ).status_code == 409
    assert client.patch(
        f"/api/v1/investigations/{data['id']}", json={"status": "archived"}, headers=analyst_headers
    ).status_code == 200
    assert client.patch(
        f"/api/v1/investigations/{data['id']}", json={"name": "after archive"}, headers=analyst_headers
    ).status_code == 409


def test_investigation_invalid_scope_and_create_status_rejected(client, analyst_headers):
    base = {
        "name": "Valid name",
        "organization_name": "Valid Org",
        "description": "Valid description",
        "lead_investigator": "ignored",
    }
    assert client.post("/api/v1/investigations", json={**base, "status": "archived"}, headers=analyst_headers).status_code == 422
    assert client.post(
        "/api/v1/investigations", json={**base, "scope": {"approved_ips": ["not-an-ip"]}}, headers=analyst_headers
    ).status_code == 422
    assert client.post(
        "/api/v1/investigations", json={**base, "scope": {"approved_cidrs": ["127.0.0.1/24"]}}, headers=analyst_headers
    ).status_code == 422
    assert client.post("/api/v1/investigations", json={**base, "name": "   "}, headers=analyst_headers).status_code == 422


def test_cookie_authenticated_investigation_mutations_require_csrf(admin_client):
    payload = {
        "name": "CSRF test",
        "organization_name": "Test Org",
        "description": "CSRF check",
        "lead_investigator": "unused",
    }
    assert admin_client.post("/api/v1/investigations", json=payload).status_code == 403


def test_authorization_creation_validates_target_type_scope_operations_and_dates(
    client, admin_headers, analyst_user, db_session
):
    inv = _investigation(db_session, analyst_user.id)
    endpoint = f"/api/v1/investigations/{inv.id}/authorizations"
    valid_to = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    good = {
        "target": " LAB.EXAMPLE. ",
        "target_type": "DOMAIN",
        "allowed_operations": ["PASSIVE_RECON", "SCAN_PORTS", "SCAN_VULNERABILITY"],
        "authorization_reference": "LAB-APPROVAL-01",
        "approved_by": "untrusted claimed approver",
        "valid_to": valid_to,
    }
    created = client.post(endpoint, json=good, headers=admin_headers)
    assert created.status_code == 201
    auth = created.json()
    assert auth["target"] == "lab.example"
    assert auth["allowed_operations"] == ["RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"]
    assert auth["approved_by"] == "admin_test"

    assert client.post(endpoint, json={**good, "target_type": "IP"}, headers=admin_headers).status_code == 422
    assert client.post(endpoint, json={**good, "allowed_operations": ["SCAN_EVERYTHING"]}, headers=admin_headers).status_code == 422
    assert client.post(
        endpoint,
        json={**good, "valid_to": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()},
        headers=admin_headers,
    ).status_code == 422
    assert client.post(endpoint, json={**good, "target": "outside.example"}, headers=admin_headers).status_code == 422
    assert client.post(endpoint, json={**good, "target": "127.0.0.1/24", "target_type": "CIDR"}, headers=admin_headers).status_code == 422


def test_authorization_is_exact_operation_specific_and_owner_scoped(
    db_session, analyst_user, viewer_user, admin_user
):
    inv = _investigation(db_session, analyst_user.id)
    _authorization(db_session, inv)

    allowed, _ = verify_target_authorization(db_session, inv, "lab.example", "RECON_PASSIVE", actor_user=analyst_user)
    assert allowed is True
    assert verify_target_authorization(db_session, inv, "lab.example", "SCAN_ACTIVE", actor_user=analyst_user)[0] is False
    assert verify_target_authorization(db_session, inv, "sub.lab.example", "RECON_PASSIVE", actor_user=analyst_user)[0] is False
    assert verify_target_authorization(db_session, inv, "other.example", "RECON_PASSIVE", actor_user=analyst_user)[0] is False
    assert verify_target_authorization(db_session, inv, "lab.example", "RECON_PASSIVE", actor_user=viewer_user)[0] is False
    assert verify_target_authorization(db_session, inv, "lab.example", "RECON_PASSIVE", actor_user=None)[0] is False
    assert verify_target_authorization(db_session, inv, "lab.example", "NOT_A_REAL_OPERATION", actor_user=analyst_user)[0] is False

    legacy = _investigation(db_session, analyst_user.id, inv_id="inv-legacy-auth")
    legacy.authorization_reference = "OLD-REFERENCE"
    legacy.authorization_expiry = datetime.now(timezone.utc) + timedelta(days=1)
    db_session.commit()
    assert verify_target_authorization(db_session, legacy, "lab.example", "RECON_PASSIVE", actor_user=analyst_user)[0] is False
    assert verify_target_authorization(db_session, inv, "lab.example", "RECON_PASSIVE", actor_user=admin_user)[0] is True


def test_authorization_future_expired_revoked_and_cidr_boundaries(db_session, analyst_user, admin_user):
    inv = _investigation(db_session, analyst_user.id)
    now = datetime.now(timezone.utc)
    future = _authorization(
        db_session, inv, id="auth-future", valid_from=now + timedelta(days=1), valid_to=now + timedelta(days=2)
    )
    assert verify_target_authorization(db_session, inv, "lab.example", "RECON_PASSIVE", actor_user=analyst_user)[0] is False
    future.is_revoked = True
    future.valid_from = now - timedelta(days=2)
    future.valid_to = now - timedelta(days=1)
    db_session.commit()
    assert verify_target_authorization(db_session, inv, "lab.example", "RECON_PASSIVE", actor_user=analyst_user)[0] is False

    cidr = _authorization(
        db_session,
        inv,
        id="auth-cidr",
        target="127.0.0.0/8",
        target_type="CIDR",
        allowed_operations=["SCAN_ACTIVE"],
    )
    assert verify_target_authorization(db_session, inv, "127.0.0.1", "SCAN_ACTIVE", actor_user=admin_user)[0] is True
    assert verify_target_authorization(db_session, inv, "128.0.0.1", "SCAN_ACTIVE", actor_user=admin_user)[0] is False
    cidr.is_revoked = True
    db_session.commit()
    assert verify_target_authorization(db_session, inv, "127.0.0.1", "SCAN_ACTIVE", actor_user=admin_user)[0] is False


def test_authorization_api_update_revoke_and_cross_investigation_id_rejected(
    client, admin_headers, analyst_user, admin_user, db_session
):
    inv = _investigation(db_session, analyst_user.id)
    endpoint = f"/api/v1/investigations/{inv.id}/authorizations"
    payload = {
        "target": "lab.example",
        "target_type": "DOMAIN",
        "allowed_operations": ["RECON_PASSIVE"],
        "authorization_reference": "ORIGINAL-REF",
        "valid_to": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    created = client.post(endpoint, json=payload, headers=admin_headers)
    assert created.status_code == 201
    auth_id = created.json()["id"]
    other_inv = _investigation(db_session, analyst_user.id, inv_id="inv-other")
    assert client.delete(
        f"/api/v1/investigations/{other_inv.id}/authorizations/{auth_id}", headers=admin_headers
    ).status_code == 404

    updated = client.patch(
        f"{endpoint}/{auth_id}",
        json={"allowed_operations": ["SCAN_ACTIVE"], "authorization_reference": "UPDATED-REF"},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["allowed_operations"] == ["SCAN_ACTIVE"]
    assert client.patch(f"{endpoint}/{auth_id}", json={"target_type": "IP"}, headers=admin_headers).status_code == 422
    assert verify_target_authorization(db_session, inv, "lab.example", "SCAN_ACTIVE", actor_user=admin_user)[0] is True

    revoked = client.delete(f"{endpoint}/{auth_id}", headers=admin_headers)
    assert revoked.status_code == 200
    assert verify_target_authorization(db_session, inv, "lab.example", "SCAN_ACTIVE", actor_user=admin_user)[0] is False


def test_target_validation_endpoint_returns_consistent_contract(client, analyst_headers, analyst_user, db_session):
    inv = _investigation(db_session, analyst_user.id)
    response = client.post(
        f"/api/v1/investigations/{inv.id}/validate-target",
        json={"target": "lab.example", "operation": "RECON_PASSIVE"},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.json()["is_valid_syntax"] is True
    assert response.json()["is_in_investigation_scope"] is True
    assert response.json()["is_authorized"] is False
    assert "authorization" in response.json()["message"].lower()

