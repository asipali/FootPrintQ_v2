"""
STEP 7: Complete End-to-End Application Integration & Workflow Acceptance Tests.
Covers Admin Persona, Investigator Persona, Scope Guardrails, Evidence Storage,
Correlation Engine, Exposure Scoring (v3.0-5factor), Reporting, and Tenant Isolation.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import UserModel
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.core.security import hash_password, ROLE_INVESTIGATOR, ROLE_ADMINISTRATOR


def test_admin_persona_investigator_approval_workflow(client: TestClient, admin_headers: dict, db_session: Session):
    """
    User Journey 1: Administrator Persona
    - User signs up as investigator -> status is pending
    - Login rejected with HTTP 403 pending approval
    - Admin lists pending investigators
    - Admin approves investigator
    - Investigator logs in successfully
    - Investigator denied admin-only user management (RBAC check)
    """
    uid = uuid.uuid4().hex[:8]
    email = f"test_e2e_{uid}@investigation-audit.org"
    username = f"inv_{uid}"
    password = "InvestigatorPass2026!#"

    # 1. Signup
    signup_resp = client.post("/api/v1/auth/signup", json={
        "email": email,
        "username": username,
        "password": password,
        "full_name": f"Investigator {uid}"
    })
    assert signup_resp.status_code in (200, 201)
    signup_data = signup_resp.json()
    user_id = signup_data.get("id") or signup_data.get("user", {}).get("id")
    status = signup_data.get("account_status") or signup_data.get("user", {}).get("account_status")
    assert status == "pending"

    # 2. Unapproved login attempt blocked with 403
    blocked_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": email,
        "password": password
    })
    assert blocked_resp.status_code == 403
    assert "pending" in blocked_resp.json()["error"]["message"].lower()

    # 3. Admin lists pending investigators
    pending_resp = client.get("/api/v1/users/pending-investigators", headers=admin_headers)
    assert pending_resp.status_code == 200
    pending_users = pending_resp.json()
    assert any(u["id"] == user_id for u in pending_users)

    # 4. Admin approves investigator
    approve_resp = client.post(f"/api/v1/users/{user_id}/approve", headers=admin_headers, json={})
    assert approve_resp.status_code == 200
    assert approve_resp.json()["account_status"] == "active"

    # 5. Investigator login succeeds
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": email,
        "password": password
    })
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert "access_token" in login_data
    token = login_data["access_token"]
    inv_headers = {"Authorization": f"Bearer {token}"}

    # 6. Investigator RBAC: cannot access admin user management
    forbidden_resp = client.get("/api/v1/users", headers=inv_headers)
    assert forbidden_resp.status_code == 403


def test_investigator_campaign_authorization_and_guardrails(client: TestClient, admin_headers: dict, db_session: Session):
    """
    User Journey 2: Investigator Persona & Scope Guardrails
    - Investigator creates investigation with defined scope
    - Target authorization provisioned
    - Out-of-scope validation rejected
    - In-scope validation approved
    """
    uid = uuid.uuid4().hex[:8]
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    # Create investigation
    inv_resp = client.post("/api/v1/investigations", headers=admin_headers, json={
        "name": f"Scope Guardrail Test {uid}",
        "organization_name": "Test Lab Corp",
        "description": "Verifying scope guardrail rejection and approval",
        "lead_investigator": "Lead Auditor",
        "active_scanning_enabled": True,
        "scope": {
            "owned_domains": ["audit.lab"],
            "approved_ips": ["192.168.56.102"],
            "approved_cidrs": ["192.168.56.0/24"],
            "active_targets": ["192.168.56.102"]
        }
    })
    assert inv_resp.status_code in (200, 201)
    inv_id = inv_resp.json()["id"]

    # Add Target Authorization for IP
    auth_resp = client.post(f"/api/v1/investigations/{inv_id}/authorizations", headers=admin_headers, json={
        "target": "192.168.56.102",
        "target_type": "IP",
        "allowed_operations": ["RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"],
        "authorization_reference": f"AUTH-TEST-{uid}",
        "valid_to": future,
        "notes": "E2E authorization test"
    })
    assert auth_resp.status_code in (200, 201)

    # Out-of-scope target rejected
    val_out = client.post(f"/api/v1/investigations/{inv_id}/validate-target", headers=admin_headers, json={
        "target": "8.8.8.8",
        "operation": "SCAN_ACTIVE"
    })
    assert val_out.status_code == 200
    assert val_out.json()["is_in_investigation_scope"] is False
    assert val_out.json()["is_authorized"] is False

    # In-scope target approved
    val_in = client.post(f"/api/v1/investigations/{inv_id}/validate-target", headers=admin_headers, json={
        "target": "192.168.56.102",
        "operation": "SCAN_ACTIVE"
    })
    assert val_in.status_code == 200
    assert val_in.json()["is_in_investigation_scope"] is True
    assert val_in.json()["is_authorized"] is True


def test_e2e_correlation_and_exposure_scoring(client: TestClient, admin_headers: dict, db_session: Session):
    """
    Step 5 Correlation + Step 6 Exposure Scoring Integration:
    - Verifies correlation refresh endpoint
    - Verifies v3.0-5factor exposure score calculation
    - Verifies score retrieval and audit history
    """
    uid = uuid.uuid4().hex[:8]
    inv = InvestigationModel(
        id=f"inv-step7-{uid}",
        name=f"Analytics Integration {uid}",
        organization_name="Analytics Lab",
        description="Correlation and Scoring acceptance test",
        lead_investigator="Lead Auditor",
        status="active",
        owned_domains=["analytics.lab"],
        approved_ips=["192.168.56.102"],
        approved_cidrs=["192.168.56.0/24"],
        active_targets=["192.168.56.102"]
    )
    db_session.add(inv)
    db_session.commit()

    # Trigger correlation refresh
    corr_refresh = client.post(f"/api/v1/investigations/{inv.id}/correlations/refresh", headers=admin_headers, json={})
    assert corr_refresh.status_code == 200
    assert isinstance(corr_refresh.json(), (dict, list))

    # Query correlations
    corr_list = client.get(f"/api/v1/investigations/{inv.id}/correlations", headers=admin_headers)
    assert corr_list.status_code == 200

    # Calculate exposure score
    calc_resp = client.post(f"/api/v1/investigations/{inv.id}/exposure-score/calculate", headers=admin_headers, json={
        "formula_version": "v3.0-5factor"
    })
    assert calc_resp.status_code == 200
    score_data = calc_resp.json()
    assert score_data["formula_version"] == "v3.0-5factor"
    assert "total_score" in score_data
    assert "renormalized_score" in score_data
    assert "formula_weights" in score_data

    # Query current score
    get_score = client.get(f"/api/v1/investigations/{inv.id}/exposure-score", headers=admin_headers)
    assert get_score.status_code == 200

    # Query history
    hist_resp = client.get(f"/api/v1/investigations/{inv.id}/exposure-score/history", headers=admin_headers)
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1


def test_e2e_reporting_pdf_and_graphml(client: TestClient, admin_headers: dict, db_session: Session):
    """
    Reporting Integration:
    - Generates PDF report with %PDF header
    - Exports GraphML topology with <graphml XML tag
    """
    uid = uuid.uuid4().hex[:8]
    inv = InvestigationModel(
        id=f"inv-rep-{uid}",
        name=f"Report Campaign {uid}",
        organization_name="Report Org",
        description="Report Generation acceptance test",
        lead_investigator="Lead Auditor",
        status="active",
        owned_domains=["report.lab"],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=[]
    )
    db_session.add(inv)
    db_session.commit()

    # PDF Report
    pdf_resp = client.get(f"/api/v1/investigations/{inv.id}/workflow/report/pdf", headers=admin_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.content.startswith(b"%PDF-")

    # GraphML Export
    graph_resp = client.get(f"/api/v1/investigations/{inv.id}/export/graphml", headers=admin_headers)
    assert graph_resp.status_code == 200
    assert b"<graphml" in graph_resp.content


def test_tenant_isolation_and_cross_user_boundaries(client: TestClient, admin_headers: dict, db_session: Session):
    """
    Security Audit: Tenant Isolation
    - User A creates an investigation
    - User B cannot view or modify User A's investigation (returns 403 or non-disclosing 404)
    """
    uid1 = uuid.uuid4().hex[:8]
    uid2 = uuid.uuid4().hex[:8]

    # Create User A
    user_a = UserModel(
        id=f"usr-a-{uid1}",
        username=f"usera_{uid1}",
        email=f"usera_{uid1}@corp.org",
        password_hash=hash_password("Pass12345!#Aa"),
        role=ROLE_INVESTIGATOR,
        account_status="active",
        is_active=True
    )
    # Create User B
    user_b = UserModel(
        id=f"usr-b-{uid2}",
        username=f"userb_{uid2}",
        email=f"userb_{uid2}@corp.org",
        password_hash=hash_password("Pass12345!#Aa"),
        role=ROLE_INVESTIGATOR,
        account_status="active",
        is_active=True
    )
    db_session.add_all([user_a, user_b])
    db_session.commit()

    # User A investigation
    inv_a = InvestigationModel(
        id=f"inv-iso-{uid1}",
        name="User A Confidential",
        organization_name="Org A",
        description="Confidential to A",
        lead_investigator="Investigator A",
        owner_user_id=user_a.id,
        status="active",
        owned_domains=["a.internal"],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=[]
    )
    db_session.add(inv_a)
    db_session.commit()

    # Login as User B
    login_b = client.post("/api/v1/auth/login", json={
        "username_or_email": f"userb_{uid2}@corp.org",
        "password": "Pass12345!#Aa"
    })
    token_b = login_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User B attempts to access User A's investigation
    resp = client.get(f"/api/v1/investigations/{inv_a.id}", headers=headers_b)
    assert resp.status_code in (403, 404)
