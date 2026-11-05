"""Comprehensive automated test suite for Feature Card Navigation & Authentication-Aware Redirects.

Covers:
1. All 7 landing page & features page cards rendered with semantic <a> links and valid destinations.
2. Complete 12-case test matrix from the prompt:
   - Case 1: Authenticated investigator/admin -> direct navigation (no login prompt)
   - Case 2: Unauthenticated user -> 303 Redirect to /login?next=<destination>
   - Case 3: Post-login redirect to exact requested feature destination
   - Case 4: Login without feature selection -> role-based default dashboard (/dashboard vs /admin/dashboard)
   - Case 5: Invalid login attempt -> remains on /login, error displayed, next parameter preserved
   - Case 6: Permitted features accessible to investigator (/investigations, /scans, /findings, /evidence)
   - Case 7: Restricted feature (/admin/investigators) -> /access-denied (no redirect loop, user stays authenticated)
   - Case 8: Restricted feature accessible to administrator (/admin/investigators -> 200 OK)
   - Case 9: External return URL (https://evil.com) rejected -> safe default fallback
   - Case 10: Protocol-relative return URL (//evil.com, /\\evil.com) rejected -> safe default fallback
   - Case 11: Missing/empty return URL -> safe default fallback
   - Case 12: Login page reload (/login?next=/scans) preserves next parameter in form
3. Rigorous security unit tests for is_safe_redirect_url (CRLF, schemes, encoding, netloc bypasses).
"""

import pytest
from starlette.testclient import TestClient
from app.core.security import is_safe_redirect_url

EXPECTED_FEATURE_DESTINATIONS = [
    "/scans#passive-recon",
    "/investigations",
    "/scans#nmap-scans",
    "/findings",
    "/evidence",
    "/investigations",
    "/admin/investigators",
]


# =============================================================================
# 1. LANDING & FEATURES PAGE FEATURE CARD AUDIT
# =============================================================================
def test_all_seven_feature_cards_present_and_clickable_on_landing(client: TestClient):
    """Verify all 7 feature cards exist on the landing page (/) as semantic links."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    for dest in EXPECTED_FEATURE_DESTINATIONS:
        assert f'href="{dest}"' in html, f"Missing destination {dest} in landing page"

    assert "public-card-link" in html
    assert "Passive Reconnaissance" in html
    assert "Investigation Management" in html
    assert "Network Assessment (Nmap)" in html
    assert "Vulnerability Assessment" in html
    assert "Evidence Management" in html
    assert "Investigation Reports" in html
    assert "Authentication and Access Control" in html


def test_all_seven_feature_cards_present_and_clickable_on_features_page(client: TestClient):
    """Verify all 7 feature cards exist on /features as semantic links with proper metadata."""
    res = client.get("/features")
    assert res.status_code == 200
    html = res.text

    for dest in EXPECTED_FEATURE_DESTINATIONS:
        assert f'href="{dest}"' in html, f"Missing destination {dest} in /features page"

    assert "public-card-link" in html
    assert "Platform capabilities" in html


# =============================================================================
# 2. THE 12-CASE ACCEPTANCE TEST MATRIX
# =============================================================================

def test_case_1_authenticated_direct_navigation(
    authenticated_client: TestClient, admin_client: TestClient
):
    """Case 1: Authenticated user navigating to feature destinations gets direct 200 OK (no login prompt)."""
    # Investigator/Analyst navigating to permitted features
    for path in ["/investigations", "/scans", "/findings", "/evidence"]:
        res = authenticated_client.get(path, follow_redirects=False)
        assert res.status_code == 200, f"Expected 200 for {path}, got {res.status_code}"
        assert "/login" not in res.headers.get("location", "")

    # Admin navigating to admin and operational features
    for path in ["/investigations", "/scans", "/findings", "/evidence", "/admin/investigators"]:
        res = admin_client.get(path, follow_redirects=False)
        assert res.status_code == 200, f"Expected 200 for admin on {path}, got {res.status_code}"


def test_case_2_unauthenticated_click_feature_card_redirects_to_login(client: TestClient):
    """Case 2: Unauthenticated visitor accessing feature destinations gets redirected to /login?next=..."""
    destinations = [
        "/investigations",
        "/scans",
        "/findings",
        "/evidence",
        "/admin/investigators",
    ]
    for dest in destinations:
        res = client.get(dest, follow_redirects=False)
        assert res.status_code == 303, f"Expected 303 for unauthenticated {dest}"
        loc = res.headers.get("location")
        assert loc == f"/login?next={dest}", f"Expected /login?next={dest}, got {loc}"


def test_case_3_login_after_selecting_feature_redirects_to_exact_destination(
    client: TestClient, analyst_user
):
    """Case 3: Unauthenticated user clicks card, redirected to login, logs in -> redirected to requested feature."""
    login_page = client.get("/login?next=/findings")
    assert login_page.status_code == 200
    csrf = client.cookies.get("footprintiq_csrf")
    assert csrf

    login_res = client.post(
        "/auth/login",
        data={
            "username_or_email": "analyst_test",
            "password": "AnalystSecure123!#",
            "csrf_token": csrf,
            "next": "/findings",
        },
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/findings"


def test_case_4_login_without_selecting_feature_redirects_to_default_dashboard(
    client: TestClient, analyst_user, admin_user
):
    """Case 4: Direct login without next parameter sends users to role-based default dashboard."""
    # Analyst/Investigator -> /dashboard
    client.get("/login")
    csrf = client.cookies.get("footprintiq_csrf")
    inv_login = client.post(
        "/auth/login",
        data={
            "username_or_email": "analyst_test",
            "password": "AnalystSecure123!#",
            "csrf_token": csrf,
            "next": "",
        },
        follow_redirects=False,
    )
    assert inv_login.status_code == 303
    assert inv_login.headers["location"] == "/dashboard"

    # Admin -> /admin/dashboard
    client.cookies.clear()
    client.get("/login")
    admin_csrf = client.cookies.get("footprintiq_csrf")
    admin_login = client.post(
        "/auth/login",
        data={
            "username_or_email": "admin_test",
            "password": "AdminSecure123!#",
            "csrf_token": admin_csrf,
            "next": "",
        },
        follow_redirects=False,
    )
    assert admin_login.status_code == 303
    assert admin_login.headers["location"] == "/admin/dashboard"


def test_case_5_invalid_login_preserves_next_and_shows_error(client: TestClient, analyst_user):
    """Case 5: Bad credentials attempt preserves next parameter in form and displays error without losing state."""
    client.get("/login?next=/evidence")
    csrf = client.cookies.get("footprintiq_csrf")

    fail_res = client.post(
        "/auth/login",
        data={
            "username_or_email": "analyst_test",
            "password": "WrongPassword123!",
            "csrf_token": csrf,
            "next": "/evidence",
        },
        follow_redirects=False,
    )
    assert fail_res.status_code in (401, 400)
    html = fail_res.text
    assert 'name="next" value="/evidence"' in html
    assert "Invalid username or password" in html or "Sign-in error" in html or "error" in html.lower()


def test_case_6_investigator_opens_permitted_features(
    authenticated_client: TestClient
):
    """Case 6: Authenticated investigator accesses permitted operational features (200 OK)."""
    for route in ["/investigations", "/scans", "/findings", "/evidence"]:
        res = authenticated_client.get(route)
        assert res.status_code == 200
        assert "FootprintIQ" in res.text


def test_case_7_investigator_accessing_admin_investigators_denied(
    authenticated_client: TestClient
):
    """Case 7: Investigator attempting to access /admin/investigators is denied without a redirect loop."""
    res = authenticated_client.get("/admin/investigators", follow_redirects=False)
    # Redirects cleanly to /access-denied
    assert res.status_code == 303
    assert res.headers["location"] == "/access-denied"

    # Following to /access-denied returns 403 Access Restricted page without looping
    denied_res = authenticated_client.get("/access-denied")
    assert denied_res.status_code == 403
    assert "Access Restricted" in denied_res.text or "403" in denied_res.text
    assert "analyst_test" in denied_res.text or "ANALYST" in denied_res.text


def test_case_8_admin_opens_admin_investigators(
    admin_client: TestClient
):
    """Case 8: Administrator opens /admin/investigators successfully with 200 OK."""
    res = admin_client.get("/admin/investigators")
    assert res.status_code == 200
    assert "Investigator Approval Management" in res.text


def test_case_9_external_return_url_rejected(client: TestClient, analyst_user):
    """Case 9: External absolute return URLs (https://evil.com) are rejected and fall back safely to default dashboard."""
    client.get("/login?next=https://evil.com")
    csrf = client.cookies.get("footprintiq_csrf")

    login_res = client.post(
        "/auth/login",
        data={
            "username_or_email": "analyst_test",
            "password": "AnalystSecure123!#",
            "csrf_token": csrf,
            "next": "https://evil.com/phish",
        },
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/dashboard"


def test_case_10_protocol_relative_return_url_rejected(client: TestClient, analyst_user):
    """Case 10: Protocol-relative URLs (//evil.com, /\\evil.com, /%2fevil.com) are rejected and fall back safely."""
    for malformed in ["//evil.com", "//evil.com/path", "/\\evil.com", "/%2fevil.com"]:
        client.get(f"/login?next={malformed}")
        csrf = client.cookies.get("footprintiq_csrf")

        login_res = client.post(
            "/auth/login",
            data={
                "username_or_email": "analyst_test",
                "password": "AnalystSecure123!#",
                "csrf_token": csrf,
                "next": malformed,
            },
            follow_redirects=False,
        )
        assert login_res.status_code == 303
        assert login_res.headers["location"] == "/dashboard"


def test_case_11_missing_or_empty_return_url_safe_fallback(client: TestClient, analyst_user):
    """Case 11: Missing or blank return URL safely redirects to role-based dashboard."""
    client.get("/login")
    csrf = client.cookies.get("footprintiq_csrf")

    login_res = client.post(
        "/auth/login",
        data={
            "username_or_email": "analyst_test",
            "password": "AnalystSecure123!#",
            "csrf_token": csrf,
            "next": "   ",
        },
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/dashboard"


def test_case_12_refresh_login_preserves_next_in_form(client: TestClient):
    """Case 12: Navigating to or reloading /login?next=/scans preserves the destination in hidden form input."""
    res = client.get("/login?next=/scans")
    assert res.status_code == 200
    assert '<input type="hidden" name="next" value="/scans">' in res.text


# =============================================================================
# 3. UNIT SECURITY TESTS FOR IS_SAFE_REDIRECT_URL
# =============================================================================
@pytest.mark.parametrize(
    "safe_url",
    [
        "/",
        "/dashboard",
        "/investigations",
        "/scans",
        "/scans#nmap-scans",
        "/scans#passive-recon",
        "/findings",
        "/evidence",
        "/admin/investigators",
        "/investigations?status=active",
        "/findings?severity=critical&q=cve-2024",
    ],
)
def test_is_safe_redirect_url_accepts_valid_relative_urls(safe_url: str):
    assert is_safe_redirect_url(safe_url) is True


@pytest.mark.parametrize(
    "dangerous_url",
    [
        None,
        "",
        "   ",
        "https://evil.com",
        "http://attacker.org",
        "ftp://files.example.com",
        "//evil.com",
        "//attacker.org/login",
        "/\\evil.com",
        "\\evil.com",
        "/%2f/evil.com",
        "/%5cevil.com",
        "/test\r\nSet-Cookie: evil=1",
        "/test\nHeader: value",
        "/test\0nullbyte",
        "javascript:alert(1)",
        "javascript://alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox",
        "/@evil.com",
        "/foo@bar.com",
        "//localhost:8000",
        "http://127.0.0.1:8000/dashboard",
    ],
)
def test_is_safe_redirect_url_rejects_dangerous_targets(dangerous_url):
    assert is_safe_redirect_url(dangerous_url) is False


def test_authenticated_user_accessing_login_with_next_redirects_immediately(
    authenticated_client: TestClient
):
    """When an already authenticated user accesses /login?next=/evidence, they are immediately bounced to /evidence."""
    res = authenticated_client.get("/login?next=/evidence", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/evidence"


def test_auth_loop_prevention(client: TestClient, analyst_user):
    """If next points back to /login or /auth/login, it should be ignored and fallback to default dashboard."""
    for loop_target in ["/login", "/auth/login", "/signup", "/register", "/auth/logout"]:
        client.cookies.clear()
        client.get("/login")
        csrf = client.cookies.get("footprintiq_csrf")
        res = client.post(
            "/auth/login",
            data={
                "username_or_email": "analyst_test",
                "password": "AnalystSecure123!#",
                "csrf_token": csrf,
                "next": loop_target,
            },
            follow_redirects=False,
        )
        assert res.status_code == 303
        assert res.headers["location"] == "/dashboard"
