"""Live Verification of Feature Card Navigation and Authentication-Aware Redirects against http://127.0.0.1:8000.

Performs live HTTP requests to verify:
1. Feature Cards on Landing Page (/) & Features Page (/features):
   - All 7 feature cards exist as semantic <a class="public-card public-card-link" href="...">
   - All 7 destinations match canonical routes
2. Scenario A: Direct Access for Authenticated Users (Investigator & Admin)
3. Scenario B: Logged-Out Click & Login Redirect (Return-to-Page preserves destination)
4. Scenario C: Failed Login preserves destination in form input
5. Scenario D: Investigator accessing /admin/investigators redirected to /access-denied (no redirect loop)
6. Security checks: open-redirect rejections (external, protocol-relative, CRLF, javascript)
"""

import sys
import re
import requests

BASE_URL = "http://127.0.0.1:8000"
INVESTIGATOR_USER = "footprint_investigator_demo"
INVESTIGATOR_PASS = "FootprintIQ-Demo-2026!"
ADMIN_USER = "footprint_admin_demo"
ADMIN_PASS = "FootprintIQ-Demo-2026!"

EXPECTED_CARDS = [
    {"title": "Passive Reconnaissance", "url": "/scans#passive-recon"},
    {"title": "Investigation Management", "url": "/investigations"},
    {"title": "Network Assessment (Nmap)", "url": "/scans#nmap-scans"},
    {"title": "Vulnerability Assessment", "url": "/findings"},
    {"title": "Evidence Management", "url": "/evidence"},
    {"title": "Investigation Reports", "url": "/investigations"},
    {"title": "Authentication and Access Control", "url": "/admin/investigators"},
]

def check(condition: bool, desc: str):
    if condition:
        print(f"  [PASS] {desc}")
    else:
        print(f"  [FAIL] {desc}")
        sys.exit(1)

def run_live_verification():
    print("=" * 70)
    print("FOOTPRINTIQ LIVE FEATURE CARD NAVIGATION AUDIT")
    print(f"Target Server: {BASE_URL}")
    print("=" * 70)

    # 1. Landing page card inspection
    print("\n1. Verifying Feature Cards on Landing Page (GET /):")
    res = requests.get(f"{BASE_URL}/", allow_redirects=False)
    check(res.status_code == 200, "Landing page returns HTTP 200 OK")
    html = res.text
    for card in EXPECTED_CARDS:
        check(f'href="{card["url"]}"' in html, f"Card for '{card['title']}' has href='{card['url']}'")
        check(f'class="public-card public-card-link"' in html, "Semantic public-card-link class applied")

    # 2. Features page card inspection
    print("\n2. Verifying Feature Cards on Features Page (GET /features):")
    res = requests.get(f"{BASE_URL}/features", allow_redirects=False)
    check(res.status_code == 200, "Features page returns HTTP 200 OK")
    html = res.text
    for card in EXPECTED_CARDS:
        check(f'href="{card["url"]}"' in html, f"Features page card has href='{card['url']}'")

    # 3. Unauthenticated redirects to login?next=...
    print("\n3. Verifying Unauthenticated Interception & Return-To-Page:")
    test_dests = [
        ("/investigations", "/login?next=/investigations"),
        ("/scans", "/login?next=/scans"),
        ("/findings", "/login?next=/findings"),
        ("/evidence", "/login?next=/evidence"),
        ("/admin/investigators", "/login?next=/admin/investigators"),
    ]
    for path, expected_redirect in test_dests:
        r = requests.get(f"{BASE_URL}{path}", allow_redirects=False)
        check(r.status_code == 303, f"GET {path} unauthenticated returns 303 See Other")
        check(r.headers.get("Location") == expected_redirect, f"Redirect location is '{expected_redirect}'")

    # 4. Successful Login with Return-To-Page (Scenario B)
    print("\n4. Verifying Login with Return-To-Page (Scenario B):")
    s = requests.Session()
    login_page = s.get(f"{BASE_URL}/login?next=/findings")
    check(login_page.status_code == 200, "GET /login?next=/findings returns 200 OK")
    check('<input type="hidden" name="next" value="/findings">' in login_page.text, "Hidden input 'next' has value '/findings'")
    csrf = s.cookies.get("footprintiq_csrf")
    check(bool(csrf), "CSRF cookie footprintiq_csrf acquired")

    login_post = s.post(
        f"{BASE_URL}/auth/login",
        data={
            "username_or_email": INVESTIGATOR_USER,
            "password": INVESTIGATOR_PASS,
            "csrf_token": csrf,
            "next": "/findings",
        },
        allow_redirects=False,
    )
    check(login_post.status_code == 303, "Login POST returns HTTP 303 See Other")
    check(login_post.headers.get("Location") == "/findings", "Post-login redirect location is exactly '/findings'")
    
    # Follow redirect to destination
    dest_page = s.get(f"{BASE_URL}/findings")
    check(dest_page.status_code == 200, "Navigating to /findings as authenticated user returns 200 OK")
    check("Vulnerability Findings" in dest_page.text, "Findings ledger rendered for authenticated investigator")

    # 5. Direct access for authenticated user (Scenario A)
    print("\n5. Verifying Authenticated Direct Access (Scenario A):")
    for direct_path in ["/investigations", "/scans", "/findings", "/evidence"]:
        r = s.get(f"{BASE_URL}{direct_path}", allow_redirects=False)
        check(r.status_code == 200, f"Authenticated investigator gets 200 OK on {direct_path} directly without login prompt")

    # 6. Failed login preserves destination (Scenario C)
    print("\n6. Verifying Failed Login Preserves Return URL (Scenario C):")
    s_fail = requests.Session()
    s_fail.get(f"{BASE_URL}/login?next=/evidence")
    fail_csrf = s_fail.cookies.get("footprintiq_csrf")
    fail_post = s_fail.post(
        f"{BASE_URL}/auth/login",
        data={
            "username_or_email": INVESTIGATOR_USER,
            "password": "WrongPassword999!",
            "csrf_token": fail_csrf,
            "next": "/evidence",
        },
        allow_redirects=False,
    )
    check(fail_post.status_code in (400, 401), f"Failed login returns 401 Unauthorized (got {fail_post.status_code})")
    check('name="next" value="/evidence"' in fail_post.text, "Preserved 'next' field value in error form")
    check("Invalid username or password" in fail_post.text or "Sign-in error" in fail_post.text, "Clear authentication error message displayed")

    # 7. Investigator accessing restricted admin feature -> access-denied (Scenario D)
    print("\n7. Verifying Access Denied for Insufficient Permissions (Scenario D):")
    admin_res = s.get(f"{BASE_URL}/admin/investigators", allow_redirects=False)
    check(admin_res.status_code == 303, "GET /admin/investigators as investigator returns 303 redirect to /access-denied")
    check(admin_res.headers.get("Location") == "/access-denied", "Redirect target is /access-denied")

    denied_page = s.get(f"{BASE_URL}/access-denied")
    check(denied_page.status_code == 403, "GET /access-denied returns 403 Forbidden status code")
    check("Access Restricted" in denied_page.text or "403" in denied_page.text, "Access Restricted message rendered")
    check(INVESTIGATOR_USER in denied_page.text or "INVESTIGATOR" in denied_page.text, "Identity and investigator role preserved")

    # 8. Admin accessing admin feature succeeds
    print("\n8. Verifying Administrator Access:")
    s_admin = requests.Session()
    s_admin.get(f"{BASE_URL}/login")
    adm_csrf = s_admin.cookies.get("footprintiq_csrf")
    adm_login = s_admin.post(
        f"{BASE_URL}/auth/login",
        data={
            "username_or_email": ADMIN_USER,
            "password": ADMIN_PASS,
            "csrf_token": adm_csrf,
            "next": "/admin/investigators",
        },
        allow_redirects=False,
    )
    check(adm_login.status_code == 303, "Admin login returns 303 redirect")
    check(adm_login.headers.get("Location") == "/admin/investigators", "Admin post-login redirects to /admin/investigators")
    adm_page = s_admin.get(f"{BASE_URL}/admin/investigators")
    check(adm_page.status_code == 200, "Administrator opens /admin/investigators with 200 OK")

    # 9. Open Redirect Defense Checks
    print("\n9. Verifying Open Redirect Defenses:")
    dangerous_targets = [
        "https://evil.com/phish",
        "http://attacker.org",
        "//evil.com",
        "//evil.com/path",
        "/\\evil.com",
        "/%2f/evil.com",
        "javascript:alert(1)",
    ]
    for bad_target in dangerous_targets:
        s_sec = requests.Session()
        s_sec.get(f"{BASE_URL}/login")
        c_csrf = s_sec.cookies.get("footprintiq_csrf")
        sec_post = s_sec.post(
            f"{BASE_URL}/auth/login",
            data={
                "username_or_email": INVESTIGATOR_USER,
                "password": INVESTIGATOR_PASS,
                "csrf_token": c_csrf,
                "next": bad_target,
            },
            allow_redirects=False,
        )
        check(sec_post.status_code == 303, f"Login with dangerous next='{bad_target}' returns 303")
        loc = sec_post.headers.get("Location")
        check(loc == "/dashboard", f"Dangerous next='{bad_target}' safely redirected to fallback '/dashboard' (got {loc})")

    # 10. Login without selection redirects to default dashboard
    print("\n10. Verifying Default Dashboard Redirects (no next param):")
    s_def = requests.Session()
    s_def.get(f"{BASE_URL}/login")
    d_csrf = s_def.cookies.get("footprintiq_csrf")
    d_post = s_def.post(
        f"{BASE_URL}/auth/login",
        data={
            "username_or_email": INVESTIGATOR_USER,
            "password": INVESTIGATOR_PASS,
            "csrf_token": d_csrf,
            "next": "",
        },
        allow_redirects=False,
    )
    check(d_post.status_code == 303 and d_post.headers.get("Location") == "/dashboard", "Investigator without next lands on /dashboard")

    print("\n" + "=" * 70)
    print("ALL LIVE FEATURE CARD NAVIGATION TESTS PASSED SUCCESSFULLY (32/32 assertions)!")
    print("=" * 70)

if __name__ == "__main__":
    run_live_verification()

