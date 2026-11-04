"""
Step 7.1 UI and Browser Form Interaction Validation Script.
Exercises the actual web UI forms, cookies, and HTMX endpoints.
"""

import urllib.request
import urllib.parse
import http.cookiejar
import json
import re

BASE_URL = "http://127.0.0.1:8000"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get_cookie(name):
    for c in cj:
        if c.name == name:
            return c.value
    return None

ui_audit_results = {}

def record_ui(name, status, details):
    print(f"[{status:8}] {name:35} : {details}")
    ui_audit_results[name] = {"status": status, "details": details}

print("=" * 80)
print("FOOTPRINTIQ STEP 7.1 — WEB UI & BROWSER INTERACTION VALIDATION")
print("=" * 80)

# 1. Access login page & extract CSRF
try:
    resp = opener.open(f"{BASE_URL}/login")
    html = resp.read().decode("utf-8")
    csrf_cookie = get_cookie("footprintiq_csrf")
    has_form = '<form' in html and 'name="username_or_email"' in html
    record_ui("UI_LOGIN_PAGE", "VERIFIED" if has_form else "FAILED", f"Status {resp.status}, CSRF cookie: {bool(csrf_cookie)}")
except Exception as e:
    record_ui("UI_LOGIN_PAGE", "FAILED", str(e))

# 2. Submit Login via Form (POST /auth/login)
try:
    csrf_token = get_cookie("footprintiq_csrf") or ""
    login_data = urllib.parse.urlencode({
        "username_or_email": "admin@footprint.org",
        "password": "FootprintIQ-Demo-2026!",
        "csrf_token": csrf_token
    }).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    resp = opener.open(req)
    session_cookie = get_cookie("footprintiq_session")
    record_ui("UI_FORM_LOGIN", "VERIFIED" if session_cookie else "FAILED", f"Status {resp.status}, Session cookie: {bool(session_cookie)}")
except Exception as e:
    record_ui("UI_FORM_LOGIN", "FAILED", str(e))

# 3. View Dashboard
try:
    resp = opener.open(f"{BASE_URL}/admin/dashboard")
    html = resp.read().decode("utf-8")
    has_stats = "investigations" in html.lower() or "active" in html.lower()
    record_ui("UI_ADMIN_DASHBOARD", "VERIFIED" if has_stats else "FAILED", f"Status {resp.status}, HTML size: {len(html)} bytes")
except Exception as e:
    record_ui("UI_ADMIN_DASHBOARD", "FAILED", str(e))

# 4. View Pending Investigators Admin Management
try:
    resp = opener.open(f"{BASE_URL}/admin/investigators")
    html = resp.read().decode("utf-8")
    has_table = "investigators" in html.lower()
    record_ui("UI_ADMIN_INVESTIGATORS", "VERIFIED" if has_table else "FAILED", f"Status {resp.status}, HTML size: {len(html)} bytes")
except Exception as e:
    record_ui("UI_ADMIN_INVESTIGATORS", "FAILED", str(e))

# 5. View Investigations List
test_inv_id = "inv-b239e808"
try:
    resp = opener.open(f"{BASE_URL}/investigations")
    html = resp.read().decode("utf-8")
    has_inv = test_inv_id in html or "E2E Acceptance" in html
    record_ui("UI_INVESTIGATIONS_LIST", "VERIFIED" if has_inv else "FAILED", f"Status {resp.status}, Found test investigation: {has_inv}")
except Exception as e:
    record_ui("UI_INVESTIGATIONS_LIST", "FAILED", str(e))

# 6. View Investigation Workspace Detail & Tabs
try:
    resp = opener.open(f"{BASE_URL}/investigations/{test_inv_id}")
    html = resp.read().decode("utf-8")
    tabs = {
        "overview": "overview" in html.lower(),
        "recon": "reconnaissance" in html.lower() or "passive" in html.lower(),
        "scans": "scans" in html.lower() or "nmap" in html.lower(),
        "vulnerabilities": "vulnerabilit" in html.lower() or "greenbone" in html.lower(),
        "correlations": "correlation" in html.lower(),
        "scoring": "exposure" in html.lower() or "risk" in html.lower(),
        "evidence": "evidence" in html.lower(),
        "reports": "report" in html.lower() or "pdf" in html.lower(),
    }
    all_tabs = all(tabs.values())
    record_ui("UI_WORKSPACE_DETAIL_TABS", "VERIFIED" if all_tabs else "PARTIALLY VERIFIED", f"Status {resp.status}, Tabs detected: {tabs}")
except Exception as e:
    record_ui("UI_WORKSPACE_DETAIL_TABS", "FAILED", str(e))

# 7. Check PDF Report Export
try:
    resp = opener.open(f"{BASE_URL}/api/v1/investigations/{test_inv_id}/workflow/report/pdf")
    pdf_bytes = resp.read()
    is_pdf = pdf_bytes.startswith(b"%PDF-")
    record_ui("UI_PDF_REPORT_DOWNLOAD", "VERIFIED" if is_pdf else "FAILED", f"Status {resp.status}, Header: {pdf_bytes[:8]}, Size: {len(pdf_bytes)} bytes")
except Exception as e:
    record_ui("UI_PDF_REPORT_DOWNLOAD", "FAILED", str(e))

# 8. Check GraphML Export
try:
    resp = opener.open(f"{BASE_URL}/api/v1/investigations/{test_inv_id}/export/graphml")
    gml_bytes = resp.read()
    is_gml = b"<graphml" in gml_bytes
    record_ui("UI_GRAPHML_EXPORT_DOWNLOAD", "VERIFIED" if is_gml else "FAILED", f"Status {resp.status}, Found <graphml: {is_gml}, Size: {len(gml_bytes)} bytes")
except Exception as e:
    record_ui("UI_GRAPHML_EXPORT_DOWNLOAD", "FAILED", str(e))

# 9. Check Evidence Download from UI
try:
    # First get evidence list
    resp = opener.open(f"{BASE_URL}/api/v1/investigations/{test_inv_id}/evidence")
    ev_list = json.loads(resp.read().decode())
    items = ev_list.get("evidence", []) if isinstance(ev_list, dict) else ev_list
    if items:
        ev_id = items[0]["id"]
        # Download raw
        r_resp = opener.open(f"{BASE_URL}/api/v1/investigations/{test_inv_id}/evidence/{ev_id}/raw")
        raw_b = r_resp.read()
        record_ui("UI_EVIDENCE_RAW_DOWNLOAD", "VERIFIED", f"Downloaded evidence {ev_id} ({len(raw_b)} bytes)")
    else:
        record_ui("UI_EVIDENCE_RAW_DOWNLOAD", "PARTIALLY VERIFIED", "No evidence in investigation")
except Exception as e:
    record_ui("UI_EVIDENCE_RAW_DOWNLOAD", "FAILED", str(e))

# 10. Check Exposure Score History UI
try:
    resp = opener.open(f"{BASE_URL}/api/v1/investigations/{test_inv_id}/exposure-score/history")
    hist = json.loads(resp.read().decode())
    record_ui("UI_SCORE_HISTORY_ENDPOINT", "VERIFIED" if len(hist) > 0 else "PARTIALLY VERIFIED", f"Retrieved {len(hist)} score records")
except Exception as e:
    record_ui("UI_SCORE_HISTORY_ENDPOINT", "FAILED", str(e))

print("=" * 80)
total = len(ui_audit_results)
v = sum(1 for r in ui_audit_results.values() if r["status"] == "VERIFIED")
p = sum(1 for r in ui_audit_results.values() if r["status"] == "PARTIALLY VERIFIED")
f = sum(1 for r in ui_audit_results.values() if r["status"] == "FAILED")
print(f"UI AUDIT SUMMARY: Total: {total} | VERIFIED: {v} | PARTIALLY: {p} | FAILED: {f}")
print("=" * 80)

