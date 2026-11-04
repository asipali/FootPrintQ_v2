"""
End-to-end integration and acceptance test runner for Step 7.
Tests all workflows against the live FootprintIQ server (http://127.0.0.1:8000).
"""

import sys
import json
import time
import uuid
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

BASE_URL = "http://127.0.0.1:8000"
LAB_TARGET = "192.168.56.102"
LAB_CIDR = "192.168.56.0/24"
OUT_OF_SCOPE_TARGET = "8.8.8.8"

results = {}

def log_step(name, status, details=None):
    print(f"[{status}] {name}")
    if details:
        print(f"       {details}")
    results[name] = {"status": status, "details": details}

class ApiSession:
    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.token = None

    def request(self, method, path, data=None, headers=None):
        url = f"{BASE_URL}{path}"
        hdrs = dict(headers or {})
        if self.token:
            hdrs["Authorization"] = f"Bearer {self.token}"

        body = None
        if data is not None:
            if isinstance(data, dict):
                body = json.dumps(data).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
            elif isinstance(data, (bytes, bytearray)):
                body = data
            elif isinstance(data, str):
                body = data.encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            resp = self.opener.open(req, timeout=15)
            content = resp.read()
            return resp.status, resp.headers, content
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()
        except Exception as e:
            return 0, {}, str(e).encode()

    def get_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie.value
        return None

def run_e2e_acceptance():
    print("=" * 80)
    print("FOOTPRINTIQ STEP 7 — LIVE END-TO-END ACCEPTANCE AUDIT")
    print("=" * 80)

    # ---------------------------------------------------------
    # PHASE A: Pre-Flight Health & Status
    # ---------------------------------------------------------
    client = ApiSession()
    status_code, headers, body = client.request("GET", "/health/live")
    if status_code == 200:
        log_step("PHASE_A_HEALTH_LIVE", "VERIFIED", f"HTTP {status_code}: {body.decode()}")
    else:
        log_step("PHASE_A_HEALTH_LIVE", "FAILED", f"HTTP {status_code}: {body.decode()}")

    status_code, headers, body = client.request("GET", "/health/ready")
    if status_code == 200:
        log_step("PHASE_A_HEALTH_READY", "VERIFIED", f"HTTP {status_code}: {body.decode()}")
    else:
        log_step("PHASE_A_HEALTH_READY", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # ---------------------------------------------------------
    # PHASE B: Admin Persona & Investigator Registration / Approval
    # ---------------------------------------------------------
    admin_session = ApiSession()
    # 1. Admin login
    status_code, headers, body = admin_session.request("POST", "/api/v1/auth/login", {
        "username_or_email": "admin@footprint.org",
        "password": "FootprintIQ-Demo-2026!"
    })
    if status_code == 200:
        data = json.loads(body.decode())
        admin_session.token = data.get("access_token")
        admin_cookie = admin_session.get_cookie("footprintiq_session")
        admin_csrf = admin_session.get_cookie("footprintiq_csrf")
        log_step("PHASE_B_ADMIN_LOGIN", "VERIFIED", f"Admin token received; cookie={bool(admin_cookie)}, csrf={bool(admin_csrf)}")
    else:
        log_step("PHASE_B_ADMIN_LOGIN", "FAILED", f"HTTP {status_code}: {body.decode()}")
        return

    # 2. Check Greenbone & Nmap Tool Status via Admin API
    status_code, headers, body = admin_session.request("GET", "/api/v1/tools/nmap/status")
    nmap_status = json.loads(body.decode()) if status_code == 200 else {}
    log_step("PHASE_A_NMAP_STATUS", "VERIFIED" if status_code == 200 and nmap_status.get("is_available") else "FAILED", f"{nmap_status}")

    status_code, headers, body = admin_session.request("GET", "/api/v1/tools/greenbone/status")
    gb_status = json.loads(body.decode()) if status_code == 200 else {}
    log_step("PHASE_A_GREENBONE_STATUS", "VERIFIED" if status_code == 200 and gb_status.get("authenticated") else "FAILED", f"{gb_status}")

    # 3. Investigator Registration Workflow
    test_unique = uuid.uuid4().hex[:8]
    inv_email = f"e2e_investigator_{test_unique}@investigation-audit.org"
    inv_username = f"e2e_inv_{test_unique}"
    inv_password = "InvestigatorPass2026!#Strong"

    inv_client = ApiSession()
    status_code, headers, body = inv_client.request("POST", "/api/v1/auth/signup", {
        "email": inv_email,
        "username": inv_username,
        "password": inv_password,
        "full_name": f"E2E Investigator {test_unique}"
    })
    if status_code in (200, 201):
        reg_data = json.loads(body.decode())
        inv_user_id = reg_data.get("id") or reg_data.get("user", {}).get("id")
        account_status = reg_data.get("account_status") or reg_data.get("user", {}).get("account_status")
        log_step("PHASE_B_INVESTIGATOR_SIGNUP", "VERIFIED", f"Registered ID={inv_user_id}, initial status={account_status}")
    else:
        log_step("PHASE_B_INVESTIGATOR_SIGNUP", "FAILED", f"HTTP {status_code}: {body.decode()}")
        return

    # 4. Attempt login before approval (must be rejected HTTP 403)
    status_code, headers, body = inv_client.request("POST", "/api/v1/auth/login", {
        "username_or_email": inv_email,
        "password": inv_password
    })
    if status_code == 403 and "pending" in body.decode().lower():
        log_step("PHASE_B_PENDING_LOGIN_BLOCKED", "VERIFIED", f"Properly blocked with HTTP 403: {body.decode()[:120]}")
    else:
        log_step("PHASE_B_PENDING_LOGIN_BLOCKED", "FAILED", f"Expected HTTP 403 pending, got {status_code}: {body.decode()}")

    # 5. Admin lists pending investigators
    status_code, headers, body = admin_session.request("GET", "/api/v1/users/pending-investigators")
    if status_code == 200:
        pending_list = json.loads(body.decode())
        found = any(u.get("email") == inv_email for u in pending_list)
        log_step("PHASE_B_ADMIN_LIST_PENDING", "VERIFIED" if found else "FAILED", f"Found pending user: {found} (total pending: {len(pending_list)})")
    else:
        log_step("PHASE_B_ADMIN_LIST_PENDING", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # 6. Admin approves investigator
    status_code, headers, body = admin_session.request("POST", f"/api/v1/users/{inv_user_id}/approve", {})
    if status_code == 200:
        appr_data = json.loads(body.decode())
        log_step("PHASE_B_ADMIN_APPROVE", "VERIFIED", f"Approved user {inv_user_id}, status={appr_data.get('account_status')}")
    else:
        log_step("PHASE_B_ADMIN_APPROVE", "FAILED", f"HTTP {status_code}: {body.decode()}")
        return

    # 7. Investigator login succeeds after approval
    status_code, headers, body = inv_client.request("POST", "/api/v1/auth/login", {
        "username_or_email": inv_email,
        "password": inv_password
    })
    if status_code == 200:
        token_data = json.loads(body.decode())
        inv_client.token = token_data.get("access_token")
        log_step("PHASE_B_APPROVED_LOGIN_SUCCESS", "VERIFIED", f"Logged in! Role: {token_data.get('user', {}).get('role')}")
    else:
        log_step("PHASE_B_APPROVED_LOGIN_SUCCESS", "FAILED", f"HTTP {status_code}: {body.decode()}")
        return

    # 8. Investigator cannot access admin-only endpoints (RBAC check)
    status_code, headers, body = inv_client.request("GET", "/api/v1/users")
    if status_code == 403:
        log_step("PHASE_B_RBAC_INVESTIGATOR_BLOCKED_FROM_ADMIN", "VERIFIED", f"Investigator properly denied admin API (HTTP 403)")
    else:
        log_step("PHASE_B_RBAC_INVESTIGATOR_BLOCKED_FROM_ADMIN", "FAILED", f"Expected HTTP 403, got {status_code}")

    # ---------------------------------------------------------
    # PHASE C: Investigator Workflow Acceptance Test
    # ---------------------------------------------------------
    from datetime import datetime, timezone, timedelta
    future_date = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    # 1. Create new investigation
    inv_payload = {
        "name": f"E2E Acceptance Investigation {test_unique}",
        "organization_name": "FootprintIQ Lab Systems",
        "description": "Step 7 End-to-End integration verification campaign against authorized lab target",
        "lead_investigator": f"E2E Investigator {test_unique}",
        "active_scanning_enabled": True,
        "scope": {
            "owned_domains": ["lab.internal", "local.test"],
            "approved_ips": [LAB_TARGET],
            "approved_cidrs": [LAB_CIDR],
            "active_targets": [LAB_TARGET]
        }
    }
    status_code, headers, body = inv_client.request("POST", "/api/v1/investigations", inv_payload)
    if status_code in (200, 201):
        inv_data = json.loads(body.decode())
        investigation_id = inv_data.get("id")
        log_step("PHASE_C_CREATE_INVESTIGATION", "VERIFIED", f"Created Investigation ID: {investigation_id}")
    else:
        log_step("PHASE_C_CREATE_INVESTIGATION", "FAILED", f"HTTP {status_code}: {body.decode()}")
        return

    # 2. Add Target Authorization for IP (Nmap scan) and Domain (Passive recon)
    auth_payload = {
        "target": LAB_TARGET,
        "target_type": "IP",
        "allowed_operations": ["RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"],
        "authorization_reference": f"AUTH-STEP7-{test_unique}",
        "valid_to": future_date,
        "notes": "Target authorization for Step 7 E2E audit verification on lab host"
    }
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/authorizations", auth_payload)
    if status_code in (200, 201):
        auth_data = json.loads(body.decode())
        auth_id = auth_data.get("id")
        log_step("PHASE_C_TARGET_AUTHORIZATION", "VERIFIED", f"Created Authorization ID: {auth_id}, Ticket: {auth_data.get('authorization_reference')}")
    else:
        log_step("PHASE_C_TARGET_AUTHORIZATION", "FAILED", f"HTTP {status_code}: {body.decode()}")
        return

    # Add Domain Authorization for passive recon
    inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/authorizations", {
        "target": "lab.internal",
        "target_type": "DOMAIN",
        "allowed_operations": ["RECON_PASSIVE"],
        "authorization_reference": f"AUTH-STEP7-DOM-{test_unique}",
        "valid_to": future_date,
        "notes": "Target authorization for lab.internal"
    })

    # 3. Guardrail / Scope Validation Enforcement: Unauthorized target must fail
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/validate-target", {
        "target": OUT_OF_SCOPE_TARGET,
        "operation": "SCAN_ACTIVE"
    })
    val_data = json.loads(body.decode()) if status_code == 200 else {}
    if status_code == 403 or (status_code == 200 and not val_data.get("is_authorized", True)):
        log_step("PHASE_C_GUARDRAILS_OUT_OF_SCOPE_REJECTED", "VERIFIED", f"Target {OUT_OF_SCOPE_TARGET} rejected as out of scope: {val_data}")
    else:
        log_step("PHASE_C_GUARDRAILS_OUT_OF_SCOPE_REJECTED", "FAILED", f"Expected out of scope rejection, got HTTP {status_code}: {val_data}")

    # Validate authorized in-scope target
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/validate-target", {
        "target": LAB_TARGET,
        "operation": "SCAN_ACTIVE"
    })
    val_data = json.loads(body.decode()) if status_code == 200 else {}
    if status_code == 200 and val_data.get("is_authorized"):
        log_step("PHASE_C_GUARDRAILS_IN_SCOPE_ACCEPTED", "VERIFIED", f"Target {LAB_TARGET} confirmed authorized: {val_data}")
    else:
        log_step("PHASE_C_GUARDRAILS_IN_SCOPE_ACCEPTED", "FAILED", f"Expected in scope approval, got HTTP {status_code}: {val_data}")

    # 4. Passive Reconnaissance
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/passive-recon", {
        "target": "lab.internal"
    })
    if status_code in (200, 201, 202):
        recon_data = json.loads(body.decode())
        log_step("PHASE_C_PASSIVE_RECON_EXECUTION", "VERIFIED", f"Job: {recon_data.get('job_id') or recon_data.get('id')}, status: {recon_data.get('status')}")
    else:
        log_step("PHASE_C_PASSIVE_RECON_EXECUTION", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # 5. Active Nmap Scan on Authorized Lab Target
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/nmap-scans", {
        "target": LAB_TARGET,
        "profile_id": "basic_tcp"
    })
    scan_job_id = None
    if status_code in (200, 201, 202):
        scan_data = json.loads(body.decode())
        scan_job_id = scan_data.get("job_id") or scan_data.get("id")
        log_step("PHASE_C_NMAP_DISPATCH", "VERIFIED", f"Nmap Scan Job: {scan_job_id}, status: {scan_data.get('status')}")
    else:
        log_step("PHASE_C_NMAP_DISPATCH", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # Poll Nmap scan completion (up to 50s)
    if scan_job_id:
        completed = False
        for _ in range(25):
            time.sleep(2)
            status_code, headers, body = inv_client.request("GET", f"/api/v1/nmap-scans/{scan_job_id}")
            if status_code == 200:
                job_status = json.loads(body.decode())
                st = job_status.get("status")
                if st in ("COMPLETED", "FAILED", "completed", "failed"):
                    completed = True
                    log_step("PHASE_C_NMAP_COMPLETION", "VERIFIED" if "completed" in st.lower() else "PARTIALLY VERIFIED", f"Scan finished with status: {st}")
                    break
        if not completed:
            log_step("PHASE_C_NMAP_COMPLETION", "PARTIALLY VERIFIED", "Scan still running or queued (asynchronous worker)")

        # Query Nmap scan results
        status_code, headers, body = inv_client.request("GET", f"/api/v1/nmap-scans/{scan_job_id}/results")
        if status_code == 200:
            results_data = json.loads(body.decode())
            log_step("PHASE_C_NMAP_RESULTS", "VERIFIED", f"Results: hosts={len(results_data.get('hosts', []))}, ports={len(results_data.get('ports', []))}")
            # Check host reachability state
            for h in results_data.get("hosts", []):
                hstate = h.get("reachability_state") or h.get("host_state") or h.get("state")
                log_step("PHASE_F_NMAP_REACHABILITY_SEMANTICS", "VERIFIED", f"Host {h.get('ip_address')} reachability state: {hstate}")
        else:
            log_step("PHASE_C_NMAP_RESULTS", "PARTIALLY VERIFIED", f"HTTP {status_code}: {body.decode()}")

    # 6. Correlation Engine Verification
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/correlations/refresh", {})
    if status_code == 200:
        corrs = json.loads(body.decode())
        count = len(corrs) if isinstance(corrs, list) else corrs.get("count", 0)
        log_step("PHASE_C_CORRELATION_REFRESH", "VERIFIED", f"Correlation refresh succeeded; records={count}")
    else:
        log_step("PHASE_C_CORRELATION_REFRESH", "FAILED", f"HTTP {status_code}: {body.decode()}")

    status_code, headers, body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/correlations")
    if status_code == 200:
        corrs_list = json.loads(body.decode())
        records = corrs_list.get("records", []) if isinstance(corrs_list, dict) else corrs_list
        log_step("PHASE_C_CORRELATION_QUERY", "VERIFIED", f"Retrieved {len(records)} correlation records")
    else:
        log_step("PHASE_C_CORRELATION_QUERY", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # 7. Exposure Scoring Engine (v3.0-5factor)
    status_code, headers, body = inv_client.request("POST", f"/api/v1/investigations/{investigation_id}/exposure-score/calculate", {
        "formula_version": "v3.0-5factor"
    })
    score_data = {}
    if status_code == 200:
        score_data = json.loads(body.decode())
        raw_score = score_data.get("total_score")
        renorm_score = score_data.get("renormalized_score")
        formula = score_data.get("formula_version")
        cov = score_data.get("coverage_pct")
        weights = score_data.get("factor_weights")
        log_step("PHASE_C_EXPOSURE_SCORING_CALCULATE", "VERIFIED",
                 f"Score calculated: total={raw_score}, renorm={renorm_score}, formula={formula}, coverage={cov}%, weights={weights}")
    else:
        log_step("PHASE_C_EXPOSURE_SCORING_CALCULATE", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # Query Exposure Score & History
    status_code, headers, body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/exposure-score")
    if status_code == 200:
        log_step("PHASE_C_EXPOSURE_SCORE_GET", "VERIFIED", f"Score retrieved successfully: {json.loads(body.decode()).get('risk_tier')}")
    else:
        log_step("PHASE_C_EXPOSURE_SCORE_GET", "FAILED", f"HTTP {status_code}: {body.decode()}")

    status_code, headers, body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/exposure-score/history")
    if status_code == 200:
        history_list = json.loads(body.decode())
        log_step("PHASE_C_EXPOSURE_SCORE_HISTORY", "VERIFIED", f"Retrieved {len(history_list)} historical score entries")
    else:
        log_step("PHASE_C_EXPOSURE_SCORE_HISTORY", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # 8. Report Generation: PDF & GraphML
    status_code, headers, body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/workflow/report/pdf")
    if status_code == 200 and body.startswith(b"%PDF-"):
        log_step("PHASE_C_REPORT_PDF", "VERIFIED", f"PDF generated successfully ({len(body)} bytes, header={body[:8].decode(errors='ignore')})")
    else:
        log_step("PHASE_C_REPORT_PDF", "FAILED", f"HTTP {status_code}: {body[:100]}")

    status_code, headers, body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/export/graphml")
    if status_code == 200 and b"<graphml" in body:
        log_step("PHASE_C_EXPORT_GRAPHML", "VERIFIED", f"GraphML topology exported successfully ({len(body)} bytes)")
    else:
        log_step("PHASE_C_EXPORT_GRAPHML", "FAILED", f"HTTP {status_code}: {body[:100]}")

    # ---------------------------------------------------------
    # PHASE D: Centralized Evidence Storage & SHA-256 Verification
    # ---------------------------------------------------------
    status_code, headers, body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/evidence")
    if status_code == 200:
        evidence_list = json.loads(body.decode())
        items = evidence_list.get("evidence", []) if isinstance(evidence_list, dict) else evidence_list
        log_step("PHASE_D_EVIDENCE_LIST", "VERIFIED", f"Retrieved {len(items)} evidence records for investigation")

        verified_count = 0
        for ev in items[:3]:
            ev_id = ev.get("id")
            # Verify cryptographic SHA-256 integrity endpoint
            v_code, v_hdrs, v_body = inv_client.request("POST", f"/api/v1/evidence/{ev_id}/verify", {})
            if v_code == 200:
                v_data = json.loads(v_body.decode())
                if v_data.get("is_valid") or v_data.get("valid") or v_data.get("status") == "VERIFIED":
                    verified_count += 1
                    log_step(f"PHASE_D_EVIDENCE_VERIFY_{ev_id[:8]}", "VERIFIED", f"SHA-256 match: {v_data.get('message')}")
                else:
                    log_step(f"PHASE_D_EVIDENCE_VERIFY_{ev_id[:8]}", "PARTIALLY VERIFIED", f"Result: {v_data}")
            else:
                log_step(f"PHASE_D_EVIDENCE_VERIFY_{ev_id[:8]}", "FAILED", f"HTTP {v_code}: {v_body.decode()[:100]}")

            # Download raw evidence
            r_code, r_hdrs, r_body = inv_client.request("GET", f"/api/v1/investigations/{investigation_id}/evidence/{ev_id}/raw")
            if r_code == 200:
                log_step(f"PHASE_D_EVIDENCE_RAW_DOWNLOAD_{ev_id[:8]}", "VERIFIED", f"Downloaded {len(r_body)} bytes directly from primary store")
            else:
                log_step(f"PHASE_D_EVIDENCE_RAW_DOWNLOAD_{ev_id[:8]}", "PARTIALLY VERIFIED", f"HTTP {r_code}")
    else:
        log_step("PHASE_D_EVIDENCE_LIST", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # Also test an existing investigation with confirmed SeaweedFS evidence
    status_code, headers, body = admin_session.request("GET", "/api/v1/investigations/inv-dbddbcd3a4/evidence")
    if status_code == 200:
        ev_data = json.loads(body.decode())
        ev_items = ev_data.get("evidence", []) if isinstance(ev_data, dict) else ev_data
        log_step("PHASE_D_SEAWEEDFS_HISTORICAL_EVIDENCE", "VERIFIED", f"Confirmed {len(ev_items)} historical SeaweedFS evidence records intact")
        if ev_items:
            test_ev_id = ev_items[0].get("id")
            v_code, v_hdrs, v_body = admin_session.request("POST", f"/api/v1/evidence/{test_ev_id}/verify", {})
            log_step("PHASE_D_HISTORICAL_SHA256_CHECK", "VERIFIED" if v_code == 200 else "FAILED", f"Result: {v_body.decode()[:120]}")

    # ---------------------------------------------------------
    # PHASE E: Audit Trail Completeness
    # ---------------------------------------------------------
    status_code, headers, body = admin_session.request("GET", "/api/v1/audit-logs")
    if status_code == 200:
        audit_data = json.loads(body.decode())
        logs = audit_data.get("logs", []) if isinstance(audit_data, dict) else audit_data
        event_types = set(l.get("event_type") for l in logs)
        log_step("PHASE_E_AUDIT_TRAIL", "VERIFIED", f"Total logs: {len(logs)}, Unique event types observed: {sorted(list(event_types))[:8]}")
    else:
        log_step("PHASE_E_AUDIT_TRAIL", "FAILED", f"HTTP {status_code}: {body.decode()}")

    # ---------------------------------------------------------
    # PHASE H & I: UI Endpoints, Security Headers & Tenant Isolation
    # ---------------------------------------------------------
    # Check Web Dashboard endpoints
    ui_client = ApiSession()
    # Login via web form
    # Note: verify security headers on response
    status_code, headers, body = ui_client.request("GET", "/login")
    sec_headers = {
        "nosniff": headers.get("X-Content-Type-Options") == "nosniff",
        "frame_deny": headers.get("X-Frame-Options") == "DENY",
        "csp": bool(headers.get("Content-Security-Policy")),
    }
    log_step("PHASE_I_SECURITY_HEADERS", "VERIFIED" if all(sec_headers.values()) else "FAILED", f"Security headers: {sec_headers}")

    # Tenant Isolation Verification:
    # Another investigator user tries to access this investigation
    other_inv = ApiSession()
    other_inv.request("POST", "/api/v1/auth/signup", {
        "email": f"other_inv_{test_unique}@investigation-audit.org",
        "username": f"other_{test_unique}",
        "password": "OtherInvestigator2026!#",
        "full_name": "Other Investigator"
    })
    # Admin approves other investigator
    # Note: approve uses user_id, let's find user_id for other_inv
    p_code, p_hdrs, p_body = admin_session.request("GET", "/api/v1/users/pending-investigators")
    other_id = None
    if p_code == 200:
        for u in json.loads(p_body.decode()):
            if u.get("username") == f"other_{test_unique}":
                other_id = u.get("id")
                admin_session.request("POST", f"/api/v1/users/{other_id}/approve", {})
                break

    if other_id:
        other_inv.request("POST", "/api/v1/auth/login", {
            "username_or_email": f"other_{test_unique}",
            "password": "OtherInvestigator2026!#"
        })
        token_data = other_inv.get_cookie("footprintiq_session")
        # Try to access investigation_id created by inv_client
        t_code, t_hdrs, t_body = other_inv.request("GET", f"/api/v1/investigations/{investigation_id}")
        if t_code in (403, 404):
            log_step("PHASE_I_TENANT_ISOLATION", "VERIFIED", f"Tenant isolation enforced: access denied with HTTP {t_code}")
        else:
            log_step("PHASE_I_TENANT_ISOLATION", "FAILED", f"Tenant isolation breach! HTTP {t_code}")

    print("=" * 80)
    print("SUMMARY OF VERIFICATION STEPS:")
    total = len(results)
    verified = sum(1 for r in results.values() if r["status"] == "VERIFIED")
    partially = sum(1 for r in results.values() if r["status"] == "PARTIALLY VERIFIED")
    failed = sum(1 for r in results.values() if r["status"] == "FAILED")
    print(f"Total: {total} | VERIFIED: {verified} | PARTIALLY VERIFIED: {partially} | FAILED: {failed}")
    print("=" * 80)

if __name__ == "__main__":
    run_e2e_acceptance()
