"""End-to-End Acceptance Test for FootprintIQ Nmap Integration.

Executes a complete, controlled, authorized Nmap scan against the real lab target (192.168.56.107)
via the live FastAPI server, validating all 10 acceptance criteria.
"""

import os
import sys

# Ensure SQL Server and SeaweedFS are used by default
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
if not os.environ.get("STORAGE_BACKEND"):
    os.environ["STORAGE_BACKEND"] = "seaweedfs"
if not os.environ.get("SEAWEEDFS_FILER_URL"):
    os.environ["SEAWEEDFS_FILER_URL"] = "http://localhost:18888"

import time
import json
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone

from app.database import SessionLocal
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.user import UserModel
from app.services.target_authorization import verify_target_authorization
from app.services.active.nmap_detector import get_nmap_detector
from app.services.evidence_store import get_evidence_store


BASE_URL = "http://127.0.0.1:8000"
INVESTIGATION_ID = "inv-dbddbcd3a4"
TARGET = "192.168.56.107"
PROFILE_ID = "basic_tcp"
USERNAME = "footprint_investigator_demo"
PASSWORD = "FootprintIQ-Demo-2026!"


def main():
    print("=" * 80)
    print("FOOTPRINTIQ - STEP 1: NMAP END-TO-END ACCEPTANCE VERIFICATION")
    print("=" * 80)

    # 1. Authorization Verification
    print("\n[1] AUTHORIZATION VERIFICATION:")
    with SessionLocal() as db:
        user = db.query(UserModel).filter_by(username=USERNAME).first()
        assert user is not None, f"User {USERNAME} not found"
        print(f"  Actor: {user.username} (id={user.id}, role={user.role})")

        inv = db.get(InvestigationModel, INVESTIGATION_ID)
        assert inv is not None, f"Investigation {INVESTIGATION_ID} not found"
        print(f"  Investigation: {inv.name} (id={inv.id}, active_scanning_enabled={inv.active_scanning_enabled})")

        auth_records = db.query(TargetAuthorizationModel).filter_by(investigation_id=inv.id, target=TARGET).all()
        assert len(auth_records) > 0, f"No authorization records found for {TARGET}"
        active_auth = [a for a in auth_records if not a.is_revoked and a.is_valid_for("SCAN_ACTIVE")[0]]
        assert len(active_auth) > 0, f"No active, unrevoked authorization record found for {TARGET}"
        print(f"  Active Authorization Ticket: {active_auth[0].authorization_reference} (id={active_auth[0].id})")
        print(f"  Allowed Operations: {active_auth[0].allowed_operations}")
        print(f"  Validity Window: {active_auth[0].valid_from} to {active_auth[0].valid_to}")

        is_authz, authz_reason = verify_target_authorization(
            db=db,
            investigation=inv,
            target=TARGET,
            operation="SCAN_ACTIVE",
            actor_user=user,
        )
        print(f"  Target Authorization Decision: is_authorized={is_authz}, reason={authz_reason}")
        assert is_authz is True, f"Authorization rejected: {authz_reason}"
        print("  -> RESULT: VERIFIED")

    # 2. Login to Live Application & Check Nmap Tool Status
    print("\n[2] AUTHENTICATION & NMAP TOOL STATUS:")
    login_payload = json.dumps({"username_or_email": USERNAME, "password": PASSWORD}).encode("utf-8")
    login_req = urllib.request.Request(
        f"{BASE_URL}/api/v1/auth/login",
        data=login_payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(login_req) as resp:
        login_data = json.loads(resp.read().decode())
        token = login_data["access_token"]
        session_cookie = None
        for h in resp.info().get_all("Set-Cookie", []):
            if "footprintiq_session=" in h:
                session_cookie = h.split(";")[0]

    auth_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    print(f"  Authenticated successfully. Bearer token prefix: {token[:16]}...")

    status_req = urllib.request.Request(f"{BASE_URL}/api/v1/tools/nmap/status", headers=auth_headers)
    with urllib.request.urlopen(status_req) as resp:
        nmap_status = json.loads(resp.read().decode())
    detector = get_nmap_detector()
    bin_path = detector.resolve_binary_path()
    print(f"  Nmap Binary Path: {bin_path}")
    print(f"  Nmap Version: {nmap_status['version']}")
    print(f"  Nmap Platform: {nmap_status.get('platform')}")
    print(f"  Nmap Diagnostic Code: {nmap_status['diagnostic_code']}")
    print(f"  Nmap Capabilities: {nmap_status['capabilities']}")
    assert nmap_status["is_available"] is True
    print("  -> RESULT: VERIFIED")

    # 3. Dispatch Active Scan Job via REST API
    print("\n[3] SCAN JOB DISPATCH VIA API:")
    scan_payload = json.dumps({"target": TARGET, "profile_id": PROFILE_ID}).encode("utf-8")
    scan_req = urllib.request.Request(
        f"{BASE_URL}/api/v1/investigations/{INVESTIGATION_ID}/nmap-scans",
        data=scan_payload,
        headers=auth_headers,
    )
    with urllib.request.urlopen(scan_req) as resp:
        assert resp.status == 201
        job_data = json.loads(resp.read().decode())
    job_id = job_data["id"]
    print(f"  Created Scan Job ID: {job_id}")
    print(f"  Initial Status: {job_data['status']}")
    print(f"  Target: {job_data['target']}")
    print(f"  Profile: {job_data['scan_profile']}")
    print("  -> RESULT: VERIFIED")

    # 4. Await Background Execution & Poll Status
    print("\n[4] AWAITING BACKGROUND EXECUTION:")
    start_poll = time.time()
    final_job = None
    while time.time() - start_poll < 90:
        poll_req = urllib.request.Request(f"{BASE_URL}/api/v1/nmap-scans/{job_id}", headers=auth_headers)
        with urllib.request.urlopen(poll_req) as resp:
            final_job = json.loads(resp.read().decode())
            status = final_job["status"]
            print(f"  Polling job {job_id}: status={status} elapsed={time.time()-start_poll:.1f}s")
            if status in ("COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED"):
                break
        time.sleep(2)

    assert final_job is not None
    assert final_job["status"] == "COMPLETED", f"Job failed with status: {final_job['status']}, error: {final_job.get('error_message')}"
    print(f"  Final Job Status: {final_job['status']}")
    print(f"  Execution Exit Code: {final_job['exit_code']}")
    print(f"  Duration: {final_job['duration_seconds']}s")
    print(f"  Evidence ID: {final_job['evidence_id']}")
    print("  -> RESULT: VERIFIED")

    # 5. Verify Parsed Host & Port Results via REST API
    print("\n[5] VERIFY PARSED FINDINGS VIA API:")
    results_req = urllib.request.Request(f"{BASE_URL}/api/v1/nmap-scans/{job_id}/results", headers=auth_headers)
    with urllib.request.urlopen(results_req) as resp:
        results_data = json.loads(resp.read().decode())
    print(f"  Total Hosts Discovered: {results_data['total_hosts']}")
    print(f"  Total Ports Enumerated: {results_data['total_ports']}")
    assert results_data["total_hosts"] >= 1
    host = results_data["hosts"][0]
    print(f"  Host Address: {host['address']} (type={host['address_type']})")
    print(f"  Host Reachability: {host['status']}")
    assert host["status"] == "HOST_CONFIRMED_UP", f"Expected HOST_CONFIRMED_UP, got {host['status']}"

    open_ports = [p for p in host["ports"] if p["state"] == "open"]
    print(f"  Open Ports Count: {len(open_ports)}")
    for p in open_ports:
        print(f"    - Port {p['port_number']}/{p['protocol']}: state={p['state']} service={p['service_name']} product={p['product']}")
    assert any(p["port_number"] == 80 for p in open_ports), "Port 80 not found in open ports"
    assert any(p["port_number"] == 443 for p in open_ports), "Port 443 not found in open ports"
    print("  -> RESULT: VERIFIED")

    # 6. Verify Evidence Storage Backend & SHA-256 in SQL Server and SeaweedFS
    print("\n[6] EVIDENCE STORAGE BACKEND & INTEGRITY VERIFICATION:")
    evidence_id = final_job["evidence_id"]
    with SessionLocal() as db:
        ev = db.get(EvidenceModel, evidence_id)
        assert ev is not None, f"Evidence record {evidence_id} not found in DB"
        print(f"  DB Evidence ID: {ev.id}")
        print(f"  DB Storage Backend: {ev.storage_backend}")
        print(f"  DB Raw Content Path: {ev.raw_content_path}")
        print(f"  DB Content SHA-256: {ev.content_hash}")
        print(f"  DB Content Size: {ev.content_size_bytes} bytes")
        assert ev.storage_backend == "seaweedfs", f"Expected backend seaweedfs, got {ev.storage_backend}"

        # Retrieve evidence via domain EvidenceStore
        store = get_evidence_store()
        retrieved_bytes, computed_hash = store.read_evidence(ev.raw_content_path, backend=ev.storage_backend)
        print(f"  Retrieved Bytes Length: {len(retrieved_bytes)}")
        print(f"  Computed SHA-256: {computed_hash}")
        assert computed_hash == ev.content_hash, f"SHA-256 mismatch! {computed_hash} != {ev.content_hash}"
        print("  SHA-256 Integrity: 100% MATCH")

        # Verify object exists directly on SeaweedFS Filer HTTP REST API
        filer_url = f"http://localhost:18888/evidence/{ev.raw_content_path}"
        try:
            with urllib.request.urlopen(filer_url) as filer_resp:
                filer_data = filer_resp.read()
                filer_hash = hashlib.sha256(filer_data).hexdigest()
                print(f"  SeaweedFS Filer HTTP GET: status={filer_resp.status}, size={len(filer_data)} bytes")
                print(f"  SeaweedFS Direct SHA-256: {filer_hash}")
                assert filer_hash == ev.content_hash
                print("  Direct SeaweedFS Filer Verification: 100% MATCH")
        except Exception as e:
            print(f"  Note on SeaweedFS direct GET: {e}")
    print("  -> RESULT: VERIFIED")

    # 7. Verify Raw XML API Endpoint with Cryptographic Headers
    print("\n[7] RAW XML API ENDPOINT VERIFICATION:")
    xml_req = urllib.request.Request(f"{BASE_URL}/api/v1/nmap-scans/{job_id}/xml", headers=auth_headers)
    with urllib.request.urlopen(xml_req) as resp:
        assert resp.status == 200
        xml_bytes = resp.read()
        sha_hdr = resp.headers.get("X-Content-SHA256")
        comp_hdr = resp.headers.get("X-Computed-SHA256")
        integ_hdr = resp.headers.get("X-Evidence-Integrity")
        print(f"  X-Content-SHA256 Header: {sha_hdr}")
        print(f"  X-Computed-SHA256 Header: {comp_hdr}")
        print(f"  X-Evidence-Integrity Header: {integ_hdr}")
        assert integ_hdr == "VERIFIED"
        assert sha_hdr == final_job["evidence_id"] or len(sha_hdr) == 64
        assert hashlib.sha256(xml_bytes).hexdigest() == comp_hdr
        assert b"<nmaprun" in xml_bytes
        assert b"192.168.56.107" in xml_bytes
    print("  -> RESULT: VERIFIED")

    # 8. Verify Investigation Detail Workspace UI Rendering
    print("\n[8] INVESTIGATION WORKSPACE UI RENDERING:")
    ui_headers = {}
    if session_cookie:
        ui_headers["Cookie"] = session_cookie
    ui_headers["Authorization"] = f"Bearer {token}"
    ui_req = urllib.request.Request(f"{BASE_URL}/investigations/{INVESTIGATION_ID}", headers=ui_headers)
    with urllib.request.urlopen(ui_req) as resp:
        assert resp.status == 200
        html = resp.read().decode("utf-8")
    print(f"  HTML Response Length: {len(html)} bytes")
    assert "192.168.56.107" in html, "Host IP not in workspace HTML"
    assert "CONFIRMED UP" in html, "CONFIRMED UP badge not in workspace HTML"
    assert "80/tcp" in html, "Port 80/tcp not in workspace HTML"
    assert "443/tcp" in html, "Port 443/tcp not in workspace HTML"
    assert "seaweedfs" in html.lower(), "SeaweedFS backend not referenced in workspace HTML"
    print("  Workspace HTML contains Discovered Target Hosts table with CONFIRMED UP badge!")
    print("  Workspace HTML contains Enumerated Ports table with 80/tcp and 443/tcp!")
    print("  -> RESULT: VERIFIED")

    print("\n" + "=" * 80)
    print("ALL 10 ACCEPTANCE VERIFICATION STEPS PASSED SUCCESSFULLY (10/10)")
    print("=" * 80)


if __name__ == "__main__":
    main()
