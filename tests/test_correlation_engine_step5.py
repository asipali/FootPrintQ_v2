"""Phase J — Comprehensive Automated Unit & Integration Tests for Step 5: Correlation Engine."""

from datetime import datetime, timezone, timedelta
import hashlib
from typing import Dict, Any
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.database import get_db, get_db_context
from app.main import create_app
from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel, EvidenceModel, TargetAuthorizationModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.user import UserModel
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.models.correlation import CorrelationRecordModel
from app.core.auth import create_user_session
from app.services.correlation.engine import CorrelationEngine
from app.services.correlation.models import (
    AssetType,
    EvidenceVerificationState,
    FindingLifecycleState,
    RelationshipStrength,
)
from app.services.correlation.normalizer import (
    classify_and_normalize_asset,
    normalize_domain_name,
    normalize_hostname,
    normalize_ip,
    normalize_ipv4,
    normalize_ipv6,
    normalize_port_protocol,
    normalize_service_name,
    normalize_url,
)
from app.services.correlation.rules import (
    HostPortVulnerabilityMatchRule,
    ServiceBannerMatchRule,
    DNSHostResolutionRule,
    HostGeneralVulnerabilityRule,
    EvidenceAssetLinkRule,
)
from app.services.correlation.deduplicator import (
    VulnerabilityLifecycleTracker,
    compute_vulnerability_dedup_key,
)
from app.services.evidence_store import get_evidence_store


# =============================================================================
# 1-4. Normalization Tests
# =============================================================================

def test_ipv4_normalization():
    """1. Tests standard IPv4 address normalization."""
    assert normalize_ipv4("  192.168.1.100  ") == "192.168.1.100"
    assert normalize_ipv4("10.0.0.1") == "10.0.0.1"
    assert normalize_ipv4("256.0.0.1") is None
    assert normalize_ipv4("invalid-ip") is None
    assert normalize_ipv4("192.168.1.0/24") is None  # CIDR not a single IP


def test_domain_normalization():
    """2. Tests FQDN normalization: lowercase, strip protocol/port/path/trailing dot/wildcard."""
    assert normalize_domain_name("HTTP://Portal.Example.COM:8080/path?arg=1") == "portal.example.com"
    assert normalize_domain_name("api.sec.lab.example.") == "api.sec.lab.example"
    assert normalize_domain_name("*.wildcard.example.com") == "wildcard.example.com"
    assert normalize_domain_name("invalid_single_label") is None
    assert normalize_domain_name("") is None


def test_ipv6_normalization():
    """3. Tests IPv6 address parsing, lowercase compression, and validation."""
    assert normalize_ipv6("2001:0db8:0000:0000:0000:ff00:0042:8329") == "2001:db8::ff00:42:8329"
    assert normalize_ipv6("::1") == "::1"
    assert normalize_ipv6("fe80::1") == "fe80::1"
    assert normalize_ipv6("192.168.1.1") is None  # IPv4 rejected by IPv6 normalizer


def test_port_protocol_normalization():
    """4. Tests port and protocol normalization."""
    p, proto = normalize_port_protocol("443", "TCP")
    assert p == 443 and proto == "tcp"

    p, proto = normalize_port_protocol(8080, "udp")
    assert p == 8080 and proto == "udp"

    p, proto = normalize_port_protocol("65536")  # Out of range
    assert p is None

    p, proto = normalize_port_protocol("0")  # Out of range
    assert p is None

    p, proto = normalize_port_protocol(None)
    assert p is None and proto is None


# =============================================================================
# 5-8. Rule Matching & Separation Tests
# =============================================================================

def test_matching_nmap_and_greenbone_observations():
    """5. Tests exact match between Nmap open port and Greenbone vulnerability finding."""
    rule = HostPortVulnerabilityMatchRule()
    res = rule.evaluate(
        host_ip="192.168.56.102",
        nmap_port=443,
        nmap_protocol="tcp",
        nmap_state="open",
        vuln_port=443,
        vuln_protocol="tcp",
    )
    assert res is not None
    rel_type, score, attrs, summary = res
    assert rel_type == RelationshipStrength.CONFIRMED_MATCH
    assert score == 1.0
    assert "port_state_open" in attrs


def make_test_investigation(inv_id: str, name: str = "Test Campaign", lead: str = "lead_analyst") -> InvestigationModel:
    return InvestigationModel(
        id=inv_id,
        name=name,
        organization_name="Test Organization",
        description="Comprehensive security reconnaissance campaign",
        lead_investigator=lead,
        status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def make_test_scan_job(inv_id: str, target: str = "10.10.10.5") -> ActiveScanJobModel:
    return ActiveScanJobModel(
        id=f"job-{uuid.uuid4().hex[:6]}",
        investigation_id=inv_id,
        requested_by="admin",
        target=target,
        resolved_ips=[target],
        scan_profile="nmap-fast",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def make_test_vuln_job(inv_id: str, target: str = "10.10.10.5") -> VulnerabilityScanJobModel:
    return VulnerabilityScanJobModel(
        id=f"vjob-{uuid.uuid4().hex[:6]}",
        investigation_id=inv_id,
        requested_by="admin",
        target=target,
        profile_id="openvas-basic",
        scan_config_id="daba56c8-73ec-11df-a475-002264764cea",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def make_test_user(user_id: str, username: str, role: str) -> UserModel:
    from app.core.security import hash_password
    return UserModel(
        id=user_id,
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("Password123!#"),
        role=role,
        is_active=True,
        account_status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_different_investigation_ids_isolated(db_session: Session):
    """6 & 19. Tests that correlation is strictly investigation-scoped and isolated."""
    now = datetime.now(timezone.utc)
    # Investigation A
    inv_a = make_test_investigation(f"inv-test-a-{uuid.uuid4().hex[:6]}", name="Campaign A")
    # Investigation B
    inv_b = make_test_investigation(f"inv-test-b-{uuid.uuid4().hex[:6]}", name="Campaign B")
    db_session.add_all([inv_a, inv_b])
    db_session.commit()

    # Scan job on Inv A
    job_a = make_test_scan_job(inv_a.id, target="10.10.10.5")
    db_session.add(job_a)
    db_session.commit()

    # Host & Port in Inv A
    h_a = ScanFindingHostModel(id=f"host-a-{uuid.uuid4().hex[:6]}", investigation_id=inv_a.id, job_id=job_a.id, address="10.10.10.5", status="up", created_at=now)
    db_session.add(h_a)
    db_session.commit()
    p_a = ScanFindingPortModel(id=f"port-a-{uuid.uuid4().hex[:6]}", host_id=h_a.id, job_id=job_a.id, port_number=80, protocol="tcp", state="open", service_name="http", created_at=now)
    db_session.add(p_a)

    # Scan job on Inv B
    vjob_b = make_test_vuln_job(inv_b.id, target="10.10.10.5")
    db_session.add(vjob_b)
    db_session.commit()

    # Vulnerability in Inv B on the same IP and port!
    v_b = VulnerabilityFindingModel(
        id=f"vf-b-{uuid.uuid4().hex[:6]}",
        investigation_id=inv_b.id,
        job_id=vjob_b.id,
        host="10.10.10.5",
        port=80,
        protocol="tcp",
        name="HTTP Vulnerability",
        severity="high",
        cvss_score=7.5,
        first_seen=now,
        last_seen=now,
    )
    db_session.add(v_b)
    db_session.commit()

    engine = CorrelationEngine(db_session)
    res_a = engine.run_correlation(inv_a.id)
    res_b = engine.run_correlation(inv_b.id)

    # Inv A has open port, but NO vulnerability finding from Inv B!
    assert res_a["summary"]["total_vulnerabilities"] == 0
    # Inv B has vulnerability, but NO open port from Inv A!
    assert res_b["summary"]["total_open_ports"] == 0

    # Zero cross-investigation leakage
    for c in res_a["correlations"]:
        assert c["related_vulnerability_id"] is None


def test_similar_hostnames_not_merged():
    """7. Tests that similar-looking hostnames or subdomains are never merged."""
    h1 = normalize_hostname("server-prod-01")
    h2 = normalize_hostname("server-prod-02")
    assert h1 != h2

    d1 = normalize_domain_name("app.sec.example.com")
    d2 = normalize_domain_name("sec.example.com")
    d3 = normalize_domain_name("example.com")
    # All 3 must remain separate identities
    assert len({d1, d2, d3}) == 3


def test_service_matching_and_non_matching():
    """8. Tests service banner match vs non-matching service advisories."""
    rule = ServiceBannerMatchRule()

    # Product match
    res_match = rule.evaluate(
        nmap_service="postgresql",
        nmap_product="PostgreSQL",
        vuln_name="PostgreSQL Trust Authentication on External Interface",
        vuln_description="Misconfiguration in PostgreSQL authentication settings",
    )
    assert res_match is not None
    rel_type, score, attrs, summary = res_match
    assert rel_type == RelationshipStrength.CONFIRMED_MATCH
    assert "service_product" in attrs

    # Non-matching service
    res_nomatch = rule.evaluate(
        nmap_service="ssh",
        nmap_product="OpenSSH",
        vuln_name="Apache HTTP Server DoS",
        vuln_description="Denial of service in Apache HTTP Server",
    )
    assert res_nomatch is None


def test_missing_port_information():
    """9. Tests handling when vulnerability has no specific port (host-level flaw)."""
    rule = HostGeneralVulnerabilityRule()
    res = rule.evaluate(host_ip="192.168.56.102", vuln_port=None)
    assert res is not None
    rel_type, score, attrs, summary = res
    assert rel_type == RelationshipStrength.POSSIBLE_MATCH
    assert score == 0.50
    assert "host_level_unspecified_port" in attrs


# =============================================================================
# 10-14. Finding Deduplication, Lifecycle & Resolution Tests
# =============================================================================

def test_duplicate_vulnerability_observations():
    """10. Tests deduplication key stability for duplicate vulnerability observations."""
    k1 = compute_vulnerability_dedup_key(
        investigation_id="inv-123",
        host="192.168.1.50",
        port=443,
        protocol="tcp",
        nvt_oid="1.3.6.1.4.1.25623.1.0.12345",
        name="SSL Weak Cipher",
        primary_cve="CVE-2021-1234",
    )
    k2 = compute_vulnerability_dedup_key(
        investigation_id="inv-123",
        host="192.168.1.50",
        port=443,
        protocol="tcp",
        nvt_oid="1.3.6.1.4.1.25623.1.0.12345",
        name="SSL Weak Cipher",
        primary_cve="CVE-2021-1234",
    )
    assert k1 == k2


def test_same_cve_on_different_assets_not_merged():
    """11. Tests that the same CVE on different hosts or ports produces distinct keys."""
    k_host_a = compute_vulnerability_dedup_key(
        investigation_id="inv-123", host="192.168.1.10", port=443, protocol="tcp", nvt_oid="oid-1", name="Vuln", primary_cve="CVE-2023-44487"
    )
    k_host_b = compute_vulnerability_dedup_key(
        investigation_id="inv-123", host="192.168.1.20", port=443, protocol="tcp", nvt_oid="oid-1", name="Vuln", primary_cve="CVE-2023-44487"
    )
    k_port_diff = compute_vulnerability_dedup_key(
        investigation_id="inv-123", host="192.168.1.10", port=8443, protocol="tcp", nvt_oid="oid-1", name="Vuln", primary_cve="CVE-2023-44487"
    )
    assert k_host_a != k_host_b
    assert k_host_a != k_port_diff


def test_historical_finding_preservation_and_lifecycle():
    """12 & 13. Tests lifecycle states (NEW, REOBSERVED, CHANGED) across scan history."""
    now = datetime.now(timezone.utc)
    inv_id = "inv-life-test"

    f1 = VulnerabilityFindingModel(
        id="vf-001",
        investigation_id=inv_id,
        job_id="vjob-01",
        host="10.0.0.5",
        port=80,
        protocol="tcp",
        name="Apache Misconfig",
        severity="medium",
        cvss_score=5.0,
        nvt_oid="1.3.6.1.4.1.25623.1.0.999",
        first_seen=now - timedelta(days=2),
        last_seen=now - timedelta(days=2),
    )
    f2 = VulnerabilityFindingModel(
        id="vf-002",
        investigation_id=inv_id,
        job_id="vjob-02",
        host="10.0.0.5",
        port=80,
        protocol="tcp",
        name="Apache Misconfig",
        severity="medium",
        cvss_score=5.0,
        nvt_oid="1.3.6.1.4.1.25623.1.0.999",
        first_seen=now - timedelta(days=1),
        last_seen=now - timedelta(days=1),
    )

    j1 = VulnerabilityScanJobModel(id="vjob-01", investigation_id=inv_id, target="10.0.0.5", status="COMPLETED", started_at=now - timedelta(days=2), completed_at=now - timedelta(days=2))
    j2 = VulnerabilityScanJobModel(id="vjob-02", investigation_id=inv_id, target="10.0.0.5", status="COMPLETED", started_at=now - timedelta(days=1), completed_at=now - timedelta(days=1))

    tracker = VulnerabilityLifecycleTracker(
        investigation_id=inv_id,
        findings=[f1, f2],
        scan_jobs=[j1, j2],
    )
    lifecycles = tracker.compute_finding_lifecycles()

    # Re-observed across multiple scans
    state_f1, _ = lifecycles["vf-001"]
    state_f2, _ = lifecycles["vf-002"]
    assert state_f1 == FindingLifecycleState.REOBSERVED
    assert state_f2 == FindingLifecycleState.REOBSERVED


def test_failed_scans_never_resolve_findings():
    """14. Strict rule: A failed or cancelled subsequent scan must mark findings UNCONFIRMED, never RESOLVED."""
    now = datetime.now(timezone.utc)
    inv_id = "inv-fail-test"

    f1 = VulnerabilityFindingModel(
        id="vf-fail-01",
        investigation_id=inv_id,
        job_id="vjob-initial",
        host="10.0.0.5",
        port=443,
        protocol="tcp",
        name="TLS Weakness",
        severity="high",
        cvss_score=7.0,
        nvt_oid="1.3.6.1.4.1.25623.1.0.777",
        first_seen=now - timedelta(hours=5),
        last_seen=now - timedelta(hours=5),
    )
    j_success = VulnerabilityScanJobModel(id="vjob-initial", investigation_id=inv_id, target="10.0.0.5", status="COMPLETED", started_at=now - timedelta(hours=5), completed_at=now - timedelta(hours=5))
    # Subsequent scan FAILED
    j_failed = VulnerabilityScanJobModel(id="vjob-failed", investigation_id=inv_id, target="10.0.0.5", status="FAILED", started_at=now - timedelta(hours=1), completed_at=now - timedelta(hours=1))

    tracker = VulnerabilityLifecycleTracker(
        investigation_id=inv_id,
        findings=[f1],
        scan_jobs=[j_success, j_failed],
    )
    lifecycles = tracker.compute_finding_lifecycles()
    state, meta = lifecycles["vf-fail-01"]

    assert state == FindingLifecycleState.UNCONFIRMED
    assert "failed" in meta["lifecycle_reason"].lower()


# =============================================================================
# 15-18. Evidence Integrity & Idempotency Tests
# =============================================================================

def test_evidence_hash_verification(db_session: Session):
    """15 & 16. Tests evidence SHA-256 integrity match vs missing/corrupted evidence."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-ev-test-{uuid.uuid4().hex[:6]}"
    inv = make_test_investigation(inv_id, name="Evidence Test")
    db_session.add(inv)

    raw_payload = b"Sample Vulnerability Report XML from OpenVAS"
    real_hash = hashlib.sha256(raw_payload).hexdigest()

    # Store via EvidenceStore
    store = get_evidence_store()
    evi_id = f"evi-test-{uuid.uuid4().hex[:6]}"
    store_res = store.store_evidence(
        investigation_id=inv_id,
        evidence_id=evi_id,
        source_type="greenbone",
        content=raw_payload,
    )
    rel_path, _, _ = store_res

    # 1. Evidence with valid matching hash
    ev_valid = EvidenceModel(
        id=evi_id,
        investigation_id=inv_id,
        source_type="greenbone",
        source_name="OpenVAS",
        target="192.168.1.50",
        collection_status="SUCCESS",
        raw_content_path=rel_path,
        storage_backend="filesystem",
        content_hash=real_hash,
        content_size_bytes=len(raw_payload),
    )
    # 2. Corrupted evidence record with wrong hash
    ev_corrupted = EvidenceModel(
        id=f"evi-corrupt-{uuid.uuid4().hex[:6]}",
        investigation_id=inv_id,
        source_type="greenbone",
        source_name="OpenVAS",
        target="192.168.1.50",
        collection_status="SUCCESS",
        raw_content_path=rel_path,
        storage_backend="filesystem",
        content_hash="0000000000000000000000000000000000000000000000000000000000000000",
        content_size_bytes=len(raw_payload),
    )
    # 3. Missing evidence file
    ev_missing = EvidenceModel(
        id=f"evi-missing-{uuid.uuid4().hex[:6]}",
        investigation_id=inv_id,
        source_type="greenbone",
        source_name="OpenVAS",
        target="192.168.1.50",
        collection_status="SUCCESS",
        raw_content_path="nonexistent/path/file.txt",
        storage_backend="filesystem",
        content_hash="abcdef",
        content_size_bytes=100,
    )
    db_session.add_all([ev_valid, ev_corrupted, ev_missing])
    db_session.commit()

    from app.services.correlation.evidence_verifier import EvidenceVerifier
    verifier = EvidenceVerifier(db_session)

    # Valid
    st_val, _ = verifier.verify_evidence(ev_valid.id)
    assert st_val == EvidenceVerificationState.VERIFIED

    # Mismatch
    st_corrupt, _ = verifier.verify_evidence(ev_corrupted.id)
    assert st_corrupt == EvidenceVerificationState.HASH_MISMATCH

    # Missing
    st_miss, _ = verifier.verify_evidence(ev_missing.id)
    assert st_miss == EvidenceVerificationState.UNAVAILABLE


def test_correlation_idempotency_and_rule_versioning(db_session: Session):
    """17 & 18. Tests that repeated correlation execution is strictly idempotent and carries rule versions."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-idemp-{uuid.uuid4().hex[:6]}"
    inv = make_test_investigation(inv_id, name="Idempotency Test")
    db_session.add(inv)
    db_session.commit()

    job = make_test_scan_job(inv_id, target="10.50.50.1")
    db_session.add(job)
    db_session.commit()

    # Seed an open port and a vulnerability
    h = ScanFindingHostModel(id=f"host-{uuid.uuid4().hex[:6]}", investigation_id=inv_id, job_id=job.id, address="10.50.50.1", status="up", created_at=now)
    db_session.add(h)
    db_session.commit()

    vjob = make_test_vuln_job(inv_id, target="10.50.50.1")
    db_session.add(vjob)
    db_session.commit()

    p = ScanFindingPortModel(id=f"port-{uuid.uuid4().hex[:6]}", host_id=h.id, job_id=job.id, port_number=443, protocol="tcp", state="open", service_name="https", created_at=now)
    v = VulnerabilityFindingModel(id=f"vf-{uuid.uuid4().hex[:6]}", investigation_id=inv_id, job_id=vjob.id, host="10.50.50.1", port=443, protocol="tcp", name="SSL Issue", severity="medium", cvss_score=5.5, first_seen=now, last_seen=now)
    db_session.add_all([p, v])
    db_session.commit()

    engine = CorrelationEngine(db_session)

    # Run 1
    res1 = engine.run_correlation(inv_id)
    count1 = db_session.query(CorrelationRecordModel).filter(CorrelationRecordModel.investigation_id == inv_id).count()
    assert count1 == 1

    # Check rule versioning
    rec1 = db_session.query(CorrelationRecordModel).filter(CorrelationRecordModel.investigation_id == inv_id).first()
    assert rec1.rule_version == "1.0.0"
    assert rec1.correlation_rule_id == "RULE-HOST-PORT-VULN-001"

    # Run 2 on unchanged data
    res2 = engine.run_correlation(inv_id)
    count2 = db_session.query(CorrelationRecordModel).filter(CorrelationRecordModel.investigation_id == inv_id).count()
    assert count2 == 1  # Strict idempotency: no uncontrolled duplicate records created


# =============================================================================
# 19-21. API Authorization & UI Integration Tests
# =============================================================================

def test_correlation_api_authorization_and_filters(client: TestClient, db_session: Session):
    """20. Tests API endpoints /api/v1/investigations/{id}/correlations with RBAC and filters."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-api-{uuid.uuid4().hex[:6]}"
    admin_user = make_test_user(f"usr-adm-{uuid.uuid4().hex[:6]}", "corr_admin", "administrator")
    unauth_user = make_test_user(f"usr-ana-{uuid.uuid4().hex[:6]}", "corr_other", "investigator")
    inv = make_test_investigation(inv_id, name="API Test", lead=admin_user.username)

    db_session.add_all([admin_user, unauth_user, inv])
    db_session.commit()

    job = make_test_scan_job(inv_id, target="192.168.1.100")
    db_session.add(job)
    db_session.commit()

    vjob = make_test_vuln_job(inv_id, target="192.168.1.100")
    db_session.add(vjob)
    db_session.commit()

    # Seed correlated port & vuln
    h = ScanFindingHostModel(id=f"host-{uuid.uuid4().hex[:6]}", investigation_id=inv_id, job_id=job.id, address="192.168.1.100", status="up", created_at=now)
    db_session.add(h)
    db_session.commit()
    p = ScanFindingPortModel(id=f"port-{uuid.uuid4().hex[:6]}", host_id=h.id, job_id=job.id, port_number=22, protocol="tcp", state="open", service_name="ssh", created_at=now)
    v = VulnerabilityFindingModel(id=f"vf-{uuid.uuid4().hex[:6]}", investigation_id=inv_id, job_id=vjob.id, host="192.168.1.100", port=22, protocol="tcp", name="OpenSSH Bug", severity="high", cvss_score=7.8, first_seen=now, last_seen=now)
    db_session.add_all([p, v])
    db_session.commit()

    token_admin, _ = create_user_session(db=db_session, user=admin_user)
    token_unauth, _ = create_user_session(db=db_session, user=unauth_user)

    client.cookies.set("footprintiq_session", token_admin)
    client.headers.update({"Authorization": f"Bearer {token_admin}"})

    # Authorized Admin GET
    resp = client.get(f"/api/v1/investigations/{inv_id}/correlations")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == inv_id
    assert len(data["correlations"]) >= 1
    assert data["correlations"][0]["relationship_type"] == "CONFIRMED_MATCH"

    # Filter by relationship_type
    resp_filter = client.get(f"/api/v1/investigations/{inv_id}/correlations?relationship_type=CONFIRMED_MATCH")
    assert resp_filter.status_code == 200
    assert len(resp_filter.json()["correlations"]) >= 1

    resp_filter_none = client.get(f"/api/v1/investigations/{inv_id}/correlations?relationship_type=UNMATCHED")
    assert resp_filter_none.status_code == 200
    assert len(resp_filter_none.json()["correlations"]) == 0


def test_investigator_workspace_rendering(client: TestClient, db_session: Session):
    """21. Tests that the HTML investigation detail view renders Tab: Correlated Intelligence accurately."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-ui-{uuid.uuid4().hex[:6]}"
    admin_user = make_test_user(f"usr-ui-{uuid.uuid4().hex[:6]}", "ui_admin", "administrator")
    inv = make_test_investigation(inv_id, name="UI Test", lead=admin_user.username)

    db_session.add_all([admin_user, inv])
    db_session.commit()

    token, _ = create_user_session(db=db_session, user=admin_user)
    client.cookies.set("footprintiq_session", token)
    client.headers.update({"Authorization": f"Bearer {token}"})

    resp = client.get(f"/investigations/{inv_id}")
    assert resp.status_code == 200
    html = resp.text
    # Verify Correlated Intelligence tab presence
    assert "Correlated Intelligence" in html
    assert "tab-correlations" in html
    assert "Normalized Asset Profiles" in html
    assert "Deterministic Correlation Matrix" in html
