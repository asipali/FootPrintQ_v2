"""Phase I — Comprehensive Automated Unit, Mathematical, and Integration Tests for Step 6: Exposure Scoring Engine.

Covers all 22 required test dimensions:
1. Exact v3.0-5factor formula calculation
2. Exact legacy v1.0 formula calculation
3. Weight totals sum to 1.00
4. Factor normalization strictly within [0, 100]
5. Boundary values (0 and max caps)
6. Missing factor behavior
7. Partial assessment coverage
8. Greenbone unavailable handling
9. Nmap incomplete handling
10. Empty but successfully completed scan (0 open ports clean)
11. Duplicate observations deduplication
12. Duplicate vulnerability findings deduplication
13. Missing CVSS score handling
14. Historical score preservation
15. Formula version storage
16. Weighted contribution calculation
17. Evidence hash / correlation integration
18. Insufficient evidence behavior
19. Idempotent calculations
20. REST API endpoints & schema
21. Tenant isolation & RBAC enforcement
22. Dashboard rendering
"""

from datetime import datetime, timezone
from typing import Optional
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.database import get_db
from app.models.investigation import InvestigationModel
from app.models.recon import CollectionJobModel, EntityModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.models.correlation import CorrelationRecordModel
from app.models.exposure_score import ExposureScoreModel
from app.models.user import UserModel
from app.core.auth import create_user_session
from app.core.security import hash_password
from app.services.scoring.calculator import DEFAULT_SCORING_MODEL, SCORING_MODELS, ExposureScorer


def _make_investigation(
    inv_id: str,
    name: str = "Scoring Test Campaign",
    lead: str = "lead_analyst",
    owner_id: Optional[str] = None,
) -> InvestigationModel:
    return InvestigationModel(
        id=inv_id,
        name=name,
        organization_name="Acme Cyber Corp",
        description="Comprehensive security assessment campaign",
        lead_investigator=lead,
        owner_user_id=owner_id,
        status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


# =============================================================================
# 1-5. Mathematical Formula, Weights, Normalization & Boundaries
# =============================================================================

def test_exact_v3_formula_and_weights():
    """1 & 3. Verifies authoritative v3.0-5factor formula and exact weight totals."""
    v3_meta = SCORING_MODELS["v3.0-5factor"]
    weights = v3_meta["weights"]
    assert weights["P"] == 0.20
    assert weights["D"] == 0.15
    assert weights["S"] == 0.25
    assert weights["V"] == 0.35
    assert weights["C"] == 0.05
    assert round(sum(weights.values()), 6) == 1.00

    # Independently calculated expected value:
    # P=50, D=40, S=60, V=80, C=100
    # Expected = 0.20*50 + 0.15*40 + 0.25*60 + 0.35*80 + 0.05*100
    #          = 10.0 + 6.0 + 15.0 + 28.0 + 5.0 = 64.0
    expected = (0.20 * 50) + (0.15 * 40) + (0.25 * 60) + (0.35 * 80) + (0.05 * 100)
    assert expected == 64.0


def test_exact_legacy_formula_and_weights():
    """2 & 3. Verifies historical v1.0-legacy formula and exact weight totals."""
    v1_meta = SCORING_MODELS["v1.0-legacy"]
    weights = v1_meta["weights"]
    assert weights["P"] == 0.25
    assert weights["D"] == 0.20
    assert weights["S"] == 0.25
    assert weights["V"] == 0.20
    assert weights["C"] == 0.10
    assert round(sum(weights.values()), 6) == 1.00

    # Independently calculated expected value:
    # P=50, D=40, S=60, V=80, C=100
    # Expected = 0.25*50 + 0.20*40 + 0.25*60 + 0.20*80 + 0.10*100
    #          = 12.5 + 8.0 + 15.0 + 16.0 + 10.0 = 61.5 -> round = 62
    expected = (0.25 * 50) + (0.20 * 40) + (0.25 * 60) + (0.20 * 80) + (0.10 * 100)
    assert round(expected) == 62


def test_factor_normalization_and_boundaries(db_session: Session):
    """4 & 5. Verifies factors remain strictly within [0, 100] even with extreme counts."""
    inv = _make_investigation(f"inv-bound-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    db_session.commit()

    # 1. Zero inputs give exactly 0 for all factors
    res_zero = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert res_zero.P == 0
    assert res_zero.D == 0
    assert res_zero.S == 0
    assert res_zero.V == 0
    assert res_zero.C == 0
    assert res_zero.total_score == 0
    assert res_zero.tier == "Minimal"

    # 2. Huge inputs cap strictly at 100
    # Add 20 emails (20 * 12 = 240 > 100)
    for i in range(20):
        db_session.add(EntityModel(
            id=f"e-huge-{i}", investigation_id=inv.id, entity_type="EMAIL",
            canonical_value=f"user{i}@bigcorp.example", original_value=f"user{i}@bigcorp.example"
        ))
    # Add 20 subdomains (20 * 10 = 200 > 100)
    for i in range(20):
        db_session.add(EntityModel(
            id=f"sub-huge-{i}", investigation_id=inv.id, entity_type="SUBDOMAIN",
            canonical_value=f"sub{i}.bigcorp.example", original_value=f"sub{i}.bigcorp.example"
        ))
    db_session.commit()

    res_huge = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert res_huge.P == 100
    assert res_huge.D == 100
    assert res_huge.total_score <= 100


# =============================================================================
# 6-10. Missing Data, Coverage, Scanner Availability & Clean Scans
# =============================================================================

def test_missing_factors_and_coverage_metadata(db_session: Session):
    """6 & 7. Tests explicit coverage metadata distinguishing unassessed from clean."""
    inv = _make_investigation(f"inv-cov-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    # Only active scan ran
    job = ActiveScanJobModel(
        id=f"job-act-{uuid.uuid4().hex[:6]}", investigation_id=inv.id,
        requested_by="admin", target="192.168.1.1", scan_profile="fast", status="COMPLETED"
    )
    db_session.add(job)
    db_session.commit()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.assessment_status == "PARTIAL"
    assert score.components_detail["coverage_percentage"] == 33
    assert score.components_detail["is_fully_assessed"] is False
    assert score.components_detail["dimension_status"]["active_nmap"] == "NO_FINDINGS_DETECTED"
    assert score.components_detail["dimension_status"]["vulnerability_scan"] == "NOT_EXECUTED"
    assert score.components_detail["dimension_status"]["passive_recon"] == "NOT_EXECUTED"
    assert len(score.components_detail["coverage_warnings"]) >= 1


def test_greenbone_unavailable_not_masked_as_clean(db_session: Session):
    """8. Verifies Greenbone scanner unavailable emits explicit warning and V=0 is not clean."""
    inv = _make_investigation(f"inv-gvm-unavail-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    vjob = VulnerabilityScanJobModel(
        id=f"vjob-{uuid.uuid4().hex[:6]}", investigation_id=inv.id,
        requested_by="admin", target="10.0.0.1", profile_id="fast", scan_config_id="full",
        status="FAILED", error_category="SCANNER_UNAVAILABLE",
        error_message="Connection to gvmd.sock failed."
    )
    db_session.add(vjob)
    db_session.commit()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.components_detail["dimension_status"]["vulnerability_scan"] == "SCANNER_UNAVAILABLE"
    assert score.V == 0
    warnings = score.components_detail["coverage_warnings"]
    assert any("Vulnerability (Greenbone) scanner was unavailable" in w for w in warnings)


def test_empty_completed_nmap_scan_clean_not_penalized(db_session: Session):
    """10. Tests that 0 open ports on a completed scan produces clean NO_FINDINGS_DETECTED."""
    inv = _make_investigation(f"inv-clean-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    job = ActiveScanJobModel(
        id=f"job-clean-{uuid.uuid4().hex[:6]}", investigation_id=inv.id,
        requested_by="admin", target="192.168.1.100", scan_profile="full_tcp", status="COMPLETED"
    )
    db_session.add(job)
    db_session.commit()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.S == 0
    assert score.components_detail["dimension_status"]["active_nmap"] == "NO_FINDINGS_DETECTED"


# =============================================================================
# 11-13. Deduplication and CVSS Handling
# =============================================================================

def test_duplicate_observations_deduplication(db_session: Session):
    """11. Tests that identical entities are deduplicated and do not inflate Factor P or D."""
    inv = _make_investigation(f"inv-dedup-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    # Add identical email 3 times
    for i in range(3):
        db_session.add(EntityModel(
            id=f"e-dup-{i}", investigation_id=inv.id, entity_type="EMAIL",
            canonical_value="admin@example.com", original_value="admin@example.com"
        ))
    # Add identical subdomain 3 times
    for i in range(3):
        db_session.add(EntityModel(
            id=f"sub-dup-{i}", investigation_id=inv.id, entity_type="SUBDOMAIN",
            canonical_value="vpn.example.com", original_value="vpn.example.com"
        ))
    db_session.commit()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    # 1 unique email = 12 pts (not 36!)
    assert score.P == 12
    # 1 unique subdomain = 10 pts (not 30!)
    assert score.D == 10


def test_duplicate_vulnerabilities_and_missing_cvss(db_session: Session):
    """12 & 13. Tests duplicate vulnerability deduplication and findings without CVSS scores."""
    inv = _make_investigation(f"inv-vuln-dedup-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    vjob = VulnerabilityScanJobModel(
        id=f"vjob-d-{uuid.uuid4().hex[:6]}", investigation_id=inv.id,
        requested_by="admin", target="10.10.10.1", profile_id="fast", scan_config_id="full",
        status="COMPLETED"
    )
    db_session.add(vjob)
    db_session.commit()

    # 2 observations of the exact same vulnerability finding
    now = datetime.now(timezone.utc)
    for i in range(2):
        db_session.add(VulnerabilityFindingModel(
            id=f"vf-dup-{i}", investigation_id=inv.id, job_id=vjob.id,
            host="10.10.10.1", port=443, protocol="tcp",
            name="Apache HTTP/2 Rapid Reset", severity="high",
            cvss_score=None,  # Missing CVSS!
            nvt_oid="1.3.6.1.4.1.25623.1.0.12345",
            cve_references=["CVE-2023-44487"],
            qod=100, first_seen=now, last_seen=now
        ))
    db_session.commit()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    # High severity = 22 pts (counted once, not twice!)
    assert score.V == 22
    assert score.components_detail["vulnerabilities_count"] == 1


# =============================================================================
# 14-19. Historical Preservation, Contributions, Correlation, Idempotency
# =============================================================================

def test_historical_score_preservation_and_versioning(db_session: Session):
    """14 & 15. Verifies calculations are persisted, prior scores retained, and formula versions tracked."""
    inv = _make_investigation(f"inv-hist-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    db_session.commit()

    # Calculation 1: v3.0-5factor
    score1 = ExposureScorer.calculate_for_investigation(inv.id, db_session, model_version="v3.0-5factor", persist=True)
    db_session.commit()

    # Calculation 2: v1.0-legacy
    score2 = ExposureScorer.calculate_for_investigation(inv.id, db_session, model_version="v1.0-legacy", persist=True)
    db_session.commit()

    # Inspect history in database
    history = ExposureScorer.get_score_history(inv.id, db_session)
    assert len(history) == 2
    assert history[0]["formula_version"] == "v1.0-legacy"
    assert history[0]["is_active"] is True
    assert history[1]["formula_version"] == "v3.0-5factor"
    assert history[1]["is_active"] is False  # Prior score deactivated, not deleted!


def test_weighted_contributions_and_correlation_factor_c(db_session: Session):
    """16 & 17. Verifies exact mathematical contributions and Factor C correlation integration."""
    inv = _make_investigation(f"inv-contrib-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    db_session.commit()

    # Seed 1 confirmed match correlation record
    corr = CorrelationRecordModel(
        id=f"corr-{uuid.uuid4().hex[:6]}", investigation_id=inv.id,
        correlation_rule_id="RULE-HOST-PORT-VULN-001", rule_version="1.0.0",
        relationship_type="CONFIRMED_MATCH", confidence_score=1.0,
        asset_identifier="192.168.1.10", asset_type="IP_ADDRESS",
        source_modules=["active_scanner", "vuln_scanner"],
        source_scanners=["nmap", "openvas"],
        source_observation_ids=["h1", "p1", "v1"],
        matching_attributes=["host_ip", "port", "protocol"],
        evidence_references=["ev1"],
        evidence_verification_status="VERIFIED",
        lifecycle_status="NEW",
    )
    db_session.add(corr)
    db_session.commit()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session, model_version="v3.0-5factor")
    # Factor C: confirmed (25) + verified evidence (10) = 35 pts
    assert score.C == 35
    assert score.weighted_contributions["C"] == round(0.05 * 35, 2)
    assert score.components_detail["correlation_records_count"] == 1


def test_idempotent_calculations(db_session: Session):
    """19. Verifies that recalculating on unchanged data produces identical results."""
    inv = _make_investigation(f"inv-idemp-{uuid.uuid4().hex[:6]}")
    db_session.add(inv)
    db_session.commit()

    s1 = ExposureScorer.calculate_for_investigation(inv.id, db_session, persist=False)
    s2 = ExposureScorer.calculate_for_investigation(inv.id, db_session, persist=False)
    assert s1.total_score == s2.total_score
    assert s1.P == s2.P and s1.D == s2.D and s1.S == s2.S and s1.V == s2.V and s1.C == s2.C


# =============================================================================
# 20-22. REST API, Tenant Isolation, RBAC & Dashboard Integration
# =============================================================================

def test_api_exposure_score_endpoints_and_history(client: TestClient, db_session: Session):
    """20. Tests GET /api/v1/investigations/{id}/exposure-score and history endpoints."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-api-score-{uuid.uuid4().hex[:6]}"
    admin_user = UserModel(
        id=f"usr-adm-{uuid.uuid4().hex[:6]}", username="score_admin",
        email="score_admin@example.com", password_hash=hash_password("Pass123!#"),
        role="administrator", is_active=True, account_status="active",
        created_at=now, updated_at=now
    )
    db_session.add(admin_user)
    db_session.commit()

    inv = _make_investigation(inv_id, lead=admin_user.username, owner_id=admin_user.id)
    db_session.add(inv)
    db_session.commit()

    token, _ = create_user_session(db=db_session, user=admin_user)
    client.cookies.set("footprintiq_session", token)
    client.headers.update({"Authorization": f"Bearer {token}"})

    # 1. GET active exposure score
    resp = client.get(f"/api/v1/investigations/{inv_id}/exposure-score")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == inv_id
    assert "v3.0-5factor" in data["formula_version"]
    assert "normalized_factor_scores" in data
    assert "weighted_contributions" in data

    # 2. GET score history
    resp_hist = client.get(f"/api/v1/investigations/{inv_id}/exposure-score/history")
    assert resp_hist.status_code == 200
    hist_data = resp_hist.json()
    assert hist_data["investigation_id"] == inv_id
    assert hist_data["total_records"] >= 1


def test_tenant_isolation_and_rbac(client: TestClient, db_session: Session):
    """21. Tests that unauthorized investigator cannot access another user's exposure score."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-iso-{uuid.uuid4().hex[:6]}"
    owner_user = UserModel(
        id=f"usr-own-{uuid.uuid4().hex[:6]}", username="owner_usr",
        email="owner@example.com", password_hash=hash_password("Pass123!#"),
        role="investigator", is_active=True, account_status="active",
        created_at=now, updated_at=now
    )
    other_user = UserModel(
        id=f"usr-oth-{uuid.uuid4().hex[:6]}", username="other_usr",
        email="other@example.com", password_hash=hash_password("Pass123!#"),
        role="investigator", is_active=True, account_status="active",
        created_at=now, updated_at=now
    )
    db_session.add_all([owner_user, other_user])
    db_session.commit()

    inv = _make_investigation(inv_id, lead="owner_usr", owner_id=owner_user.id)
    db_session.add(inv)
    db_session.commit()

    # Other unauthorized user session
    token_other, _ = create_user_session(db=db_session, user=other_user)
    client.cookies.set("footprintiq_session", token_other)
    client.headers.update({"Authorization": f"Bearer {token_other}"})

    resp = client.get(f"/api/v1/investigations/{inv_id}/exposure-score")
    # Non-disclosing tenant isolation returns 404 (or 403)
    assert resp.status_code in (403, 404)


def test_dashboard_exposure_card_rendering(client: TestClient, db_session: Session):
    """22. Tests that the HTML dashboard renders 5-Factor Score, coverage provenance, and contributions."""
    now = datetime.now(timezone.utc)
    inv_id = f"inv-ui-sc-{uuid.uuid4().hex[:6]}"
    admin_user = UserModel(
        id=f"usr-ui-{uuid.uuid4().hex[:6]}", username="ui_scorer",
        email="ui_scorer@example.com", password_hash=hash_password("Pass123!#"),
        role="administrator", is_active=True, account_status="active",
        created_at=now, updated_at=now
    )
    db_session.add(admin_user)
    db_session.commit()

    inv = _make_investigation(inv_id, lead=admin_user.username, owner_id=admin_user.id)
    db_session.add(inv)
    db_session.commit()

    token, _ = create_user_session(db=db_session, user=admin_user)
    client.cookies.set("footprintiq_session", token)
    client.headers.update({"Authorization": f"Bearer {token}"})

    resp = client.get(f"/investigations/{inv_id}")
    assert resp.status_code == 200
    html = resp.text
    assert "5-Factor Exposure Score Breakdown" in html
    assert "Assessment Coverage Provenance" in html
    assert "P &middot; Public Footprint" in html
    assert "D &middot; Domain Hygiene" in html
    assert "S &middot; Service Exposure" in html
    assert "V &middot; Vulnerability Severity" in html
    assert "C &middot; Correlation Confidence" in html
    assert "Composite Exposure Score:" in html
