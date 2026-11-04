"""Comprehensive unit and factor-level tests for 5-factor ExposureScorer."""

import pytest
from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel, EvidenceModel, CollectionJobModel
from app.models.scan import ScanFindingHostModel, ScanFindingPortModel, ActiveScanJobModel
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.services.scoring.calculator import ExposureScorer


def _make_inv(identifier: str):
    return InvestigationModel(
        id=identifier,
        name=identifier,
        organization_name="TestOrg",
        description="Testing factors",
        lead_investigator="Analyst",
        status="active",
        team_members=[],
        owned_domains=[],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=[],
    )


def test_exposure_scorer_factor_p_public_footprint(db_session):
    """Verifies Public Footprint (P) factor scaling with emails, persons, and documents."""
    inv = _make_inv("inv-score-p-test")
    db_session.add(inv)
    db_session.flush()

    score0 = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score0.P == 0

    # Add emails (12 pts each) and persons (8 pts each)
    db_session.add(EntityModel(
        id="ent-p-1",
        investigation_id=inv.id,
        entity_type="EMAIL",
        canonical_value="admin@example.com",
        original_value="admin@example.com",
    ))
    db_session.add(EntityModel(
        id="ent-p-2",
        investigation_id=inv.id,
        entity_type="PERSON",
        canonical_value="John Doe",
        original_value="John Doe",
    ))
    db_session.flush()

    score1 = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score1.P == 20  # (1 * 12) + (1 * 8) = 20


def test_exposure_scorer_factor_d_domain_hygiene(db_session):
    """Verifies Domain Hygiene (D) factor scaling with subdomains and DMARC penalties."""
    inv = _make_inv("inv-score-d-test")
    db_session.add(inv)
    db_session.flush()

    # Add 2 subdomains (10 pts each = 20)
    db_session.add(EntityModel(
        id="ent-d-1",
        investigation_id=inv.id,
        entity_type="SUBDOMAIN",
        canonical_value="vpn.example.com",
        original_value="vpn.example.com",
    ))
    db_session.add(EntityModel(
        id="ent-d-2",
        investigation_id=inv.id,
        entity_type="SUBDOMAIN",
        canonical_value="mail.example.com",
        original_value="mail.example.com",
    ))
    # Add DNS evidence with missing DMARC (+25 pts)
    db_session.add(EvidenceModel(
        id="ev-dns-1",
        investigation_id=inv.id,
        source_type="dns",
        source_name="dns_collector",
        target="example.com",
        collection_status="SUCCESS",
        content_hash="a" * 64,
        source_metadata={"records": {"A": ["1.2.3.4"]}},
    ))
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.D == 45  # (2 * 10) + 25 = 45


def test_exposure_scorer_factor_s_service_exposure(db_session):
    """Verifies Service Exposure (S) factor scaling and database/admin port penalties."""
    inv = _make_inv("inv-score-s-test")
    db_session.add(inv)
    db_session.flush()

    active_job = ActiveScanJobModel(
        id="job-active-s",
        investigation_id=inv.id,
        requested_by="analyst",
        target="192.168.1.50",
        scan_profile="default",
        status="COMPLETED",
    )
    db_session.add(active_job)
    db_session.flush()

    host = ScanFindingHostModel(
        id="host-s-1",
        investigation_id=inv.id,
        job_id=active_job.id,
        address="192.168.1.50",
        status="up",
    )
    db_session.add(host)
    db_session.flush()

    # Standard open port (14 pts)
    db_session.add(ScanFindingPortModel(
        id="port-s-1",
        host_id=host.id,
        job_id=active_job.id,
        protocol="tcp",
        port_number=443,
        state="open",
    ))
    # Database port (14 base + 20 penalty = 34 pts)
    db_session.add(ScanFindingPortModel(
        id="port-s-2",
        host_id=host.id,
        job_id=active_job.id,
        protocol="tcp",
        port_number=5432,
        state="open",
    ))
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.S == 48  # (2 * 14) + 20 = 48


def test_exposure_scorer_factor_v_vulnerability_severity(db_session):
    """Verifies Vulnerability Severity (V) factor calculation and QoD weighting."""
    inv = _make_inv("inv-score-v-test")
    db_session.add(inv)
    db_session.flush()

    vuln_job = VulnerabilityScanJobModel(
        id="job-vuln-v",
        investigation_id=inv.id,
        requested_by="analyst",
        target="192.168.1.10",
        profile_id="default",
        scan_config_id="full_and_fast",
        status="COMPLETED",
    )
    db_session.add(vuln_job)
    db_session.flush()

    # Critical severity (35 pts, 100% QoD)
    db_session.add(VulnerabilityFindingModel(
        id="vuln-v-1",
        investigation_id=inv.id,
        job_id=vuln_job.id,
        name="Remote Code Execution",
        severity="critical",
        cvss_score=9.8,
        qod=100,
        host="192.168.1.10",
        port=443,
        protocol="tcp",
    ))
    # Medium severity (12 pts, 70% QoD = 8.4 pts)
    db_session.add(VulnerabilityFindingModel(
        id="vuln-v-2",
        investigation_id=inv.id,
        job_id=vuln_job.id,
        name="SSL Weak Cipher",
        severity="medium",
        cvss_score=5.3,
        qod=70,
        host="192.168.1.10",
        port=443,
        protocol="tcp",
    ))
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    # 35 + 8.4 = 43.4 -> round = 43
    assert score.V == 43


def test_exposure_scorer_composite_formula_and_tiers(db_session):
    """Verifies composite 5-factor weighted calculation and tier mapping."""
    inv = _make_inv("inv-score-comp-test")
    db_session.add(inv)
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.total_score == 0
    assert score.tier == "Minimal"
    assert "v3.0-5factor" in score.formula_version
    assert score.assessment_status in ("NOT_ASSESSED", "PARTIAL", "FAILED")


def test_exposure_scorer_historical_vs_current_model_versioning(db_session):
    """Verifies dual-model version support: v1.0-legacy (0.25P + 0.20D + 0.25S + 0.20V + 0.10C)
    versus authoritative current v3.0-5factor (0.20P + 0.15D + 0.25S + 0.35V + 0.05C).
    """
    inv = _make_inv("inv-score-versions-test")
    db_session.add(inv)

    # 1. Add entities for P: 4 emails (48 pts) + 1 document (18 pts) = 66 pts
    for i in range(4):
        db_session.add(EntityModel(id=f"e-p-{i}", investigation_id=inv.id, entity_type="EMAIL", canonical_value=f"user{i}@ex.com", original_value=f"user{i}@ex.com"))
    db_session.add(EntityModel(id="e-p-doc", investigation_id=inv.id, entity_type="DOCUMENT", canonical_value="plan.pdf", original_value="plan.pdf"))

    # 2. Add entities for D: 4 subdomains (40 pts)
    for i in range(4):
        db_session.add(EntityModel(id=f"e-d-{i}", investigation_id=inv.id, entity_type="SUBDOMAIN", canonical_value=f"sub{i}.ex.com", original_value=f"sub{i}.ex.com"))

    # 3. Add ports for S: 1 open database port (14 + 20 = 34 pts)
    active_job = ActiveScanJobModel(id="act-j-v", investigation_id=inv.id, requested_by="admin", target="10.0.0.1", scan_profile="basic_tcp", status="COMPLETED")
    host = ScanFindingHostModel(id="h-v", investigation_id=inv.id, job_id=active_job.id, address="10.0.0.1", status="HOST_CONFIRMED_UP")
    db_session.add(active_job)
    db_session.add(host)
    db_session.add(ScanFindingPortModel(id="p-v-db", host_id=host.id, job_id=active_job.id, protocol="tcp", port_number=3306, state="open"))

    # 4. Add vuln for V: 2 critical vulnerabilities (35 + 35 = 70 pts)
    vuln_job = VulnerabilityScanJobModel(id="v-j-v", investigation_id=inv.id, requested_by="admin", target="10.0.0.1", profile_id="fast", scan_config_id="full_and_fast", status="COMPLETED")
    db_session.add(vuln_job)
    db_session.add(VulnerabilityFindingModel(id="vf-1", investigation_id=inv.id, job_id=vuln_job.id, host="10.0.0.1", name="RCE-1", severity="critical", cvss_score=9.8, qod=100))
    db_session.add(VulnerabilityFindingModel(id="vf-2", investigation_id=inv.id, job_id=vuln_job.id, host="10.0.0.1", name="RCE-2", severity="critical", cvss_score=9.6, qod=100))

    # 5. Add evidence for C: 2 distinct sources (40 pts)
    db_session.add(EvidenceModel(id="ev-c-1", investigation_id=inv.id, source_type="dns", source_name="dns_col", target="ex.com", collection_status="SUCCESS", content_hash="1"*64))
    db_session.add(EvidenceModel(id="ev-c-2", investigation_id=inv.id, source_type="rdap", source_name="rdap_col", target="ex.com", collection_status="SUCCESS", content_hash="2"*64))

    db_session.flush()

    # Calculate under v3.0 (authoritative)
    score_v3 = ExposureScorer.calculate_for_investigation(inv.id, db_session, model_version="v3.0-5factor")
    assert "v3.0-5factor" in score_v3.formula_version
    assert score_v3.components_detail["model_version"] == "v3.0-5factor"

    # Calculate under v1.0-legacy (historical baseline)
    score_v1 = ExposureScorer.calculate_for_investigation(inv.id, db_session, model_version="v1.0-legacy")
    assert "v1.0-legacy" in score_v1.formula_version
    assert score_v1.components_detail["model_version"] == "v1.0-legacy"

    # Factors P, D, S, V, C are identical raw metrics
    assert score_v3.P == score_v1.P == 66
    assert score_v3.D == score_v1.D == 65
    assert score_v3.S == score_v1.S == 34
    assert score_v3.V == score_v1.V == 70
    assert score_v3.C == score_v1.C == 50

    # But composite scores differ because v3.0 weights critical vulnerabilities higher (0.35 vs 0.20)
    # v3.0: 0.20*66 + 0.15*65 + 0.25*34 + 0.35*70 + 0.05*50 = 13.2 + 9.75 + 8.5 + 24.5 + 2.5 = 58.45 -> 58
    # v1.0: 0.25*66 + 0.20*65 + 0.25*34 + 0.20*70 + 0.10*50 = 16.5 + 13.0 + 8.5 + 14.0 + 5.0 = 57.0 -> 57
    assert score_v3.total_score != score_v1.total_score
    assert score_v3.total_score == 58
    assert score_v1.total_score == 57


def test_exposure_scorer_low_observed_exposure_complete_coverage(db_session):
    """Verifies that when all 3 stages run and find minimal or zero issues, coverage is 100% and fully assessed."""
    inv = _make_inv("inv-score-complete-low")
    db_session.add(inv)

    # 1. Passive collection completed, zero entities
    db_session.add(CollectionJobModel(
        id="col-job-1",
        investigation_id=inv.id,
        collector_name="dns",
        target="example.com",
        status="COMPLETED",
    ))
    # 2. Active scan completed, zero open ports
    db_session.add(ActiveScanJobModel(
        id="act-job-1",
        investigation_id=inv.id,
        requested_by="usr-admin",
        target="192.168.1.10",
        scan_profile="basic_tcp",
        status="COMPLETED",
    ))
    # 3. Vuln scan completed, zero vulnerabilities
    db_session.add(VulnerabilityScanJobModel(
        id="vuln-job-1",
        investigation_id=inv.id,
        requested_by="usr-admin",
        target="192.168.1.10",
        profile_id="fast",
        scan_config_id="full_and_fast",
        status="COMPLETED",
    ))
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.total_score == 0
    assert score.tier == "Minimal"
    assert score.assessment_status == "FULL_ASSESSMENT"
    assert score.components_detail["coverage_percentage"] == 100
    assert score.components_detail["is_fully_assessed"] is True
    assert score.components_detail["dimensions_assessed_count"] == 3
    assert score.components_detail["dimension_status"]["passive_recon"] == "NO_FINDINGS_DETECTED"
    assert score.components_detail["dimension_status"]["active_nmap"] == "NO_FINDINGS_DETECTED"
    assert score.components_detail["dimension_status"]["vulnerability_scan"] == "NO_FINDINGS_DETECTED"
    assert len(score.components_detail["coverage_warnings"]) == 0


def test_exposure_scorer_incomplete_assessment_coverage_tracking(db_session):
    """Verifies incomplete assessment (only passive recon executed) is distinguished from low risk."""
    inv = _make_inv("inv-score-incomplete")
    db_session.add(inv)

    # Only passive recon ran and finished
    db_session.add(CollectionJobModel(
        id="col-job-2",
        investigation_id=inv.id,
        collector_name="rdap",
        target="example.com",
        status="COMPLETED",
    ))
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.assessment_status == "PARTIAL"
    assert score.components_detail["coverage_percentage"] == 33
    assert score.components_detail["is_fully_assessed"] is False
    assert score.components_detail["dimensions_assessed_count"] == 1
    assert score.components_detail["dimension_status"]["passive_recon"] == "NO_FINDINGS_DETECTED"
    assert score.components_detail["dimension_status"]["active_nmap"] == "NOT_EXECUTED"
    assert score.components_detail["dimension_status"]["vulnerability_scan"] == "NOT_EXECUTED"
    assert len(score.components_detail["coverage_warnings"]) == 2
    assert "Vulnerability (Greenbone) assessment was not executed" in score.reviewer_notes
    assert "Active network (Nmap) assessment was not executed" in score.reviewer_notes


def test_exposure_scorer_scanner_unavailable_does_not_mask_as_zero_risk(db_session):
    """Verifies that an unavailable scanner (e.g. Greenbone NOT_CONFIGURED) emits explicit warnings."""
    inv = _make_inv("inv-score-unavail")
    db_session.add(inv)

    # Active scan completed
    db_session.add(ActiveScanJobModel(
        id="act-job-2",
        investigation_id=inv.id,
        requested_by="usr-admin",
        target="192.168.1.10",
        scan_profile="basic_tcp",
        status="COMPLETED",
    ))
    # Greenbone vuln scan failed with NOT_CONFIGURED
    db_session.add(VulnerabilityScanJobModel(
        id="vuln-job-2",
        investigation_id=inv.id,
        requested_by="usr-admin",
        target="192.168.1.10",
        profile_id="fast",
        scan_config_id="full_and_fast",
        status="FAILED",
        error_category="NOT_CONFIGURED",
        error_message="Greenbone GVM connection failed: Host or socket not configured.",
    ))
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.assessment_status == "PARTIAL"  # active completed, vuln unavailable
    assert score.components_detail["coverage_percentage"] == 33
    assert score.components_detail["is_fully_assessed"] is False
    assert score.components_detail["dimension_status"]["active_nmap"] == "NO_FINDINGS_DETECTED"
    assert score.components_detail["dimension_status"]["vulnerability_scan"] == "SCANNER_UNAVAILABLE"
    assert score.components_detail["dimension_status"]["passive_recon"] == "NOT_EXECUTED"
    
    # Verify that V=0 is not mistaken for clean vulnerability state
    assert score.V == 0
    warnings = score.components_detail["coverage_warnings"]
    assert any("Vulnerability (Greenbone) scanner was unavailable (NOT_CONFIGURED)" in w for w in warnings)
    assert "[COVERAGE NOTICE]" in score.reviewer_notes

