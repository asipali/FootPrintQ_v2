"""Regression coverage for evidence integrity, page scope, and score status."""

from app.models.investigation import InvestigationModel
from app.models.recon import CollectionJobModel, EvidenceModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.services.scoring.calculator import ExposureScorer


def _investigation(identifier, owner=None):
    return InvestigationModel(
        id=identifier, name=identifier, organization_name="Test Org", description="test",
        lead_investigator="Analyst", owner_user_id=owner, team_members=[], status="active",
        owned_domains=[], approved_ips=[], approved_cidrs=[], active_targets=[],
        active_scanning_enabled=False,
    )


def test_exposure_score_distinguishes_unassessed_from_completed_clean(db_session):
    inv = _investigation("inv-score-status")
    db_session.add(inv)
    db_session.flush()

    unassessed = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert unassessed.total_score == 0
    assert unassessed.assessment_status == "NOT_ASSESSED"

    db_session.add(CollectionJobModel(
        id="job-score-status", investigation_id=inv.id, target="example.invalid",
        collector_name="dns", status="COMPLETED", result_summary={},
    ))
    db_session.flush()
    assessed = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert assessed.total_score == 0
    assert assessed.assessment_status == "PARTIAL"


def test_score_deduplicates_equivalent_findings_and_bounds_qod(db_session):
    inv = _investigation("inv-score-dedupe")
    db_session.add(inv)
    db_session.flush()
    db_session.add(VulnerabilityScanJobModel(
        id="job-score-dedupe", investigation_id=inv.id, requested_by="test",
        target="192.0.2.1", profile_id="fixture", scan_config_id="fixture",
        status="COMPLETED",
    ))
    db_session.flush()
    base = dict(
        investigation_id=inv.id, job_id="job-score-dedupe", host="192.0.2.1",
        port=443, protocol="tcp", name="Fixture finding", severity="critical",
        nvt_oid="1.3.6.1.4.1.99999.1", qod=150,
    )
    db_session.add_all([
        VulnerabilityFindingModel(id="vf-score-dedupe-1", **base),
        VulnerabilityFindingModel(id="vf-score-dedupe-2", **base),
        VulnerabilityFindingModel(id="vf-score-low", **{**base, "name": "Low", "severity": "low", "nvt_oid": "nvt-low", "qod": 100}),
        VulnerabilityFindingModel(id="vf-score-medium", **{**base, "name": "Medium", "severity": "medium", "nvt_oid": "nvt-medium", "qod": 100}),
        VulnerabilityFindingModel(id="vf-score-high", **{**base, "name": "High", "severity": "high", "nvt_oid": "nvt-high", "qod": 100}),
        VulnerabilityFindingModel(id="vf-score-info", **{**base, "name": "Info", "severity": "info", "nvt_oid": "nvt-info", "qod": 100}),
    ])
    db_session.flush()

    score = ExposureScorer.calculate_for_investigation(inv.id, db_session)
    assert score.V == 75  # 35 critical + 22 high + 12 medium + 5 low + 1 info
    assert score.components_detail["vulnerabilities_count"] == 5
    assert score.components_detail["vulnerability_records_count"] == 6


def test_group4_pages_require_login_and_filter_records_to_owner(authenticated_client, db_session, analyst_user):
    owned = _investigation("inv-group4-owned", analyst_user.id)
    other = _investigation("inv-group4-other")
    db_session.add_all([owned, other])
    db_session.flush()
    db_session.add_all([
        EvidenceModel(id="ev-owned", investigation_id=owned.id, source_type="dns", source_name="DNS",
                      target="owned.invalid", content_hash="a" * 64, content_size_bytes=0,
                      source_metadata={}, collection_status="SUCCESS"),
        EvidenceModel(id="ev-other", investigation_id=other.id, source_type="dns", source_name="DNS",
                      target="other.invalid", content_hash="b" * 64, content_size_bytes=0,
                      source_metadata={}, collection_status="SUCCESS"),
    ])
    db_session.flush()

    for path in ("/evidence", "/findings", "/scans"):
        response = authenticated_client.get(path)
        assert response.status_code == 200
    evidence = authenticated_client.get("/evidence").text
    assert "ev-owned" in evidence
    assert "ev-other" not in evidence


def test_group4_pages_redirect_unauthenticated(client):
    for path in ("/evidence", "/findings", "/scans"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
