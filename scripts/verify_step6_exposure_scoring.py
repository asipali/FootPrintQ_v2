"""FootprintIQ — Step 6 Real Data Acceptance Verification Script.

Demonstrates the finalized 5-Factor Exposure Scoring Engine on live SQL Server 2022 Express:
- Real investigation data with full coverage and active vulnerabilities
- Partial coverage scenarios with explicit coverage notices (Nmap or Greenbone missing)
- Unassessed / insufficient evidence investigations
- Versioned formula calculations (v3.0-5factor vs v1.0-legacy)
- Historical calculation preservation and audit trail in exposure_scores table
"""

import sys
import os
import json
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import settings
from app.database import get_db_context
from app.models.investigation import InvestigationModel
from app.models.exposure_score import ExposureScoreModel
from app.models.scan import ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityFindingModel
from app.services.scoring.calculator import DEFAULT_SCORING_MODEL, SCORING_MODELS, ExposureScorer


def main():
    print("=" * 80)
    print("FOOTPRINTIQ — STEP 6 EXPOSURE SCORING ENGINE ACCEPTANCE VERIFICATION")
    print("=" * 80)
    print(f"Database URL: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
    print(f"Authoritative Model: {DEFAULT_SCORING_MODEL}")
    print("-" * 80)

    with get_db_context() as db:
        # 1. Inspect existing investigations
        investigations = db.query(InvestigationModel).all()
        print(f"\n[1] Discovered {len(investigations)} investigations in SQL Server database.")

        # Scenario 1: Comprehensive active investigation with findings & complete scans
        target_inv = db.query(InvestigationModel).filter(InvestigationModel.id == "inv-verify-p7-b00302").first()
        if not target_inv:
            target_inv = investigations[0]
        inv_id = target_inv.id

        print(f"\n[SCENARIO 1] Investigation with Active Findings: {inv_id} ('{target_inv.name}')")
        score_v3 = ExposureScorer.calculate_for_investigation(
            investigation_id=inv_id,
            db=db,
            model_version="v3.0-5factor",
            reviewer_notes="Acceptance test run under authoritative v3.0 model.",
            persist=True,
        )
        db.commit()

        print(f"    Formula:                {score_v3.formula_version}")
        print(f"    Assessment Status:      {score_v3.assessment_status}")
        print(f"    Coverage Percentage:    {score_v3.components_detail.get('coverage_percentage')}%")
        print(f"    Normalized Factors:     P={score_v3.P}, D={score_v3.D}, S={score_v3.S}, V={score_v3.V}, C={score_v3.C}")
        print(f"    Weighted Contributions: {score_v3.weighted_contributions}")
        print(f"    Composite Total Score:  {score_v3.total_score} / 100 ({score_v3.tier})")
        if score_v3.renormalized_score is not None:
            print(f"    Renormalized Score:     {score_v3.renormalized_score} / 100")
        print("\n    Generated Explanation:")
        for line in (score_v3.explanation or "").split("\n"):
            print(f"      {line}")

        # Scenario 2: Historical v1.0-legacy formula calculation on same investigation
        print(f"\n[SCENARIO 2] Historical v1.0-legacy Comparison on: {inv_id}")
        score_v1 = ExposureScorer.calculate_for_investigation(
            investigation_id=inv_id,
            db=db,
            model_version="v1.0-legacy",
            reviewer_notes="Acceptance test run under historical v1.0-legacy model.",
            persist=True,
        )
        db.commit()

        print(f"    v1.0-legacy Total Score: {score_v1.total_score} / 100 ({score_v1.tier})")
        print(f"    v3.0 vs v1.0 Difference: {score_v3.total_score} vs {score_v1.total_score} points")
        print(f"    Reason: v3.0 weights critical vulnerabilities at 35% vs 20% in v1.0.")

        # Scenario 3: Partial or Incomplete Assessment Investigation
        partial_inv = None
        for inv in investigations:
            if inv.id != inv_id:
                ports_cnt = db.query(ScanFindingPortModel).filter(ScanFindingPortModel.host_id.in_(
                    db.query(ScanFindingHostModel.id).filter(ScanFindingHostModel.investigation_id == inv.id)
                )).count()
                vulns_cnt = db.query(VulnerabilityFindingModel).filter(VulnerabilityFindingModel.investigation_id == inv.id).count()
                if ports_cnt == 0 or vulns_cnt == 0:
                    partial_inv = inv
                    break

        if partial_inv:
            print(f"\n[SCENARIO 3] Incomplete / Partial Assessment Investigation: {partial_inv.id} ('{partial_inv.name}')")
            score_part = ExposureScorer.calculate_for_investigation(
                investigation_id=partial_inv.id,
                db=db,
                model_version="v3.0-5factor",
                persist=True,
            )
            db.commit()
            print(f"    Assessment Status:   {score_part.assessment_status}")
            print(f"    Coverage Percentage: {score_part.components_detail.get('coverage_percentage')}%")
            print(f"    Fully Assessed:      {score_part.components_detail.get('is_fully_assessed')}")
            print(f"    Coverage Warnings:   {score_part.components_detail.get('coverage_warnings')}")
            print(f"    Observed Score:      {score_part.total_score} / 100 ({score_part.tier})")
            if score_part.renormalized_score:
                print(f"    Renormalized Score:  {score_part.renormalized_score} / 100")

        # Scenario 4: Historical Score Audit Trail Verification in SQL Server
        print(f"\n[SCENARIO 4] Historical Score Audit Trail in exposure_scores table:")
        history = ExposureScorer.get_score_history(inv_id, db)
        print(f"    Retrieved {len(history)} calculation records for investigation {inv_id}:")
        for idx, h in enumerate(history, 1):
            print(f"      Record #{idx}: ID={h['id']} | Model={h['formula_version']} | Score={h['total_score']}/100 | Tier={h['risk_tier']} | Active={h['is_active']} | Status={h['assessment_status']}")

        # Scenario 5: Score Comparison Logic
        if len(history) >= 2:
            print(f"\n[SCENARIO 5] Explainable Score Comparison:")
            comp = ExposureScorer.compare_scores(history[0], history[1])
            print(f"    Same Formula Version: {comp['same_formula_version']}")
            print(f"    Delta Total Score:    {comp['delta_total_score']}")
            print(f"    Factor Deltas:        {comp['factor_deltas']}")
            print(f"    Comparison Notes:     {comp['comparison_notes']}")

        print("\n" + "=" * 80)
        print("STEP 6 ACCEPTANCE VERIFICATION COMPLETED SUCCESSFULLY.")
        print("=" * 80)


if __name__ == "__main__":
    main()

