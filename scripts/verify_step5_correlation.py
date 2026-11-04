"""FootprintIQ — Step 5 Real Data Acceptance Verification Script.

Demonstrates traceable evidence correlation on live SQL Server 2022 Express and SeaweedFS:
Asset -> Nmap Observation -> Greenbone Finding -> Original Report -> Evidence Record -> SHA-256 Hash -> Correlation Relationship.
"""

import sys
import os
import json
import hashlib
from typing import Dict, Any

# Ensure app is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import settings
from app.database import get_db_context
from app.models.investigation import InvestigationModel
from app.models.correlation import CorrelationRecordModel
from app.models.vulnerability import VulnerabilityFindingModel
from app.models.scan import ScanFindingHostModel, ScanFindingPortModel
from app.models.recon import EvidenceModel
from app.services.correlation.engine import CorrelationEngine
from app.services.evidence_store import get_evidence_store


def main():
    print("=" * 80)
    print("FOOTPRINTIQ — STEP 5 CORRELATION ENGINE ACCEPTANCE VERIFICATION")
    print("=" * 80)
    print(f"Database URL: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
    print(f"Storage Backend: {settings.STORAGE_BACKEND}")
    print(f"SeaweedFS Filer URL: {settings.SEAWEEDFS_FILER_URL}")
    print("-" * 80)

    with get_db_context() as db:
        # 1. Inspect existing investigations
        investigations = db.query(InvestigationModel).all()
        print(f"\n[1] Discovered {len(investigations)} investigations in SQL Server database.")

        # Target investigations for verification
        target_inv_id = "inv-verify-p7-b00302"
        inv = db.query(InvestigationModel).filter(InvestigationModel.id == target_inv_id).first()
        if not inv:
            # Fallback to first available
            inv = investigations[0]
            target_inv_id = inv.id

        print(f"    Testing Target Investigation: {target_inv_id} ('{inv.name}')")

        # 2. Check assets and findings before correlation
        hosts = db.query(ScanFindingHostModel).filter(ScanFindingHostModel.investigation_id == target_inv_id).all()
        vulns = db.query(VulnerabilityFindingModel).filter(VulnerabilityFindingModel.investigation_id == target_inv_id).all()
        evidence_items = db.query(EvidenceModel).filter(EvidenceModel.investigation_id == target_inv_id).all()
        print(f"    - Discovered Scan Hosts: {len(hosts)}")
        for h in hosts:
            ports = db.query(ScanFindingPortModel).filter(ScanFindingPortModel.host_id == h.id).all()
            port_strs = [f"{p.port_number}/{p.protocol} ({p.service_name or 'unknown'}, {p.state})" for p in ports]
            print(f"      * Host {h.address} ({h.status}): {', '.join(port_strs)}")
        print(f"    - Discovered Vulnerability Findings: {len(vulns)}")
        for v in vulns:
            print(f"      * [{v.severity.upper()}] {v.name} on {v.host}:{v.port}/{v.protocol} (CVSS: {v.cvss_score})")
        print(f"    - Associated Evidence Records: {len(evidence_items)}")

        # 3. Execute First Correlation Run
        print(f"\n[2] Executing CorrelationEngine.run_correlation({target_inv_id}) [Run 1]...")
        engine = CorrelationEngine(db)
        res1 = engine.run_correlation(target_inv_id)

        corrs1 = res1.get("correlations", [])
        summary1 = res1.get("summary", {})
        rel_types = summary1.get("relationship_types", {})
        print(f"    Correlation Run 1 Result:")
        print(f"    - Total Correlated Records: {len(corrs1)}")
        print(f"    - Normalized Assets: {summary1.get('total_assets', 0)}")
        print(f"    - Confirmed Matches: {rel_types.get('CONFIRMED_MATCH', 0)}")
        print(f"    - Strong Matches: {rel_types.get('STRONG_MATCH', 0)}")
        print(f"    - Possible Matches: {rel_types.get('POSSIBLE_MATCH', 0)}")
        print(f"    - Unmatched Observations: {summary1.get('total_unmatched', 0)}")

        # 4. Display Traceable Correlation Chains
        print(f"\n[3] Traceable Provenance Chains in Run 1:")
        for idx, c in enumerate(corrs1, 1):
            print(f"    Chain #{idx}:")
            print(f"      - Asset:               {c['asset_identifier']} ({c['asset_type']})")
            print(f"      - Relationship:        {c['relationship_type']} (Confidence: {c['confidence_score']:.2f})")
            print(f"      - Rule Applied:        {c['correlation_rule_id']} v{c['rule_version']}")
            print(f"      - Summary:             {c['summary']}")
            print(f"      - Evidence References: {c.get('evidence_references') or []}")
            print(f"      - Verification Status: {c.get('evidence_verification_status')}")
            print(f"      - Matching Attrs:      {json.dumps(c.get('matching_attributes', {}))}")

        # 5. Verify SHA-256 Hashes Against SeaweedFS Storage
        print(f"\n[4] Verifying Evidence Cryptographic Integrity Against Storage...")
        ev_step4_id = "inv-dbddbcd3a4"
        res_ev = engine.run_correlation(ev_step4_id)
        ev_corrs = res_ev.get("correlations", [])
        verified_count = sum(1 for c in ev_corrs if c.get("evidence_verification_status") == "VERIFIED")
        print(f"    Investigation {ev_step4_id}:")
        print(f"    - Total Evidence Records Checked: {len(ev_corrs)}")
        print(f"    - Cryptographically Verified (SHA-256 match): {verified_count}")
        assert verified_count > 0, "Expected at least one verified evidence item against SeaweedFS"

        # 6. Test Idempotency (Run 2)
        print(f"\n[5] Testing Correlation Idempotency (Run 2 on {target_inv_id})...")
        res2 = engine.run_correlation(target_inv_id)
        corrs2 = res2.get("correlations", [])
        db_records_active = db.query(CorrelationRecordModel).filter(
            CorrelationRecordModel.investigation_id == target_inv_id,
        ).count()
        print(f"    - Run 1 Record Count: {len(corrs1)}")
        print(f"    - Run 2 Record Count: {len(corrs2)}")
        print(f"    - DB Records Count:   {db_records_active}")
        assert len(corrs1) == len(corrs2) == db_records_active, "Idempotency violation!"
        print("    [PASS] Idempotency confirmed: correlation records match exactly without duplicates.")

    print("\n" + "=" * 80)
    print("STEP 5 ACCEPTANCE VERIFICATION COMPLETED SUCCESSFULLY.")
    print("=" * 80)


if __name__ == "__main__":
    main()
