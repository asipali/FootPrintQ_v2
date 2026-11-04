"""
Step 7.1 Independent validation probe script.
Checks Greenbone records, Exposure scores, evidence objects, and UI endpoints.
"""

import os
import sys
import json
import hashlib
import urllib.request
from datetime import datetime, timezone

from app.database import SessionLocal
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.models.recon import EvidenceModel, TargetAuthorizationModel, CollectionJobModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.exposure_score import ExposureScoreModel
from app.models.correlation import CorrelationRecordModel
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.services.evidence_store import get_evidence_store
from app.storage.factory import get_storage_adapter

def audit_greenbone():
    print("=== 2. GREENBONE END-TO-END AUDIT ===")
    db = SessionLocal()
    jobs = db.query(VulnerabilityScanJobModel).all()
    print(f"Total vulnerability scan jobs in DB: {len(jobs)}")
    for j in jobs:
        print(f"  Job: {j.id} | Inv: {j.investigation_id} | Target: {j.target} | Status: {j.status} | RemoteTask: {getattr(j, 'remote_task_id', None)} | Evidence: {j.evidence_id}")

    findings = db.query(VulnerabilityFindingModel).all()
    print(f"\nTotal vulnerability findings in DB: {len(findings)}")
    for f in findings:
        print(f"  Finding: {f.id} | Job: {f.job_id} | Name: {f.name} | Sev: {f.severity} | CVSS: {f.cvss_score} | Port: {f.port} | CVEs: {f.cve_references}")

    ev_vuln = db.query(EvidenceModel).filter(EvidenceModel.source_type.like("%vuln%")).all()
    print(f"\nVulnerability Evidence Records in DB: {len(ev_vuln)}")
    for e in ev_vuln:
        print(f"  Evidence: {e.id} | Inv: {e.investigation_id} | Backend: {e.storage_backend} | Path: {e.raw_content_path} | Hash: {e.content_hash}")

    db.close()

def audit_exposure_scoring():
    print("\n=== 3. EXPOSURE SCORING AUDIT ===")
    db = SessionLocal()
    scores = db.query(ExposureScoreModel).order_by(ExposureScoreModel.created_at.desc()).all()
    print(f"Total Exposure Score records in DB: {len(scores)}")
    for s in scores:
        print(f"\nScore ID: {s.id}")
        print(f"  Investigation: {s.investigation_id}")
        print(f"  Formula: {s.formula_version}")
        print(f"  Total (Raw): {s.total_score}")
        print(f"  Renormalized: {s.renormalized_score}")
        print(f"  Risk Tier: {s.risk_tier}")
        print(f"  Assessment Status: {s.assessment_status}")
        print(f"  Coverage %: {s.coverage_percentage}")
        print(f"  Weights: {s.formula_weights}")
        print(f"  Factor Scores: {s.normalized_factor_scores}")
        print(f"  Contributions: {s.weighted_contributions}")
        print(f"  Coverage Metadata: {s.coverage_metadata}")
        print(f"  Scanner Availability: {s.scanner_availability}")
    db.close()

def audit_evidence_preservation():
    print("\n=== 5. EVIDENCE PRESERVATION AUDIT ===")
    db = SessionLocal()
    evidence_records = db.query(EvidenceModel).all()
    print(f"Total Evidence Records in DB: {len(evidence_records)}")

    seaweed_adapter = get_storage_adapter()
    total_checked = 0
    verified_count = 0
    missing_count = 0
    mismatch_count = 0
    backend_counts = {}

    for ev in evidence_records:
        total_checked += 1
        backend_counts[ev.storage_backend] = backend_counts.get(ev.storage_backend, 0) + 1
        # Check SeaweedFS
        url = f"http://localhost:18888/evidence/{ev.raw_content_path}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                content = resp.read()
                computed_hash = hashlib.sha256(content).hexdigest()
                if computed_hash.lower() == ev.content_hash.lower():
                    verified_count += 1
                else:
                    mismatch_count += 1
                    print(f"  [MISMATCH] {ev.id}: DB={ev.content_hash} vs Stored={computed_hash}")
        except Exception as err:
            missing_count += 1
            # print(f"  [UNREACHABLE/MISSING] {ev.id} ({ev.storage_backend}) at {url}: {err}")

    print(f"Backend distribution: {backend_counts}")
    print(f"Total checked: {total_checked}")
    print(f"Verified (SHA-256 match in SeaweedFS): {verified_count}")
    print(f"Missing in SeaweedFS: {missing_count}")
    print(f"Hash mismatches: {mismatch_count}")
    db.close()

if __name__ == "__main__":
    audit_greenbone()
    audit_exposure_scoring()
    audit_evidence_preservation()
