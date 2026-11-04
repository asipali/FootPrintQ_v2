import os
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel
from app.services.evidence_store import get_evidence_store

db_url = os.getenv('DATABASE_URL', 'mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes')
engine = create_engine(db_url)
SessionLocal = sessionmaker(bind=engine)

job_id = "nmap-cc51be1ba27e"

with SessionLocal() as db:
    job = db.get(ActiveScanJobModel, job_id)
    print("=================================================================")
    print("REAL AUTHORIZED NMAP SCAN EXECUTION AUDIT")
    print("=================================================================")
    print(f"Investigation ID: {job.investigation_id}")
    print(f"Target: {job.target}")
    print(f"Database Job ID: {job.id}")
    print(f"Status: {job.status}")
    print(f"Started At: {job.started_at}")
    print(f"Completed At: {job.completed_at}")
    print(f"Duration: {job.duration_seconds}s")
    print(f"Exit Code: {job.exit_code}")
    print(f"Command Summary: {job.command_summary}")
    print(f"Error Category: {job.error_category}")
    print(f"Error Message: {job.error_message}")
    print(f"Associated Evidence ID: {job.evidence_id}")

    hosts = db.query(ScanFindingHostModel).filter(ScanFindingHostModel.job_id == job_id).all()
    print(f"\nDiscovered Hosts Count: {len(hosts)}")
    for h in hosts:
        print(f"  Host Address: {h.address} | Status: {h.status} | Hostname: {h.hostname} | OS Match: {h.os_match}")
        print(f"  Ports ({len(h.ports)}):")
        for p in h.ports:
            print(f"    Port {p.port}/{p.protocol} | State: {p.state} | Service: {p.service_name} | Product: {p.service_product} | Version: {p.service_version}")

    evidence = db.get(EvidenceModel, job.evidence_id) if job.evidence_id else None
    if evidence:
        print("\n=== EVIDENCE RECORD VERIFICATION ===")
        print(f"Evidence ID: {evidence.id}")
        print(f"Storage Backend: {evidence.storage_backend}")
        print(f"Storage Path: {evidence.raw_content_path}")
        print(f"Recorded SHA-256 Hash: {evidence.content_hash}")
        print(f"Recorded Byte Size: {evidence.content_size_bytes} bytes")

        # Independent verification from EvidenceStore
        store = get_evidence_store()
        raw_bytes, computed_hash = store.read_evidence(evidence.raw_content_path, backend=evidence.storage_backend)
        calc_hash = hashlib.sha256(raw_bytes).hexdigest()

        print(f"Retrieved Object Size: {len(raw_bytes)} bytes")
        print(f"Independently Calculated SHA-256: {calc_hash}")
        print(f"Store-Computed SHA-256: {computed_hash}")
        print(f"Hash Matches Database Record: {calc_hash == evidence.content_hash}")
        print(f"\nRaw XML Output Preview (first 800 bytes):\n{raw_bytes[:800].decode(errors='replace')}")
    else:
        print("No evidence record associated with job.")
