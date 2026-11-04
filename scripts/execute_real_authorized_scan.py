import asyncio
import os
import hashlib
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel
from app.models.user import UserModel
from app.services.active.runner import get_nmap_runner
from app.services.active.nmap_detector import get_nmap_detector
from app.services.active.profiles import get_scan_profile
from app.services.evidence_store import get_evidence_store

db_url = os.getenv('DATABASE_URL', 'mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes')
engine = create_engine(db_url)
SessionLocal = sessionmaker(bind=engine)

async def main():
    print("=================================================================")
    print("EXECUTING REAL AUTHORIZED NMAP SCAN")
    print("=================================================================")

    inv_id = "inv-0fabf5f0690244e089b55661a273ee8a"
    target = "192.168.56.107"
    profile_id = "basic_tcp"

    with SessionLocal() as db:
        inv = db.get(InvestigationModel, inv_id)
        assert inv, "Investigation not found"
        user = db.get(UserModel, inv.owner_user_id) or db.query(UserModel).filter(UserModel.role == "administrator").first()
        authz = db.query(TargetAuthorizationModel).filter(
            TargetAuthorizationModel.investigation_id == inv_id,
            TargetAuthorizationModel.target == target,
            TargetAuthorizationModel.is_revoked == False
        ).order_by(TargetAuthorizationModel.created_at.desc()).first()

        assert authz, f"No active authorization found for {target}"
        print(f"Investigation ID: {inv.id}")
        print(f"Target: {target}")
        print(f"Authorization Record ID: {authz.id}")
        print(f"Authorized Operations: {authz.allowed_operations}")
        print(f"Authorization Reference: {authz.authorization_reference}")
        print(f"Valid: {authz.valid_from} to {authz.valid_to}")

        detector = get_nmap_detector()
        executable = detector.resolve_binary_path()
        avail = detector.check_availability()
        version = avail.get("version")
        print(f"Scanner Executable: {executable}")
        print(f"Scanner Version: {version}")

        profile = get_scan_profile(profile_id)
        print(f"Actual Execution Profile: {profile.id} ({profile.name})")
        print(f"Profile Args: {profile.args}")

        runner = get_nmap_runner()

        # Create scan job
        print("\nCreating scan job...")
        job = await runner.create_scan_job(
            db=db,
            investigation=inv,
            target=target,
            profile_id=profile_id,
            actor_user=user,
        )
        job_id = job.id
        print(f"Database Job ID: {job_id}")

    # Execute scan
    print("Executing Nmap scan via runner...")
    t_start = datetime.now(timezone.utc)
    await runner.execute_scan(SessionLocal, job_id)
    t_end = datetime.now(timezone.utc)

    # Inspect results
    with SessionLocal() as db:
        job = db.get(ActiveScanJobModel, job_id)
        print("\n=== SCAN EXECUTION RESULTS ===")
        print(f"Status: {job.status}")
        print(f"Started At: {job.started_at}")
        print(f"Completed At: {job.completed_at}")
        print(f"Duration: {(t_end - t_start).total_seconds():.2f}s")
        print(f"Exit Code / Error Category: {job.error_category}")
        print(f"Standard Output (Summary):\n{job.command_summary}")
        if job.error_message:
            print(f"Error Message: {job.error_message}")

        # Check findings
        hosts = db.query(ScanFindingHostModel).filter(ScanFindingHostModel.scan_job_id == job_id).all()
        print(f"\nDiscovered Hosts Count: {len(hosts)}")
        for h in hosts:
            print(f"  Host: {h.ip_address} | Status: {h.state} | Hostname: {h.hostname} | OS: {h.os_family}")
            for p in (h.open_ports or []):
                print(f"    Port {p.get('port')}/{p.get('protocol')}: {p.get('service')} ({p.get('state')})")

        # Check evidence
        evidence = db.query(EvidenceModel).filter(
            EvidenceModel.investigation_id == inv_id,
            EvidenceModel.evidence_type == "NMAP_XML_RAW",
            EvidenceModel.source_job_id == job_id
        ).first()

        if evidence:
            print(f"\nEvidence Object Reference: {evidence.id}")
            print(f"Evidence Storage Path: {evidence.storage_path}")
            print(f"Evidence SHA-256 Digest in DB: {evidence.sha256_hash}")
            print(f"Evidence Byte Size: {evidence.byte_size} bytes")

            # Independent verification of evidence from storage
            store = get_evidence_store()
            raw_bytes, verified = store.read_evidence(evidence.storage_path, verify_hash=True)
            calc_hash = hashlib.sha256(raw_bytes).hexdigest()
            print(f"Retrieved Evidence Size: {len(raw_bytes)} bytes")
            print(f"Independently Calculated SHA-256: {calc_hash}")
            print(f"Hash Match: {calc_hash == evidence.sha256_hash}")
            print(f"Store Built-in Hash Verified: {verified}")
            print(f"XML Content Preview:\n{raw_bytes[:300].decode(errors='replace')}...")
        else:
            print("\nEvidence record not created or not found for job.")

if __name__ == "__main__":
    asyncio.run(main())

