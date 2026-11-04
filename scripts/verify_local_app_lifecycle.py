"""Local application verification script for Task 04D final closure.

Tests complete application lifecycle:
- Startup
- SQL Server connectivity
- SeaweedFS connectivity
- Authentication
- Investigation listing
- Evidence listing
- 7 migrated evidence downloads with SHA-256 integrity verification
- Graceful shutdown
- Clean restart cycle
"""

import hashlib
import os
import sys

# Ensure local test/dev SeaweedFS configuration is active
os.environ["SEAWEEDFS_FILER_URL"] = "http://localhost:18888"
os.environ["SEAWEEDFS_COLLECTION"] = "evidence"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.main import app
from app.config import get_settings
get_settings.cache_clear()
from app.database import build_engine, get_db, check_database_connection
from app.models.recon import EvidenceModel
from app.models.user import UserModel
from app.core.auth import create_user_session
from app.storage.factory import get_storage_adapter


MSSQL_URL = (
    r"mssql+pyodbc://@localhost\SQLEXPRESS/footprintiq"
    r"?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
)

TARGET_EVIDENCE_IDS = [
    "ev-nmap-35023caf5f0b",
    "ev-nmap-35d756388e5d",
    "ev-nmap-3e8336e332be",
    "ev-nmap-4d7def5be5ff",
    "ev-nmap-ac7fa3cd2637",
    "ev-nmap-dbc9e08e77ba",
    "evi-e4f8db7dcda8",
]


def run_cycle(cycle_name: str):
    print(f"\n--- {cycle_name} ---")
    
    # 1. Check SQL Server connectivity
    mssql_engine = build_engine(MSSQL_URL)
    db_ok, db_msg = check_database_connection(engine_override=mssql_engine)
    print(f"[{cycle_name}] SQL Server Database Connection: {'OK' if db_ok else 'FAIL'} ({db_msg})")
    assert db_ok, f"SQL Server connection failed: {db_msg}"

    # 2. Check SeaweedFS connectivity
    seaweed_adapter = get_storage_adapter(
        backend_override="seaweedfs",
        filer_url="http://localhost:18888",
        collection="evidence",
        force_new=True,
    )
    storage_health = seaweed_adapter.health_check()
    print(f"[{cycle_name}] SeaweedFS Connection: {'OK' if storage_health.is_healthy else 'FAIL'} ({storage_health.details})")
    assert storage_health.is_healthy, f"SeaweedFS unhealthy: {storage_health.details}"

    # 3. Create app dependency overrides
    def _override_get_db():
        with Session(mssql_engine) as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db

    # 4. App Lifespan and TestClient execution
    with TestClient(app, base_url="http://localhost") as client:
        print(f"[{cycle_name}] Application Startup completed successfully.")

        # Authenticate admin user
        with Session(mssql_engine) as session:
            admin_user = session.query(UserModel).filter(UserModel.username == "admin").first()
            raw_token, session_rec = create_user_session(db=session, user=admin_user)
            session.commit()
            token_str = raw_token
            session_id = session_rec.id

        auth_headers = {"Authorization": f"Bearer {token_str}"}

        try:
            # List investigations
            inv_res = client.get("/api/v1/investigations", headers=auth_headers)
            print(f"[{cycle_name}] Investigation listing status: {inv_res.status_code}")
            assert inv_res.status_code == 200

            # Test each of the 7 migrated records
            with Session(mssql_engine) as session:
                for eid in TARGET_EVIDENCE_IDS:
                    db_rec = session.get(EvidenceModel, eid)
                    assert db_rec is not None
                    inv_id = db_rec.investigation_id
                    expected_hash = db_rec.content_hash
                    expected_size = db_rec.content_size_bytes

                    # 1. Listing
                    list_res = client.get(f"/api/v1/investigations/{inv_id}/evidence", headers=auth_headers)
                    assert list_res.status_code == 200
                    items = [x for x in list_res.json() if x["id"] == eid]
                    assert len(items) == 1
                    assert items[0]["storage_backend"] == "seaweedfs"

                    # 2. Raw Download
                    raw_res = client.get(f"/api/v1/investigations/{inv_id}/evidence/{eid}/raw", headers=auth_headers)
                    assert raw_res.status_code == 200
                    dl_bytes = raw_res.content
                    dl_hash = hashlib.sha256(dl_bytes).hexdigest()
                    assert dl_hash == expected_hash
                    assert len(dl_bytes) == expected_size
                    assert raw_res.headers.get("X-Evidence-Storage-Backend") == "seaweedfs"
                    assert raw_res.headers.get("X-Evidence-Integrity") == "VERIFIED"

                    print(f"  [{eid}] Downloaded {len(dl_bytes)} bytes | SHA256: {dl_hash[:16]}... | Backend: seaweedfs | Status: VERIFIED")

            print(f"[{cycle_name}] All 7 migrated evidence objects downloaded and verified via API.")

        finally:
            # Clean up session
            with Session(mssql_engine) as session:
                s = session.get(type(session_rec), session_id)
                if s:
                    session.delete(s)
                    session.commit()

        print(f"[{cycle_name}] Application Shutdown completed gracefully.")

    app.dependency_overrides.pop(get_db, None)
    mssql_engine.dispose()


def main():
    print("=" * 80)
    print("FOOTPRINTIQ - LOCAL APPLICATION LIFECYCLE VERIFICATION")
    print("=" * 80)

    # Cycle 1: Initial startup & operations
    run_cycle("CYCLE 1: INITIAL STARTUP & RUNTIME")

    # Cycle 2: Clean restart cycle
    run_cycle("CYCLE 2: CLEAN RESTART & VERIFICATION")

    print("\n" + "=" * 80)
    print("LIFECYCLE VERIFICATION COMPLETE: ALL CYCLES PASSED")
    print("=" * 80)


if __name__ == "__main__":
    main()
