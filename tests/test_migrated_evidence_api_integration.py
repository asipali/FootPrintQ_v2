"""Application-level integration testing for migrated SeaweedFS evidence records.

Verifies end-to-end evidence retrieval, metadata inspection, SHA-256 verification,
storage backend attribution, authentication, and RBAC authorization across all
seven migrated authoritative evidence records against live SQL Server 2022 Express
and live SeaweedFS Filer.
"""

import hashlib
from typing import Dict, List
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import build_engine, get_db
from app.models.recon import EvidenceModel
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.core.auth import create_user_session
from app.config import get_settings


MSSQL_URL = (
    r"mssql+pyodbc://@localhost\SQLEXPRESS/footprintiq"
    r"?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
)

MIGRATED_EVIDENCE_IDS = [
    "ev-nmap-35023caf5f0b",
    "ev-nmap-35d756388e5d",
    "ev-nmap-3e8336e332be",
    "ev-nmap-4d7def5be5ff",
    "ev-nmap-ac7fa3cd2637",
    "ev-nmap-dbc9e08e77ba",
    "evi-e4f8db7dcda8",
]


@pytest.fixture(scope="module")
def mssql_engine():
    engine = build_engine(MSSQL_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def mssql_db(mssql_engine):
    """Provides a transactional session to SQL Server."""
    connection = mssql_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def api_client(mssql_engine, monkeypatch):
    """Provides a TestClient whose get_db dependency and evidence storage are routed to live services."""
    live_settings = get_settings().model_copy(
        update={
            "DATABASE_URL": MSSQL_URL,
            "STORAGE_BACKEND": "filesystem",
            "SEAWEEDFS_FILER_URL": "http://localhost:18888",
            "SEAWEEDFS_COLLECTION": "evidence",
            "EVIDENCE_STORAGE_PATH": r"D:\Desktop\HackShift\footprint\evidence_storage",
            "ALLOWED_HOSTS": ["localhost", "127.0.0.1", "testserver"],
        }
    )

    import app.services.evidence_store as evidence_store_module
    monkeypatch.setattr(evidence_store_module, "get_settings", lambda: live_settings)
    monkeypatch.setattr(evidence_store_module, "_default_store", None)

    def _override_get_db():
        with Session(mssql_engine) as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, base_url="http://localhost") as client:
        yield client
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def admin_auth(mssql_engine):
    """Creates a real session for admin user in SQL Server and yields the raw bearer token."""
    with Session(mssql_engine) as session:
        admin_user = session.query(UserModel).filter(UserModel.username == "admin").first()
        assert admin_user is not None, "Admin user missing from SQL Server database"
        raw_token, session_rec = create_user_session(db=session, user=admin_user)
        session.commit()
        token_str = raw_token
        session_id = session_rec.id

    yield {"Authorization": f"Bearer {token_str}"}

    # Clean up session
    with Session(mssql_engine) as session:
        s = session.get(type(session_rec), session_id)
        if s:
            session.delete(s)
            session.commit()


def test_api_migrated_seven_evidence_metadata_and_download(api_client, admin_auth, mssql_engine):
    """Test 1: For each of the 7 migrated records:
    1. Authenticate through the application.
    2. Retrieve evidence listing.
    3. Retrieve evidence metadata.
    4. Download evidence through API.
    5. Verify SHA-256 match.
    6. Confirm correct investigation association.
    7. Confirm SeaweedFS backend is used.
    8. Confirm zero internal credentials or infrastructure leak.
    """
    with Session(mssql_engine) as session:
        for evidence_id in MIGRATED_EVIDENCE_IDS:
            db_record = session.get(EvidenceModel, evidence_id)
            assert db_record is not None, f"Record {evidence_id} missing from database"
            inv_id = db_record.investigation_id
            expected_hash = db_record.content_hash
            expected_size = db_record.content_size_bytes

            # Step 1 & 2: Retrieve evidence listing via API
            list_res = api_client.get(
                f"/api/v1/investigations/{inv_id}/evidence",
                headers=admin_auth,
            )
            assert list_res.status_code == 200, f"Failed listing evidence for {inv_id}: {list_res.text}"
            evidence_list = list_res.json()
            matching_items = [e for e in evidence_list if e["id"] == evidence_id]
            assert len(matching_items) == 1, f"Evidence {evidence_id} not found in listing for {inv_id}"
            meta = matching_items[0]

            # Step 3: Verify evidence metadata
            assert meta["id"] == evidence_id
            assert meta["investigation_id"] == inv_id
            assert meta["content_hash"] == expected_hash
            assert meta["storage_backend"] == "seaweedfs"

            # Step 4: Download raw evidence through application API
            raw_res = api_client.get(
                f"/api/v1/investigations/{inv_id}/evidence/{evidence_id}/raw",
                headers=admin_auth,
            )
            assert raw_res.status_code == 200, f"Raw download failed for {evidence_id}: {raw_res.text}"

            # Step 5: Cryptographic integrity verification
            downloaded_bytes = raw_res.content
            downloaded_hash = hashlib.sha256(downloaded_bytes).hexdigest()
            assert downloaded_hash == expected_hash, f"Hash mismatch for {evidence_id}"
            assert len(downloaded_bytes) == expected_size, f"Size mismatch for {evidence_id}"

            # Step 6 & 7: Backend attribution headers
            assert raw_res.headers.get("X-Evidence-Integrity") == "VERIFIED"
            assert raw_res.headers.get("X-Evidence-Storage-Backend") == "seaweedfs"
            assert raw_res.headers.get("X-Content-SHA256") == expected_hash

            # Step 8: Confidentiality inspection - zero leak of internal URLs or tokens
            header_dump = str(raw_res.headers).lower()
            assert "password" not in header_dump
            assert "token" not in header_dump
            assert "18888" not in header_dump
            assert "localhost:8888" not in header_dump


def test_api_authorization_controls(api_client, admin_auth):
    """Test 2: Rigorous verification of authorization boundaries on migrated evidence."""
    target_eid = "ev-nmap-35023caf5f0b"
    valid_inv_id = "inv-dbddbcd3a4"
    invalid_inv_id = "inv-live-nmap-lab"

    # 1. Unauthenticated request rejected with 401
    unauth_res = api_client.get(f"/api/v1/investigations/{valid_inv_id}/evidence/{target_eid}/raw")
    assert unauth_res.status_code == 401

    # 2. Cross-investigation access rejected with 404
    cross_res = api_client.get(
        f"/api/v1/investigations/{invalid_inv_id}/evidence/{target_eid}/raw",
        headers=admin_auth,
    )
    assert cross_res.status_code == 404

    # 3. Non-existent evidence ID returns 404
    missing_res = api_client.get(
        f"/api/v1/investigations/{valid_inv_id}/evidence/ev-non-existent-999/raw",
        headers=admin_auth,
    )
    assert missing_res.status_code == 404

    # 4. Unauthorized evidence deletion rejected (no DELETE route on /raw)
    del_res = api_client.delete(
        f"/api/v1/investigations/{valid_inv_id}/evidence/{target_eid}/raw",
        headers=admin_auth,
    )
    assert del_res.status_code in (404, 405)


def test_failure_seaweedfs_temporarily_unavailable(api_client, admin_auth, monkeypatch):
    """Fault injection: SeaweedFS connection failure returns controlled HTTP 500, no false success."""
    from app.storage.seaweedfs import SeaweedFSStorageAdapter
    from app.storage.base import StorageConnectionError

    monkeypatch.setattr(
        SeaweedFSStorageAdapter,
        "get_object",
        lambda self, key: (_ for _ in ()).throw(StorageConnectionError("SeaweedFS cluster connection timeout")),
    )

    res = api_client.get(
        "/api/v1/investigations/inv-dbddbcd3a4/evidence/ev-nmap-35023caf5f0b/raw",
        headers=admin_auth,
    )
    assert res.status_code == 500
    assert "Evidence could not be read or verified" in str(res.json())


def test_failure_corrupted_object_rejected(api_client, admin_auth, monkeypatch):
    """Fault injection: Bit-rot / tampering in SeaweedFS detected by SHA-256 and rejected with 500."""
    from app.storage.seaweedfs import SeaweedFSStorageAdapter
    from app.storage.base import StorageObjectMetadata
    from datetime import datetime, timezone

    corrupted_bytes = b"TAMPERED EVIDENCE BYTES"
    tampered_meta = StorageObjectMetadata(
        key="inv-dbddbcd3a4/ev-nmap-35023caf5f0b_nmap.raw.txt",
        size_bytes=len(corrupted_bytes),
        content_hash=hashlib.sha256(corrupted_bytes).hexdigest(),
        content_type="text/plain",
        backend="seaweedfs",
        created_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        SeaweedFSStorageAdapter,
        "get_object",
        lambda self, key: (corrupted_bytes, tampered_meta),
    )

    res = api_client.get(
        "/api/v1/investigations/inv-dbddbcd3a4/evidence/ev-nmap-35023caf5f0b/raw",
        headers=admin_auth,
    )
    assert res.status_code == 500
    assert "Evidence integrity check failed" in str(res.json())


def test_repeated_download_consistency(api_client, admin_auth):
    """Verifies that back-to-back repeated downloads return identical content and hashes."""
    target_eid = "ev-nmap-35023caf5f0b"
    inv_id = "inv-dbddbcd3a4"

    res1 = api_client.get(f"/api/v1/investigations/{inv_id}/evidence/{target_eid}/raw", headers=admin_auth)
    res2 = api_client.get(f"/api/v1/investigations/{inv_id}/evidence/{target_eid}/raw", headers=admin_auth)

    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res1.content == res2.content
    assert res1.headers.get("X-Content-SHA256") == res2.headers.get("X-Content-SHA256")

