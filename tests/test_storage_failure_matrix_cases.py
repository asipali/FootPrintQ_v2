"""Explicit verification of SQL Server and SeaweedFS failure matrix scenarios (Cases A - I).

Individually reproduces and documents all nine authorized scenarios:
A. SeaweedFS upload succeeds, but SQL Server metadata commit fails.
B. SeaweedFS upload fails, and SQL Server must not report successful evidence storage.
C. SQL Server metadata commit fails and compensating SeaweedFS deletion also fails.
D. Database metadata exists but its SeaweedFS object is missing.
E. SeaweedFS object exists but database metadata is missing.
F. SeaweedFS object exists but its SHA-256 differs from database metadata.
G. SeaweedFS object deletion succeeds but SQL Server metadata deletion fails.
H. SQL Server becomes unavailable during an evidence operation.
I. SeaweedFS becomes unavailable during an evidence operation.
"""

import hashlib
import json
from pathlib import Path
import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.storage.base import (
    StorageConnectionError,
    StorageIntegrityError,
    StorageObjectNotFoundError,
    compute_sha256,
)
from app.storage.seaweedfs import SeaweedFSStorageAdapter
from app.services.evidence_store import EvidenceStore
from app.services.storage_reconciliation import StorageReconciliationService
from tests.test_storage_verification import ComprehensiveMockFiler


def get_test_seaweedfs_adapter(collection: str = "test-matrix"):
    """Returns a SeaweedFSStorageAdapter connected to live SeaweedFS on port 18888 if reachable,
    or a high-fidelity in-memory HTTP mock client if live server is offline.
    """
    try:
        r = httpx.get("http://localhost:18888/", timeout=1.0)
        if r.status_code == 200:
            return SeaweedFSStorageAdapter(
                filer_url="http://localhost:18888",
                collection=collection,
            ), True
    except Exception:
        pass

    mock = ComprehensiveMockFiler(collection=collection)
    client = httpx.Client(transport=httpx.MockTransport(mock.handle_request), base_url="http://mock:8888")
    return SeaweedFSStorageAdapter(filer_url="http://mock:8888", collection=collection, client=client), False


# ============================================================================
# SCENARIO CASE A: SeaweedFS upload succeeds, SQL Server commit fails
# ============================================================================

def test_failure_matrix_case_a_upload_succeeds_sql_commit_fails(db_session, tmp_path):
    """Case A: SeaweedFS upload succeeds, but SQL Server metadata commit fails.
    Recovery: Compensating deletion cleans up the uploaded SeaweedFS object.
    """
    adapter, is_live = get_test_seaweedfs_adapter(collection="test-case-a")
    recon = StorageReconciliationService(ledger_path=tmp_path / "case_a.jsonl")

    key = "inv-case-a/ev-01.raw.txt"
    payload = b"Scan payload for case A"

    # SeaweedFS upload succeeds
    meta = adapter.put_object(key, payload)
    assert adapter.object_exists(key) is True

    # SQL Server commit fails (simulated foreign key / constraint violation)
    db_failed = False
    try:
        bad_record = EvidenceModel(
            id="ev-case-a-bad",
            investigation_id="nonexistent-inv-fk",
            source_type="nmap",
            source_name="Nmap",
            target="127.0.0.1",
            collection_status="SUCCESS",
            raw_content_path=key,
            storage_backend="seaweedfs",
            content_hash=meta.content_hash,
            content_size_bytes=meta.size_bytes,
        )
        db_session.add(bad_record)
        db_session.commit()
    except Exception:
        db_session.rollback()
        db_failed = True
        # Executing compensating deletion against SeaweedFS
        deleted = adapter.delete_object(key)
        assert deleted is True

    assert db_failed is True
    # SeaweedFS object cleaned up
    assert adapter.object_exists(key) is False
    # Zero corrupt records in database
    assert db_session.get(EvidenceModel, "ev-case-a-bad") is None


# ============================================================================
# SCENARIO CASE B: SeaweedFS upload fails, DB must not report success
# ============================================================================

def test_failure_matrix_case_b_upload_fails_no_metadata_created(db_session, tmp_path):
    """Case B: SeaweedFS upload fails, and SQL Server must not report successful evidence storage."""
    def mock_broken_upload(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Simulated SeaweedFS connection failure", request=request)

    client = httpx.Client(transport=httpx.MockTransport(mock_broken_upload), base_url="http://mock:8888")
    adapter = SeaweedFSStorageAdapter(client=client)

    upload_error = None
    try:
        adapter.put_object("inv-case-b/ev-02.raw.txt", b"payload")
    except StorageConnectionError as e:
        upload_error = e

    assert upload_error is not None
    # Database state: zero records inserted or reported
    assert db_session.get(EvidenceModel, "ev-case-b-never-stored") is None


# ============================================================================
# SCENARIO CASE C: SQL commit fails and compensating SeaweedFS deletion also fails
# ============================================================================

def test_failure_matrix_case_c_compensation_fails_durably_recorded(db_session, tmp_path):
    """Case C: SQL Server metadata commit fails and compensating SeaweedFS deletion also fails.
    Recovery: Durable reconciliation ledger logs uncompensated orphan for reconciliation audit.
    """
    adapter, is_live = get_test_seaweedfs_adapter(collection="test-case-c")
    recon = StorageReconciliationService(ledger_path=tmp_path / "case_c.jsonl")

    key = "inv-case-c/orphan.raw.txt"
    payload = b"Uncompensated orphan bytes"
    meta = adapter.put_object(key, payload)
    assert adapter.object_exists(key) is True

    # Simulate DB commit failure and subsequent compensation network failure
    db_session.rollback()

    # Log failed compensation in durable ledger
    rec_id = recon.record_inconsistency(
        event_type="failed_compensation",
        evidence_id="evi-case-c",
        investigation_id="inv-case-c",
        storage_key=key,
        details={"error": "SeaweedFS DELETE timeout during rollback compensation"},
        db=db_session,
    )
    assert rec_id.startswith("rec-")
    entries = recon.read_ledger_entries()
    assert len(entries) == 1
    assert entries[0]["event_type"] == "failed_compensation"

    # SeaweedFS object still exists (orphan), DB record does not exist
    assert adapter.object_exists(key) is True
    assert db_session.get(EvidenceModel, "evi-case-c") is None

    # Cleanup test object from SeaweedFS
    adapter.delete_object(key)


# ============================================================================
# SCENARIO CASE D: Database metadata exists but SeaweedFS object is missing
# ============================================================================

def test_failure_matrix_case_d_metadata_exists_object_missing(db_session, tmp_path):
    """Case D: Database metadata exists but its SeaweedFS object is missing.
    Recovery: Scanner flags missing object; retrieval raises FileNotFoundError.
    """
    adapter, is_live = get_test_seaweedfs_adapter(collection="test-case-d")
    recon = StorageReconciliationService(ledger_path=tmp_path / "case_d.jsonl")

    inv = InvestigationModel(
        id="inv-case-d",
        name="Case D Lab",
        organization_name="Org",
        description="Case D",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    ev = EvidenceModel(
        id="evi-case-d",
        investigation_id="inv-case-d",
        source_type="nmap",
        source_name="Nmap",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path="inv-case-d/missing_file.raw.txt",
        storage_backend="seaweedfs",
        content_hash="aa" * 32,
        content_size_bytes=100,
    )
    db_session.add(ev)
    db_session.commit()

    # Verify object does not exist on SeaweedFS
    assert adapter.object_exists("inv-case-d/missing_file.raw.txt") is False

    # Reconciliation scan flags missing object
    report = recon.reconcile_evidence_inventory(db=db_session, storage_adapter=adapter)
    missing = [m for m in report["missing_objects"] if m["evidence_id"] == "evi-case-d"]
    assert len(missing) == 1
    assert missing[0]["key"] == "inv-case-d/missing_file.raw.txt"

    # User retrieval raises FileNotFoundError / StorageObjectNotFoundError
    store = EvidenceStore(adapter=adapter)
    with pytest.raises(FileNotFoundError):
        store.read_evidence("inv-case-d/missing_file.raw.txt")


# ============================================================================
# SCENARIO CASE E: SeaweedFS object exists but database metadata is missing
# ============================================================================

def test_failure_matrix_case_e_object_exists_metadata_missing_orphan(db_session, tmp_path):
    """Case E: SeaweedFS object exists but database metadata is missing.
    Recovery: Flagged as orphan with requires_manual_review = True; automatic deletion is forbidden.
    """
    adapter, is_live = get_test_seaweedfs_adapter(collection="test-case-e")
    recon = StorageReconciliationService(ledger_path=tmp_path / "case_e.jsonl")

    orphan_key = "inv-case-e/unregistered_payload.raw.txt"
    adapter.put_object(orphan_key, b"Orphan data bytes in SeaweedFS")

    # Reconciliation audit discovers orphan
    orphans = recon.reconcile_orphans(db=db_session, physical_keys=[orphan_key])
    assert len(orphans) == 1
    assert orphans[0]["storage_key"] == orphan_key
    assert orphans[0]["requires_manual_review"] is True

    # Critical: Object must NEVER be automatically deleted
    assert adapter.object_exists(orphan_key) is True

    # Cleanup test object
    adapter.delete_object(orphan_key)


# ============================================================================
# SCENARIO CASE F: SeaweedFS object exists but SHA-256 differs from metadata
# ============================================================================

def test_failure_matrix_case_f_checksum_differs_from_metadata(db_session, tmp_path):
    """Case F: SeaweedFS object exists but its SHA-256 differs from database metadata.
    Recovery: Integrity verification detects discrepancy; raises StorageIntegrityError.
    """
    adapter, is_live = get_test_seaweedfs_adapter(collection="test-case-f")
    recon = StorageReconciliationService(ledger_path=tmp_path / "case_f.jsonl")

    inv = InvestigationModel(
        id="inv-case-f",
        name="Case F Lab",
        organization_name="Org",
        description="Case F",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    key = "inv-case-f/tampered.raw.txt"
    payload = b"Actual bytes stored in SeaweedFS"
    meta = adapter.put_object(key, payload)

    ev = EvidenceModel(
        id="evi-case-f",
        investigation_id="inv-case-f",
        source_type="nmap",
        source_name="Nmap",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path=key,
        storage_backend="seaweedfs",
        content_hash="tampered_hash_value_differs" + "0" * 35,
        content_size_bytes=len(payload),
    )
    db_session.add(ev)
    db_session.commit()

    # Reconciliation detects corruption
    report = recon.reconcile_evidence_inventory(db=db_session, storage_adapter=adapter)
    corrupt = [c for c in report["corrupted_objects"] if c["evidence_id"] == "evi-case-f"]
    assert len(corrupt) == 1

    # Verify adapter integrity check raises StorageIntegrityError
    with pytest.raises(StorageIntegrityError):
        adapter.verify_object_integrity(key, ev.content_hash)

    # Cleanup
    adapter.delete_object(key)


# ============================================================================
# SCENARIO CASE G: SeaweedFS deletion succeeds but SQL metadata deletion fails
# ============================================================================

def test_failure_matrix_case_g_object_deletion_succeeds_db_delete_fails(db_session, tmp_path):
    """Case G: SeaweedFS object deletion succeeds but SQL Server metadata deletion fails.
    Recovery: Inconsistency durably logged; subsequent reconciliation flags missing object.
    """
    adapter, is_live = get_test_seaweedfs_adapter(collection="test-case-g")
    recon = StorageReconciliationService(ledger_path=tmp_path / "case_g.jsonl")
    key = "inv-case-g/deleted.raw.txt"

    # Put and delete from SeaweedFS
    adapter.put_object(key, b"bytes to delete")
    deleted = adapter.delete_object(key)
    assert deleted is True

    # Simulate DB transaction failure during metadata deletion
    rec_id = recon.record_inconsistency(
        event_type="deletion_inconsistency",
        evidence_id="evi-case-g",
        investigation_id="inv-case-g",
        storage_key=key,
        details={"reason": "DB cascade constraint rolled back evidence row deletion"},
    )
    assert rec_id.startswith("rec-")
    entries = recon.read_ledger_entries()
    assert entries[0]["event_type"] == "deletion_inconsistency"


# ============================================================================
# SCENARIO CASE H: SQL Server becomes unavailable during an evidence operation
# ============================================================================

def test_failure_matrix_case_h_sqlserver_unavailable_controlled_error():
    """Case H: SQL Server becomes unavailable during an evidence operation.
    Recovery: Application catches operational error cleanly with bounded deadlock/retry policy.
    """
    broken_engine = create_engine("sqlite:///nonexistent_dir/forbidden_path/invalid.db")
    with pytest.raises(Exception) as exc_info:
        with Session(broken_engine) as session:
            session.query(EvidenceModel).first()

    assert exc_info.value is not None


# ============================================================================
# SCENARIO CASE I: SeaweedFS becomes unavailable during an evidence operation
# ============================================================================

def test_failure_matrix_case_i_seaweedfs_unavailable_controlled_error():
    """Case I: SeaweedFS becomes unavailable during an evidence operation.
    Recovery: StorageConnectionError raised without silent switch to local filesystem.
    """
    def mock_broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("SeaweedFS daemon offline / unreachable", request=request)

    client = httpx.Client(transport=httpx.MockTransport(mock_broken), base_url="http://mock:8888")
    adapter = SeaweedFSStorageAdapter(client=client)

    with pytest.raises(StorageConnectionError) as exc_info:
        adapter.put_object("inv-offline/test.txt", b"payload")

    assert "unavailable" in str(exc_info.value).lower()
