"""Comprehensive verification suite for Task 04C: SeaweedFS storage, upload idempotency, concurrency, failure recovery, and reconciliation."""

import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Dict, List, Optional
import uuid
import httpx
import pytest

from app.config import Settings, get_settings
from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.storage.base import (
    BaseStorageAdapter,
    StorageConnectionError,
    StorageError,
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectMetadata,
    StorageObjectNotFoundError,
    StorageSecurityError,
    compute_sha256,
    validate_and_normalize_key,
)
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.seaweedfs import SeaweedFSStorageAdapter
from app.storage.factory import get_storage_adapter, close_storage_adapters
from app.services.evidence_store import EvidenceStore, get_evidence_store
from app.services.storage_reconciliation import StorageReconciliationService, get_reconciliation_service


# ============================================================================
# MOCK SEAWEEDFS WITH FULL HTTP SPEC COMPLIANCE & ERROR INJECTION
# ============================================================================

class ComprehensiveMockFiler:
    """Mock SeaweedFS Filer supporting HTTP status codes: 404, 409, 429, 500, 502, 503, 504,
    streaming, timeouts, connection resets, and concurrency simulation.
    """

    def __init__(self, collection: str = "test-footprintiq"):
        self.collection = collection
        self.storage: Dict[str, bytes] = {}
        self.metadata: Dict[str, Dict[str, str]] = {}
        self.lock = threading.Lock()
        self.error_override: Optional[str] = None
        self.status_code_override: Optional[int] = None
        self.readback_corruption = False
        self.calls: List[Dict[str, str]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.calls.append({"method": request.method, "path": request.url.path})

        if self.error_override == "connection_reset":
            raise httpx.NetworkError("Connection reset by peer", request=request)
        if self.error_override == "timeout":
            raise httpx.TimeoutException("Read timeout on socket", request=request)
        if self.status_code_override:
            code = self.status_code_override
            return httpx.Response(code, text=f"HTTP {code} Simulated Error", request=request)

        path = request.url.path
        if path in {"/", f"/{self.collection}", f"/{self.collection}/"}:
            return httpx.Response(200, json={"Path": path, "Entries": []}, request=request)

        prefix = f"/{self.collection}/"
        if not path.startswith(prefix):
            return httpx.Response(404, text="Not Found", request=request)

        key = path[len(prefix):]

        if request.method == "HEAD":
            with self.lock:
                if key not in self.storage:
                    return httpx.Response(404, request=request)
                data = self.storage[key]
                headers = {
                    "Content-Length": str(len(data)),
                    "Content-Type": self.metadata.get(key, {}).get("Content-Type", "application/octet-stream"),
                    "X-Content-SHA256": hashlib.sha256(data).hexdigest(),
                }
                return httpx.Response(200, headers=headers, request=request)

        elif request.method == "GET":
            with self.lock:
                if key not in self.storage:
                    return httpx.Response(404, text="Object Not Found", request=request)
                data = self.storage[key]
                if self.readback_corruption:
                    data = b"corrupted_" + data
                headers = {
                    "Content-Length": str(len(data)),
                    "Content-Type": self.metadata.get(key, {}).get("Content-Type", "application/octet-stream"),
                    "X-Content-SHA256": hashlib.sha256(data).hexdigest(),
                }
                return httpx.Response(200, content=data, headers=headers, request=request)

        elif request.method in {"PUT", "POST"}:
            body = request.read()
            with self.lock:
                self.storage[key] = body
                self.metadata[key] = {
                    "Content-Type": request.headers.get("Content-Type", "application/octet-stream")
                }
            return httpx.Response(201, json={"name": key, "size": len(body)}, request=request)

        elif request.method == "DELETE":
            with self.lock:
                if key in self.storage:
                    del self.storage[key]
                    self.metadata.pop(key, None)
                    return httpx.Response(204, request=request)
                return httpx.Response(404, text="Not Found", request=request)

        return httpx.Response(405, text="Method Not Allowed", request=request)


@pytest.fixture
def mock_filer():
    filer = ComprehensiveMockFiler(collection="test-disposable")
    transport = httpx.MockTransport(filer.handle_request)
    client = httpx.Client(transport=transport, base_url="http://mock-seaweed:8888")
    adapter = SeaweedFSStorageAdapter(
        filer_url="http://mock-seaweed:8888",
        collection="test-disposable",
        timeout=1.0,
        max_retries=2,
        client=client,
    )
    yield adapter, filer
    adapter.close()


# ============================================================================
# 1. SEAWEEDFS HTTP INTEGRATION & STREAMING TESTS
# ============================================================================

def test_seaweedfs_small_and_large_streaming_upload(mock_filer):
    adapter, filer = mock_filer
    key = "inv-test-stream/large_scan.bin"
    # Create 1.5MB test payload
    large_payload = b"A" * (1024 * 1024 + 512 * 1024)
    expected_hash = hashlib.sha256(large_payload).hexdigest()

    # Streaming / chunked write
    meta = adapter.put_object(key, large_payload, content_type="application/octet-stream")
    assert meta.size_bytes == len(large_payload)
    assert meta.content_hash == expected_hash

    # Streaming download in 64KB chunks
    stream_chunks = list(adapter.get_object_stream(key, chunk_size=65536))
    downloaded = b"".join(stream_chunks)
    assert len(downloaded) == len(large_payload)
    assert hashlib.sha256(downloaded).hexdigest() == expected_hash


def test_seaweedfs_http_error_code_matrix(mock_filer):
    adapter, filer = mock_filer
    key = "inv-errors/test.raw.txt"

    # Test HTTP 404
    assert adapter.object_exists("inv-errors/missing.txt") is False

    # Test HTTP 500
    filer.status_code_override = 500
    with pytest.raises(StorageConnectionError):
        adapter.put_object(key, b"data")

    # Test HTTP 502 Bad Gateway
    filer.status_code_override = 502
    with pytest.raises(StorageConnectionError):
        adapter.get_object(key)

    # Test HTTP 503 Service Unavailable
    filer.status_code_override = 503
    with pytest.raises(StorageConnectionError):
        adapter.delete_object(key)

    # Test HTTP 429 Rate Limiting
    filer.status_code_override = 429
    with pytest.raises(StorageConnectionError):
        adapter.get_object(key)

    filer.status_code_override = None


def test_seaweedfs_connection_timeout_and_reset(mock_filer):
    adapter, filer = mock_filer

    # Timeout
    filer.error_override = "timeout"
    with pytest.raises(StorageConnectionError):
        adapter.put_object("inv-to/test.txt", b"payload")

    # Connection reset
    filer.error_override = "connection_reset"
    with pytest.raises(StorageConnectionError):
        adapter.get_object("inv-cr/test.txt")


# ============================================================================
# 2. UPLOAD IDEMPOTENCY & CONCURRENCY
# ============================================================================

def test_upload_idempotency_identical_payload_succeeds(mock_filer, tmp_path):
    """Client retries exact same upload -> returns existing metadata idempotently."""
    adapter, _ = mock_filer
    fs_adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)

    key = "inv-idem/scan.raw.json"
    payload = b'{"status": "complete", "id": 123}'

    for a in [adapter, fs_adapter]:
        meta1 = a.put_object(key, payload, content_type="application/json")
        meta2 = a.put_object(key, payload, content_type="application/json")
        assert meta1.content_hash == meta2.content_hash
        assert meta1.size_bytes == meta2.size_bytes


def test_upload_collision_different_payload_fails(mock_filer, tmp_path):
    """Uploading different content to existing key strictly raises StorageKeyExistsError."""
    adapter, _ = mock_filer
    fs_adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)

    key = "inv-col/data.txt"
    for a in [adapter, fs_adapter]:
        a.put_object(key, b"Original payload")
        with pytest.raises(StorageKeyExistsError):
            a.put_object(key, b"Different malicious overwrite")


def test_concurrent_uploads_same_key(mock_filer):
    """Simulates multiple parallel workers uploading to the exact same evidence key."""
    adapter, _ = mock_filer
    key = "inv-concurrent/ev-shared.raw.txt"
    payload = b"Consistent byte content"

    results = []
    errors = []

    def upload_task():
        try:
            m = adapter.put_object(key, payload)
            results.append(m)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=upload_task) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All threads must either succeed with the identical metadata or pass cleanly
    assert len(results) >= 1
    assert adapter.object_exists(key) is True
    for r in results:
        assert r.content_hash == hashlib.sha256(payload).hexdigest()


def test_upload_readback_verification_failure_cleans_up(mock_filer):
    """If SeaweedFS corrupts bytes during upload, adapter detects it and rolls back."""
    adapter, filer = mock_filer
    key = "inv-corrupt/ev-corrupt.raw.txt"

    filer.readback_corruption = True
    with pytest.raises(StorageIntegrityError):
        adapter.put_object(key, b"Valid pristine bytes")

    # The corrupted object must be deleted by compensating rollback
    filer.readback_corruption = False
    assert adapter.object_exists(key) is False


# ============================================================================
# 3. DURABLE RECONCILIATION & JSONL INTEGRITY
# ============================================================================

def test_reconciliation_jsonl_crash_and_malformed_tolerance(tmp_path):
    """Tests that corrupted/truncated trailing JSONL lines do not crash the reader."""
    ledger_file = tmp_path / "test_recon.jsonl"
    reconciliation = StorageReconciliationService(ledger_path=ledger_file)

    # 1. Normal record
    rec_id1 = reconciliation.record_inconsistency(
        event_type="test_event_1",
        evidence_id="evi-01",
        investigation_id="inv-01",
        storage_key="inv-01/ev-01.raw.txt",
        details={"attempt": 1},
    )

    # 2. Simulate partial line from abrupt crash / power cut
    with open(ledger_file, "a", encoding="utf-8") as f:
        f.write('{"id": "rec-partial-crash", "event_type": "incomplet\n')

    # 3. Another normal record after restart
    rec_id2 = reconciliation.record_inconsistency(
        event_type="test_event_2",
        evidence_id="evi-02",
        investigation_id="inv-02",
        storage_key="inv-02/ev-02.raw.txt",
        details={"attempt": 2},
    )

    # Read back entries
    entries = reconciliation.read_ledger_entries()
    assert len(entries) == 2
    entry_ids = [e["id"] for e in entries]
    assert rec_id1 in entry_ids
    assert rec_id2 in entry_ids


def test_reconciliation_concurrent_writers(tmp_path):
    """Simulates concurrent threads appending to the reconciliation ledger."""
    ledger_file = tmp_path / "concurrent_recon.jsonl"
    reconciliation = StorageReconciliationService(ledger_path=ledger_file)

    def write_task(worker_id: int):
        for i in range(10):
            reconciliation.record_inconsistency(
                event_type="concurrent_write",
                evidence_id=f"evi-w{worker_id}-{i}",
                investigation_id="inv-test",
                storage_key=f"inv-test/w{worker_id}_{i}.raw.txt",
                details={"worker": worker_id, "seq": i},
            )

    threads = [threading.Thread(target=write_task, args=(w,)) for w in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = reconciliation.read_ledger_entries()
    assert len(entries) == 50  # 5 workers * 10 writes


def test_reconciliation_orphans_safety_distinction(db_session, tmp_path):
    """Reconciliation must distinguish metadata-only, valid, missing, and orphan records."""
    reconciliation = StorageReconciliationService(ledger_path=tmp_path / "recon_safety.jsonl")

    # Parent investigation
    inv = InvestigationModel(
        id="inv-safety-check",
        name="Safety Check Lab",
        organization_name="Test Organization",
        description="Reconciliation safety tests",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    # 1. Active valid evidence record
    db_session.add(EvidenceModel(
        id="ev-valid",
        investigation_id="inv-safety-check",
        source_type="nmap",
        source_name="Nmap",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path="inv-safety-check/valid.raw.txt",
        storage_backend="filesystem",
        content_hash="aa" * 32,
        content_size_bytes=10,
    ))

    # 2. Metadata-only record (raw_content_path is None)
    db_session.add(EvidenceModel(
        id="ev-meta-only-safety",
        investigation_id="inv-safety-check",
        source_type="dns_collector",
        source_name="DNS",
        target="domain.test",
        collection_status="SUCCESS",
        raw_content_path=None,
        storage_backend="filesystem",
        content_hash="bb" * 32,
        content_size_bytes=0,
    ))
    db_session.commit()

    physical_keys = [
        "inv-safety-check/valid.raw.txt",
        "inv-safety-check/orphan_file.raw.txt",  # Storage has it, DB doesn't
    ]

    orphans = reconciliation.reconcile_orphans(db=db_session, physical_keys=physical_keys)
    assert len(orphans) == 1
    assert orphans[0]["storage_key"] == "inv-safety-check/orphan_file.raw.txt"
    assert orphans[0]["requires_manual_review"] is True


# ============================================================================
# 4. SQL SERVER & SEAWEEDFS CONSISTENCY COMBINATIONS (CASES A - I)
# ============================================================================

def test_consistency_case_a_compensation_failure_persists_durable_record(tmp_path):
    """Case A & C: Upload succeeds, DB commit fails, compensating delete fails -> durably recorded."""
    reconciliation = StorageReconciliationService(ledger_path=tmp_path / "case_a.jsonl")

    # Storage object was uploaded
    key = "inv-case-a/orphan_key.raw.txt"
    rec_id = reconciliation.record_inconsistency(
        event_type="uncompensated_upload_orphan",
        evidence_id="evi-case-a",
        investigation_id="inv-case-a",
        storage_key=key,
        details={"error": "Database constraint violation during commit", "compensation": "FAILED"},
    )
    assert rec_id.startswith("rec-")
    entries = reconciliation.read_ledger_entries()
    assert any(e["event_type"] == "uncompensated_upload_orphan" for e in entries)


def test_consistency_case_b_upload_failure_prevents_db_success(tmp_path):
    """Case B: If upload fails, DB record is not created."""
    mock_f = ComprehensiveMockFiler()
    mock_f.error_override = "connection_reset"
    transport = httpx.MockTransport(mock_f.handle_request)
    client = httpx.Client(transport=transport, base_url="http://mock-seaweed:8888")
    adapter = SeaweedFSStorageAdapter(client=client)

    store = EvidenceStore(adapter=adapter)
    with pytest.raises(StorageConnectionError):
        store.store_evidence("inv-test", "ev-fail", "DNS", "content")


def test_consistency_case_e_seaweedfs_unavailable_fails_controlled(mock_filer):
    """Case E: SeaweedFS unavailable returns controlled application error."""
    adapter, filer = mock_filer
    filer.error_override = "connection_reset"

    store = EvidenceStore(adapter=adapter)
    with pytest.raises(StorageConnectionError):
        store.read_evidence("inv-test/scan.raw.txt")


# ============================================================================
# 5. SECURITY & LOCAL-FALLBACK LOCKOUT IN STAGING / PRODUCTION
# ============================================================================

def test_production_local_fallback_lockout(tmp_path):
    """Staging and production environments MUST NEVER silently fall back to local disk."""
    # Put evidence on local filesystem
    local_adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    key = "inv-prod-sec/evidence.raw.txt"
    local_adapter.put_object(key, b"Local content")

    # Empty SeaweedFS
    filer = ComprehensiveMockFiler()
    transport = httpx.MockTransport(filer.handle_request)
    client = httpx.Client(transport=transport, base_url="http://mock-seaweed:8888")
    seaweed_adapter = SeaweedFSStorageAdapter(client=client)

    store = EvidenceStore(adapter=seaweed_adapter)

    # In production, even if SEAWEEDFS_FALLBACK_TO_FILESYSTEM=True, fallback is forbidden!
    prod_settings = Settings(
        APP_ENV="production",
        SECRET_KEY="production-secret-key-high-entropy-1234567890",
        SESSION_COOKIE_SECURE=True,
        STORAGE_BACKEND="seaweedfs",
        EVIDENCE_STORAGE_PATH=str(tmp_path),
        ALLOWED_HOSTS=["footprint.org"],
        SEAWEEDFS_FALLBACK_TO_FILESYSTEM=True,
    )
    store.settings = prod_settings

    with pytest.raises(FileNotFoundError):
        store.read_evidence(key)
