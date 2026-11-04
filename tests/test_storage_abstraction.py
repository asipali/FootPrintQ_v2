"""Comprehensive unit and integration tests for storage abstraction, SeaweedFS adapter, and failure recovery."""

import email.utils
import hashlib
from io import BytesIO
from pathlib import Path
import time
from typing import Dict
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
# 1. KEY VALIDATION & TRAVERSAL DEFENSE
# ============================================================================

def test_validate_and_normalize_key_valid():
    assert validate_and_normalize_key("inv-123/sample.raw.txt") == "inv-123/sample.raw.txt"
    assert validate_and_normalize_key("inv-123/sub/data.json") == "inv-123/sub/data.json"
    assert validate_and_normalize_key("inv_test\\sub\\scan.bin") == "inv_test/sub/scan.bin"


def test_validate_and_normalize_key_rejects_traversal():
    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("/inv-123/sub/data.json")

    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("../etc/passwd")

    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("inv-123/../../secret.txt")

    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("inv-123/./file.txt")

    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("inv-123/.hidden")

    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("inv-123/file;malicious.txt")

    with pytest.raises(StorageSecurityError):
        validate_and_normalize_key("just_filename_without_namespace")


# ============================================================================
# 2. LOCAL FILESYSTEM ADAPTER CONTRACT & PARITY
# ============================================================================

def test_filesystem_adapter_lifecycle(tmp_path: Path):
    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    assert adapter.backend_name == "filesystem"

    key = "inv-fs-test/ev-001.raw.txt"
    payload = b"Forensic payload 123"
    expected_hash = hashlib.sha256(payload).hexdigest()

    # 1. Put object
    meta = adapter.put_object(key, payload, content_type="text/plain; charset=utf-8")
    assert meta.key == key
    assert meta.size_bytes == len(payload)
    assert meta.content_hash == expected_hash
    assert meta.backend == "filesystem"

    # 2. Existence
    assert adapter.object_exists(key) is True
    assert adapter.object_exists("inv-fs-test/non_existent.raw.txt") is False

    # 3. Immutability: duplicate put must fail
    with pytest.raises(StorageKeyExistsError):
        adapter.put_object(key, b"Overwriting attempt")

    # 4. Get object
    retrieved_bytes, get_meta = adapter.get_object(key)
    assert retrieved_bytes == payload
    assert get_meta.content_hash == expected_hash

    # 5. Metadata retrieval
    head_meta = adapter.get_object_metadata(key)
    assert head_meta.size_bytes == len(payload)
    assert head_meta.content_hash == expected_hash

    # 6. Stream object
    chunks = list(adapter.get_object_stream(key, chunk_size=8))
    assert b"".join(chunks) == payload

    # 7. Integrity verification
    assert adapter.verify_object_integrity(key, expected_hash) is True
    with pytest.raises(StorageIntegrityError):
        adapter.verify_object_integrity(key, "invalid_hash" + "0" * 52)

    # 8. Health check
    health = adapter.health_check()
    assert health.is_healthy is True
    assert health.backend == "filesystem"
    assert health.latency_ms is not None

    # 9. Delete object
    assert adapter.delete_object(key) is True
    assert adapter.object_exists(key) is False
    assert adapter.delete_object(key) is False

    with pytest.raises(StorageObjectNotFoundError):
        adapter.get_object(key)


# ============================================================================
# 3. SEAWEEDFS ADAPTER (MOCKED REST API)
# ============================================================================

class MockSeaweedFSFiler:
    """In-memory mock implementing SeaweedFS Filer HTTP REST API semantics."""

    def __init__(self, collection: str = "footprintiq"):
        self.collection = collection
        self.storage: Dict[str, bytes] = {}
        self.metadata: Dict[str, Dict[str, str]] = {}
        self.fail_mode: Optional[str] = None
        self.call_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.call_count += 1
        path = request.url.path

        if self.fail_mode == "connection_error":
            raise httpx.ConnectError("Connection refused by mock SeaweedFS daemon", request=request)
        if self.fail_mode == "timeout":
            raise httpx.TimeoutException("Read timeout from mock SeaweedFS Filer", request=request)
        if self.fail_mode == "server_503":
            return httpx.Response(503, text="Service Unavailable", request=request)

        # Health check on root
        if path in {"/", f"/{self.collection}", f"/{self.collection}/"}:
            if request.method == "GET":
                return httpx.Response(200, json={"Path": path, "Entries": []}, request=request)

        # Object path format: /{collection}/{key}
        prefix = f"/{self.collection}/"
        if not path.startswith(prefix):
            return httpx.Response(404, text="Not Found (Invalid Collection)", request=request)

        key = path[len(prefix):]

        if request.method == "HEAD":
            if key not in self.storage:
                return httpx.Response(404, request=request)
            data = self.storage[key]
            headers = {
                "Content-Length": str(len(data)),
                "Content-Type": self.metadata.get(key, {}).get("Content-Type", "application/octet-stream"),
                "X-Content-SHA256": hashlib.sha256(data).hexdigest(),
                "Last-Modified": email.utils.formatdate(time.time(), usegmt=True),
            }
            for mk, mv in self.metadata.get(key, {}).items():
                if mk.startswith("Seaweed-Meta-"):
                    headers[mk] = mv
            return httpx.Response(200, headers=headers, request=request)

        elif request.method == "GET":
            if key not in self.storage:
                return httpx.Response(404, text="Object Not Found", request=request)
            data = self.storage[key]
            headers = {
                "Content-Length": str(len(data)),
                "Content-Type": self.metadata.get(key, {}).get("Content-Type", "application/octet-stream"),
                "X-Content-SHA256": hashlib.sha256(data).hexdigest(),
                "Last-Modified": email.utils.formatdate(time.time(), usegmt=True),
            }
            return httpx.Response(200, content=data, headers=headers, request=request)

        elif request.method in {"PUT", "POST"}:
            body = request.read()
            self.storage[key] = body
            meta = {"Content-Type": request.headers.get("Content-Type", "application/octet-stream")}
            for h_k, h_v in request.headers.items():
                if h_k.lower().startswith("seaweed-meta-"):
                    meta[h_k] = h_v
            self.metadata[key] = meta
            return httpx.Response(201, json={"name": key, "size": len(body)}, request=request)

        elif request.method == "DELETE":
            if key in self.storage:
                del self.storage[key]
                self.metadata.pop(key, None)
                return httpx.Response(204, request=request)
            return httpx.Response(404, text="Not Found", request=request)

        return httpx.Response(405, text="Method Not Allowed", request=request)


@pytest.fixture
def mock_seaweedfs():
    filer = MockSeaweedFSFiler(collection="footprintiq")
    transport = httpx.MockTransport(filer.handle_request)
    client = httpx.Client(transport=transport, base_url="http://mock-seaweedfs:8888")
    adapter = SeaweedFSStorageAdapter(
        filer_url="http://mock-seaweedfs:8888",
        collection="footprintiq",
        timeout=2.0,
        max_retries=2,
        client=client,
    )
    yield adapter, filer
    adapter.close()


def test_seaweedfs_adapter_crud(mock_seaweedfs):
    adapter, filer = mock_seaweedfs
    key = "inv-seaweed-1/ev-sample.raw.txt"
    payload = b"SeaweedFS raw evidence bytes"
    expected_hash = hashlib.sha256(payload).hexdigest()

    # 1. Put object
    meta = adapter.put_object(
        key=key,
        data=payload,
        content_type="text/plain; charset=utf-8",
        metadata={"investigation_id": "inv-seaweed-1"},
    )
    assert meta.key == key
    assert meta.size_bytes == len(payload)
    assert meta.content_hash == expected_hash
    assert meta.backend == "seaweedfs"

    # 2. Exists
    assert adapter.object_exists(key) is True
    assert adapter.object_exists("inv-seaweed-1/missing.raw.txt") is False

    # 3. Immutability
    with pytest.raises(StorageKeyExistsError):
        adapter.put_object(key, b"Conflict attempt")

    # 4. Get object
    retrieved_bytes, get_meta = adapter.get_object(key)
    assert retrieved_bytes == payload
    assert get_meta.content_hash == expected_hash

    # 5. Metadata
    head_meta = adapter.get_object_metadata(key)
    assert head_meta.size_bytes == len(payload)

    # 6. Streaming
    chunks = list(adapter.get_object_stream(key, chunk_size=10))
    assert b"".join(chunks) == payload

    # 7. Integrity
    assert adapter.verify_object_integrity(key, expected_hash) is True
    with pytest.raises(StorageIntegrityError):
        adapter.verify_object_integrity(key, "wrong_hash" + "0" * 54)

    # 8. Health check
    health = adapter.health_check()
    assert health.is_healthy is True
    assert health.backend == "seaweedfs"

    # 9. Delete
    assert adapter.delete_object(key) is True
    assert adapter.object_exists(key) is False
    assert adapter.delete_object(key) is False


def test_seaweedfs_adapter_network_failure_handling(mock_seaweedfs):
    adapter, filer = mock_seaweedfs
    filer.fail_mode = "connection_error"

    with pytest.raises(StorageConnectionError):
        adapter.put_object("inv-fail/ev-01.raw.txt", b"Test")

    with pytest.raises(StorageConnectionError):
        adapter.get_object("inv-fail/ev-01.raw.txt")

    health = adapter.health_check()
    assert health.is_healthy is False
    assert "unreachable" in health.details.lower() or "connection" in health.details.lower()


def test_seaweedfs_adapter_http_503_retry_and_exhaustion(mock_seaweedfs):
    adapter, filer = mock_seaweedfs
    filer.fail_mode = "server_503"

    with pytest.raises(StorageConnectionError):
        adapter.get_object("inv-fail/ev-02.raw.txt")

    # Confirms retries took place up to max_retries
    assert filer.call_count >= 2


# ============================================================================
# 4. EVIDENCE STORE INTEGRATION & DUAL-READ
# ============================================================================

def test_evidence_store_delegates_to_adapter(tmp_path: Path):
    store = EvidenceStore(base_path=str(tmp_path))
    rel_path, content_hash, size_bytes = store.store_evidence(
        investigation_id="inv-es-01",
        evidence_id="evi-test-99",
        source_type="dns",
        content={"records": ["1.1.1.1", "8.8.8.8"]},
    )

    assert rel_path == "inv-es-01/evi-test-99_dns.raw.json"
    assert len(content_hash) == 64
    assert size_bytes > 0

    read_bytes, verified_hash = store.read_evidence(rel_path)
    assert verified_hash == content_hash
    assert b"1.1.1.1" in read_bytes


def test_evidence_store_dual_read_fallback(tmp_path: Path):
    # Setup local file
    local_adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    key = "inv-dual/ev-local.raw.txt"
    payload = b"Local filesystem original content"
    local_adapter.put_object(key, payload)

    # Setup SeaweedFS adapter with empty storage
    filer = MockSeaweedFSFiler(collection="footprintiq")
    transport = httpx.MockTransport(filer.handle_request)
    client = httpx.Client(transport=transport, base_url="http://mock-seaweedfs:8888")
    seaweed_adapter = SeaweedFSStorageAdapter(
        filer_url="http://mock-seaweedfs:8888",
        collection="footprintiq",
        client=client,
    )

    # Store with SeaweedFS as primary, but fallback enabled
    store = EvidenceStore(adapter=seaweed_adapter)
    store.settings = Settings(
        STORAGE_BACKEND="seaweedfs",
        EVIDENCE_STORAGE_PATH=str(tmp_path),
        SEAWEEDFS_FALLBACK_TO_FILESYSTEM=True,
    )

    # Attempt to read object: missing in SeaweedFS, fallback succeeds from local filesystem
    read_bytes, computed_hash = store.read_evidence(key)
    assert read_bytes == payload
    assert computed_hash == hashlib.sha256(payload).hexdigest()

    # When fallback is disabled, must raise FileNotFoundError
    store.settings = Settings(
        STORAGE_BACKEND="seaweedfs",
        EVIDENCE_STORAGE_PATH=str(tmp_path),
        SEAWEEDFS_FALLBACK_TO_FILESYSTEM=False,
    )
    with pytest.raises(FileNotFoundError):
        store.read_evidence(key)


# ============================================================================
# 5. FAILURE RECOVERY & RECONCILIATION SCENARIOS
# ============================================================================

def test_failure_recovery_case_a_compensation_and_reconciliation(tmp_path: Path):
    """Case A: Upload succeeds, DB transaction fails -> compensating deletion or durable reconciliation."""
    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    reconciliation = StorageReconciliationService(ledger_path=tmp_path / "recon.jsonl")

    key = "inv-case-a/ev-orphan.raw.txt"
    adapter.put_object(key, b"Payload needing rollback")
    assert adapter.object_exists(key) is True

    # Compensating deletion
    deleted = adapter.delete_object(key)
    assert deleted is True
    assert adapter.object_exists(key) is False

    # Simulate failed compensation: durably record reconciliation entry
    rec_id = reconciliation.record_inconsistency(
        event_type="failed_compensation",
        evidence_id="ev-orphan",
        investigation_id="inv-case-a",
        storage_key=key,
        details={"reason": "Simulated DB transaction rollback failure"},
    )
    assert rec_id.startswith("rec-")
    assert (tmp_path / "recon.jsonl").exists()
    assert "failed_compensation" in (tmp_path / "recon.jsonl").read_text(encoding="utf-8")


def test_failure_recovery_case_c_d_reconciliation_scanner(db_session, tmp_path: Path):
    """Case C & D: Reconciling missing objects and detecting corruption."""
    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    reconciliation = StorageReconciliationService(ledger_path=tmp_path / "recon_scan.jsonl")

    # 0. Create parent investigation record
    inv = InvestigationModel(
        id="inv-test-recon",
        name="Reconciliation Test Lab",
        organization_name="Test Org",
        description="Testing reconciliation scanner",
        lead_investigator="Test Lead",
        status="active",
    )
    db_session.add(inv)
    db_session.commit()

    # 1. Create DB record pointing to missing storage file (Case D)
    missing_ev = EvidenceModel(
        id="evi-case-d-missing",
        investigation_id="inv-test-recon",
        source_type="nmap",
        source_name="Nmap Test",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path="inv-test-recon/missing_on_disk.raw.txt",
        storage_backend="filesystem",
        content_hash="deadbeef" * 8,
        content_size_bytes=100,
    )
    db_session.add(missing_ev)

    # 2. Create DB record with corrupted storage bytes
    corrupt_key = "inv-test-recon/corrupt_file.raw.txt"
    adapter.put_object(corrupt_key, b"Actual bytes on disk")
    corrupt_ev = EvidenceModel(
        id="evi-corrupt",
        investigation_id="inv-test-recon",
        source_type="nmap",
        source_name="Nmap Test",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path=corrupt_key,
        storage_backend="filesystem",
        content_hash="mismatched_hash" + "0" * 49,
        content_size_bytes=20,
    )
    db_session.add(corrupt_ev)

    # 3. Create metadata-only record (must be ignored by object check)
    meta_ev = EvidenceModel(
        id="evi-meta-only",
        investigation_id="inv-test-recon",
        source_type="dns_collector",
        source_name="DNS",
        target="example.com",
        collection_status="SUCCESS",
        raw_content_path=None,
        storage_backend="filesystem",
        content_hash="meta_only_hash" + "0" * 50,
        content_size_bytes=50,
    )
    db_session.add(meta_ev)
    db_session.commit()

    # Run reconciliation audit
    report = reconciliation.reconcile_evidence_inventory(db=db_session, storage_adapter=adapter)

    assert report["checked_records"] == 2
    assert report["metadata_only_records"] == 1
    assert len(report["missing_objects"]) == 1
    assert report["missing_objects"][0]["evidence_id"] == "evi-case-d-missing"
    assert len(report["corrupted_objects"]) == 1
    assert report["corrupted_objects"][0]["evidence_id"] == "evi-corrupt"


# ============================================================================
# 6. STORAGE FACTORY & LIFECYCLE TESTS
# ============================================================================

def test_storage_factory_selection(tmp_path: Path):
    close_storage_adapters()

    # Filesystem selection
    fs_settings = Settings(
        STORAGE_BACKEND="filesystem",
        EVIDENCE_STORAGE_PATH=str(tmp_path / "factory_fs"),
    )
    fs_adapter = get_storage_adapter(settings=fs_settings, force_new=True)
    assert isinstance(fs_adapter, LocalFilesystemStorageAdapter)
    assert fs_adapter.backend_name == "filesystem"

    # SeaweedFS selection
    sw_settings = Settings(
        STORAGE_BACKEND="seaweedfs",
        SEAWEEDFS_FILER_URL="http://localhost:8888",
    )
    sw_adapter = get_storage_adapter(settings=sw_settings, force_new=True)
    assert isinstance(sw_adapter, SeaweedFSStorageAdapter)
    assert sw_adapter.backend_name == "seaweedfs"
    sw_adapter.close()

    # Invalid backend selection
    with pytest.raises(ValueError):
        get_storage_adapter(backend_override="invalid_backend", force_new=True)

    close_storage_adapters()


def test_failure_recovery_case_f_deletion_inconsistency(tmp_path: Path):
    """Case F: Object deleted from storage, DB transaction fails -> durable record created."""
    reconciliation = StorageReconciliationService(ledger_path=tmp_path / "recon_f.jsonl")
    key = "inv-case-f/ev-deleted.raw.txt"

    rec_id = reconciliation.record_inconsistency(
        event_type="deletion_inconsistency",
        evidence_id="ev-deleted",
        investigation_id="inv-case-f",
        storage_key=key,
        details={"error": "Database delete constraint failure on parent cascade"},
    )
    assert rec_id.startswith("rec-")
    assert (tmp_path / "recon_f.jsonl").exists()
    assert "deletion_inconsistency" in (tmp_path / "recon_f.jsonl").read_text(encoding="utf-8")

