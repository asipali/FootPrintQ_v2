"""20-scenario comprehensive verification test suite for STEP 2: Centralized Evidence Storage Architecture.

Covers:
1. Normal evidence upload to SeaweedFS
2. Normal evidence retrieval from SeaweedFS
3. SeaweedFS connection error during upload
4. SeaweedFS HTTP 500 error during upload
5. SeaweedFS HTTP 503 error during upload
6. SeaweedFS 404 error during retrieval
7. Fallback to filesystem enabled (dev/test)
8. Fallback to filesystem disabled / production lockout
9. Actual backend recorded in metadata
10. SHA-256 generation on write
11. SHA-256 verification on read
12. SHA-256 mismatch detection on read
13. Path traversal rejection
14. Storage key collision prevention
15. Storage key idempotency
16. Backward-compatible retrieval (filesystem under SeaweedFS config)
17. Backward-compatible retrieval (SeaweedFS with explicit backend)
18. Evidence streaming in chunks
19. Multiple investigations isolation
20. Storage health check reports
"""

import hashlib
from io import BytesIO
from pathlib import Path
import threading
from typing import Dict, List, Optional
import httpx
import pytest

from app.config import Settings
from app.services.evidence_store import EvidenceStore, StoredEvidenceResult
from app.storage.base import (
    StorageConnectionError,
    StorageHealthStatus,
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectMetadata,
    StorageObjectNotFoundError,
    StorageSecurityError,
    compute_sha256,
)
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.seaweedfs import SeaweedFSStorageAdapter


class MockFilerTransport(httpx.BaseTransport):
    """Hermetic mock for SeaweedFS HTTP Filer API."""

    def __init__(self):
        self.storage: Dict[str, bytes] = {}
        self.metadata: Dict[str, Dict[str, str]] = {}
        self.lock = threading.Lock()
        self.error_mode: Optional[str] = None
        self.call_history: List[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            method = request.method
            path = request.url.path
            self.call_history.append(f"{method} {path}")

            if self.error_mode == "connection_error":
                raise httpx.ConnectError("Connection refused by mock filer")
            if self.error_mode == "http_500":
                return httpx.Response(500, text="Internal Server Error")
            if self.error_mode == "http_503":
                return httpx.Response(503, text="Service Unavailable")

            if method in {"PUT", "POST"}:
                content = request.read()
                self.storage[path] = content
                digest = hashlib.sha256(content).hexdigest()
                return httpx.Response(
                    201,
                    json={"name": path.split("/")[-1], "size": len(content), "eTag": digest},
                    headers={"ETag": digest, "X-Content-SHA256": digest},
                )

            elif method == "GET":
                if path not in self.storage:
                    return httpx.Response(404, text="File Not Found")
                payload = self.storage[path]
                digest = hashlib.sha256(payload).hexdigest()
                return httpx.Response(
                    200,
                    content=payload,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(payload)),
                        "ETag": digest,
                        "X-Content-SHA256": digest,
                    },
                )

            elif method == "HEAD":
                if path not in self.storage:
                    return httpx.Response(404)
                payload = self.storage[path]
                digest = hashlib.sha256(payload).hexdigest()
                return httpx.Response(
                    200,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(payload)),
                        "ETag": digest,
                        "X-Content-SHA256": digest,
                    },
                )

            elif method == "DELETE":
                if path in self.storage:
                    del self.storage[path]
                    return httpx.Response(204)
                return httpx.Response(404)

            return httpx.Response(405)


@pytest.fixture
def mock_filer():
    return MockFilerTransport()


@pytest.fixture
def mock_seaweed_adapter(mock_filer):
    client = httpx.Client(
        transport=mock_filer,
        base_url="http://mock-filer:8888",
        timeout=2.0,
    )
    adapter = SeaweedFSStorageAdapter(
        filer_url="http://mock-filer:8888",
        collection="evidence",
        max_retries=2,
        client=client,
    )
    return adapter


# 1. Normal evidence upload to SeaweedFS
def test_scenario_01_normal_upload_seaweedfs(mock_seaweed_adapter):
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    payload = {"scan": "complete", "open_ports": [22, 80, 443]}
    res = store.store_evidence("inv-test-01", "ev-01", "nmap", payload)

    assert isinstance(res, StoredEvidenceResult)
    assert res.backend == "seaweedfs"
    assert res.key.startswith("inv-test-01/")
    assert len(res.content_hash) == 64
    assert res.size_bytes > 0


# 2. Normal evidence retrieval from SeaweedFS
def test_scenario_02_normal_retrieval_seaweedfs(mock_seaweed_adapter):
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    payload = "Cryptographic forensic record"
    res = store.store_evidence("inv-test-02", "ev-02", "recon", payload)

    content, computed_hash = store.read_evidence(res.key)
    assert content.decode("utf-8") == payload
    assert computed_hash == res.content_hash


# 3. SeaweedFS connection error during upload
def test_scenario_03_connection_error_upload(mock_filer, mock_seaweed_adapter):
    mock_filer.error_mode = "connection_error"
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    # Ensure fallback is disabled
    store.settings.SEAWEEDFS_FALLBACK_TO_FILESYSTEM = False

    with pytest.raises(StorageConnectionError):
        store.store_evidence("inv-test-03", "ev-03", "active", "sample")


# 4. SeaweedFS HTTP 500 error during upload
def test_scenario_04_http_500_upload(mock_filer, mock_seaweed_adapter):
    mock_filer.error_mode = "http_500"
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    store.settings.SEAWEEDFS_FALLBACK_TO_FILESYSTEM = False

    with pytest.raises(StorageConnectionError):
        store.store_evidence("inv-test-04", "ev-04", "active", "sample")


# 5. SeaweedFS HTTP 503 error during upload
def test_scenario_05_http_503_upload_retry_exhaustion(mock_filer, mock_seaweed_adapter):
    mock_filer.error_mode = "http_503"
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    store.settings.SEAWEEDFS_FALLBACK_TO_FILESYSTEM = False

    with pytest.raises(StorageConnectionError):
        store.store_evidence("inv-test-05", "ev-05", "active", "sample")
    # Verify retries were executed
    assert len(mock_filer.call_history) >= 2


# 6. SeaweedFS 404 error during retrieval
def test_scenario_06_not_found_retrieval(mock_seaweed_adapter):
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    store.settings.SEAWEEDFS_FALLBACK_TO_FILESYSTEM = False

    with pytest.raises(FileNotFoundError):
        store.read_evidence("inv-test-06/missing_evidence.raw.txt")


# 7. Fallback to filesystem enabled (dev/test)
def test_scenario_07_fallback_to_filesystem_enabled(tmp_path, mock_filer, mock_seaweed_adapter, monkeypatch):
    mock_filer.error_mode = "connection_error"
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    monkeypatch.setattr(store.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", True)
    monkeypatch.setattr(store.settings, "APP_ENV", "development")
    monkeypatch.setattr(store.settings, "EVIDENCE_STORAGE_PATH", str(tmp_path))

    res = store.store_evidence("inv-test-07", "ev-07", "recon", "fallback content")
    assert res.backend == "filesystem"
    assert (tmp_path / res.key).is_file()


# 8. Fallback to filesystem disabled / production lockout
def test_scenario_08_fallback_lockout_in_production(tmp_path, mock_filer, mock_seaweed_adapter, monkeypatch):
    mock_filer.error_mode = "connection_error"
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    monkeypatch.setattr(store.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", True)
    monkeypatch.setattr(store.settings, "APP_ENV", "production")  # Strict production lockout

    with pytest.raises(StorageConnectionError):
        store.store_evidence("inv-test-08", "ev-08", "recon", "payload")


# 9. Actual backend recorded in metadata
def test_scenario_09_actual_backend_in_metadata(tmp_path, mock_seaweed_adapter):
    seaweed_store = EvidenceStore(adapter=mock_seaweed_adapter)
    res_sw = seaweed_store.store_evidence("inv-test-09", "ev-sw", "recon", "sw payload")
    assert res_sw.backend == "seaweedfs"

    fs_store = EvidenceStore(base_path=str(tmp_path))
    res_fs = fs_store.store_evidence("inv-test-09", "ev-fs", "recon", "fs payload")
    assert res_fs.backend == "filesystem"


# 10. SHA-256 generation on write
def test_scenario_10_sha256_generation_on_write(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    payload = b"\x00\x01\x02\x03\x04\x05binary_payload"
    expected_hash = hashlib.sha256(payload).hexdigest()

    _, content_hash, size = store.store_evidence("inv-test-10", "ev-10", "binary", payload)
    assert content_hash == expected_hash
    assert size == len(payload)


# 11. SHA-256 verification on read
def test_scenario_11_sha256_verification_on_read(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    res = store.store_evidence("inv-test-11", "ev-11", "text", "safe content")

    assert store.verify_evidence(res.key, res.content_hash) is True


# 12. SHA-256 mismatch detection on read
def test_scenario_12_sha256_mismatch_tampering(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    res = store.store_evidence("inv-test-12", "ev-12", "text", "original content")

    # Tamper with the raw file directly
    target_file = tmp_path / res.key
    target_file.write_bytes(b"tampered content")

    with pytest.raises(StorageIntegrityError):
        store.verify_evidence(res.key, res.content_hash)


# 13. Path traversal rejection
def test_scenario_13_path_traversal_rejection(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))

    with pytest.raises(ValueError):
        store.store_evidence("../../windows", "ev-bad", "recon", "data")

    with pytest.raises(ValueError):
        store.store_evidence("inv-13", "../bad-ev", "recon", "data")

    with pytest.raises(ValueError):
        store.read_evidence("../../etc/passwd")


# 14. Storage key collision prevention
def test_scenario_14_collision_prevention(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    store.store_evidence("inv-test-14", "ev-fixed", "audit", "first content")

    with pytest.raises(StorageKeyExistsError):
        store.store_evidence("inv-test-14", "ev-fixed", "audit", "different content")


# 15. Storage key idempotency
def test_scenario_15_idempotency_identical_payload(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    res1 = store.store_evidence("inv-test-15", "ev-idem", "audit", "same content")
    # Repeated store with identical content succeeds idempotently
    res2 = store.store_evidence("inv-test-15", "ev-idem", "audit", "same content")

    assert res1.key == res2.key
    assert res1.content_hash == res2.content_hash


# 16. Backward-compatible retrieval (filesystem under SeaweedFS config)
def test_scenario_16_backward_compatibility_filesystem_fallback(tmp_path, mock_seaweed_adapter, monkeypatch):
    # Store legacy file directly on local filesystem
    fs_adapter = LocalFilesystemStorageAdapter(base_path=str(tmp_path))
    legacy_meta = fs_adapter.put_object("inv-test-16/legacy.raw.txt", b"legacy evidence")

    # Access via SeaweedFS-backed store with dual-read fallback enabled
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    monkeypatch.setattr(store.settings, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", True)
    monkeypatch.setattr(store.settings, "APP_ENV", "development")
    monkeypatch.setattr(store.settings, "EVIDENCE_STORAGE_PATH", str(tmp_path))

    data, h = store.read_evidence("inv-test-16/legacy.raw.txt")
    assert data == b"legacy evidence"
    assert h == legacy_meta.content_hash


# 17. Backward-compatible retrieval (SeaweedFS with explicit backend)
def test_scenario_17_explicit_backend_override(tmp_path, mock_seaweed_adapter):
    # Put evidence in SeaweedFS
    store = EvidenceStore(adapter=mock_seaweed_adapter)
    res = store.store_evidence("inv-test-17", "ev-17", "scanner", "seaweed payload")

    # Read back specifying backend="seaweedfs"
    data, h = store.read_evidence(res.key, backend="seaweedfs")
    assert data == b"seaweed payload"
    assert h == res.content_hash


# 18. Evidence streaming in chunks
def test_scenario_18_streaming_chunks(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    large_payload = b"X" * (128 * 1024)  # 128 KB
    res = store.store_evidence("inv-test-18", "ev-18", "stream", large_payload)

    chunks = list(store.read_evidence_stream(res.key, chunk_size=16384))
    assert len(chunks) == 8  # 128KB / 16KB = 8 chunks
    assert b"".join(chunks) == large_payload


# 19. Multiple investigations isolation
def test_scenario_19_investigation_isolation(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    res_a = store.store_evidence("inv-alpha", "ev-01", "osint", "investigation alpha")
    res_b = store.store_evidence("inv-bravo", "ev-01", "osint", "investigation bravo")

    assert res_a.key != res_b.key
    assert res_a.key.startswith("inv-alpha/")
    assert res_b.key.startswith("inv-bravo/")

    data_a, _ = store.read_evidence(res_a.key)
    data_b, _ = store.read_evidence(res_b.key)
    assert data_a == b"investigation alpha"
    assert data_b == b"investigation bravo"


# 20. Storage health check reports
def test_scenario_20_storage_health_checks(tmp_path, mock_seaweed_adapter):
    fs_store = EvidenceStore(base_path=str(tmp_path))
    fs_health = fs_store.get_storage_health()
    assert isinstance(fs_health, StorageHealthStatus)
    assert fs_health.is_healthy is True
    assert fs_health.backend == "filesystem"

    sw_store = EvidenceStore(adapter=mock_seaweed_adapter)
    # Mock filer HEAD response for health
    sw_health = sw_store.get_storage_health()
    assert isinstance(sw_health, StorageHealthStatus)
    assert sw_health.backend == "seaweedfs"
