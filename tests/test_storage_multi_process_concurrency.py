"""Independent verification tests for upload idempotency and multi-process concurrency."""

import concurrent.futures
import hashlib
import multiprocessing
import os
from pathlib import Path
import threading
import time
from typing import Dict, List, Tuple
import httpx
import pytest

from app.storage.base import (
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectNotFoundError,
    compute_sha256,
)
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.seaweedfs import SeaweedFSStorageAdapter


# Worker function for multi-process concurrency testing
def _multiprocess_upload_worker(base_path: str, key: str, payload: bytes) -> Tuple[bool, str, str]:
    """Independent OS worker process attempting to write to the shared storage adapter."""
    try:
        adapter = LocalFilesystemStorageAdapter(base_path=base_path)
        meta = adapter.put_object(key, payload)
        return True, meta.content_hash, ""
    except StorageKeyExistsError as e:
        return False, "", "KEY_EXISTS"
    except Exception as e:
        return False, "", str(e)


# ============================================================================
# 1. IDENTICAL UPLOAD RETRY & CLIENT TIMEOUT IDEMPOTENCY
# ============================================================================

def test_upload_retry_after_client_timeout(tmp_path: Path):
    """Scenario 1 & 2: Server persists object, but client times out before receiving ACK.
    Client retries the exact same upload request.
    """
    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    key = "inv-timeout-test/ev-nmap-101.raw.txt"
    payload = b"<nmaprun>Valid scan xml</nmaprun>"
    expected_hash = hashlib.sha256(payload).hexdigest()

    # Attempt 1: Server completes write
    meta1 = adapter.put_object(key, payload, content_type="application/xml")
    assert meta1.content_hash == expected_hash

    # Attempt 2: Client retries identical upload
    meta2 = adapter.put_object(key, payload, content_type="application/xml")
    assert meta2.content_hash == expected_hash
    assert meta2.size_bytes == len(payload)
    assert meta2.key == key

    # Verify physical file state on disk
    file_path = tmp_path / key
    assert file_path.is_file()
    assert file_path.read_bytes() == payload


def test_different_content_submitted_under_existing_key(tmp_path: Path):
    """Scenario 4 & 5: Submitting different payload bytes under an existing object key
    must be strictly rejected to prevent evidence tampering or collision.
    """
    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    key = "inv-tamper-test/ev-tamper.raw.txt"

    original_payload = b"Legitimate evidence payload"
    adapter.put_object(key, original_payload)

    # Attempt overwrite with different bytes
    conflicting_payload = b"Malicious or altered evidence payload"
    with pytest.raises(StorageKeyExistsError):
        adapter.put_object(key, conflicting_payload)

    # Confirm original file remains 100% unaltered
    retrieved_bytes, meta = adapter.get_object(key)
    assert retrieved_bytes == original_payload
    assert meta.content_hash == hashlib.sha256(original_payload).hexdigest()


# ============================================================================
# 2. MULTI-PROCESS CONCURRENT UPLOADS
# ============================================================================

def test_multiprocess_concurrent_uploads_filesystem(tmp_path: Path):
    """Scenario 3 & 6: Multiple independent OS processes simultaneously attempt to upload
    the exact same evidence key.
    """
    key = "inv-mp-concurrency/ev-mp-shared.raw.txt"
    payload = b"Multi-process concurrent deterministic content"
    expected_hash = hashlib.sha256(payload).hexdigest()

    num_processes = 4
    resolved_base = str(tmp_path.resolve())
    tmp_path.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [
            executor.submit(_multiprocess_upload_worker, resolved_base, key, payload)
            for _ in range(num_processes)
        ]
        results = [f.result() for f in futures]

    # Every process must either successfully write or succeed via identical idempotency
    for success, content_hash, err in results:
        assert success is True, f"Worker process failed: {err}"
        assert content_hash == expected_hash

    # Physical verification
    file_path = tmp_path / key
    assert file_path.is_file()
    assert file_path.read_bytes() == payload


# ============================================================================
# 3. INTERRUPTED STREAMING & READ-BACK CHECKSUM MISMATCH
# ============================================================================

def test_readback_checksum_mismatch_compensation():
    """Scenario 8: Read-back verification detects hash discrepancy and executes compensating deletion."""
    storage_dict = {}

    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "HEAD":
            key = path.replace("/test-col/", "")
            if key in storage_dict:
                return httpx.Response(200, headers={"Content-Length": str(len(storage_dict[key]))})
            return httpx.Response(404)
        elif request.method in {"PUT", "POST"}:
            key = path.replace("/test-col/", "")
            storage_dict[key] = request.read()
            return httpx.Response(201)
        elif request.method == "GET":
            # Injected corruption: return altered bytes
            return httpx.Response(200, content=b"CORRUPTED_BYTES_RETURNED")
        elif request.method == "DELETE":
            key = path.replace("/test-col/", "")
            storage_dict.pop(key, None)
            return httpx.Response(204)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(mock_handler), base_url="http://mock:8888")
    adapter = SeaweedFSStorageAdapter(
        filer_url="http://mock:8888",
        collection="test-col",
        client=client,
    )

    key = "inv-corrupt-test/ev-corrupt.raw.txt"
    with pytest.raises(StorageIntegrityError):
        adapter.put_object(key, b"Original valid bytes")

    # Compensating deletion must have removed the corrupt object
    assert key not in storage_dict

