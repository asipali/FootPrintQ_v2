"""Automated tests for forensic evidence storage, SHA-256 hashing, and path traversal defense."""

import pytest
import hashlib
from pathlib import Path
import uuid
from app.config import get_settings
from app.services.evidence_store import EvidenceStore


def test_evidence_store_crud(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))

    inv_id = "inv-forensic-test"
    evi_id = "evi-12345"
    content = {"key": "value", "sample": [1, 2, 3]}

    # 1. Store JSON evidence
    rel_path, sha_hash, size_bytes = store.store_evidence(
        investigation_id=inv_id,
        evidence_id=evi_id,
        source_type="RDAP",
        content=content,
    )

    assert rel_path.startswith(f"{inv_id}/")
    assert rel_path.endswith(".raw.json")
    assert len(sha_hash) == 64
    assert size_bytes > 0

    # 2. Read stored evidence and verify integrity
    data_bytes, computed_hash = store.read_evidence(rel_path)
    assert computed_hash == sha_hash
    assert b"\"key\": \"value\"" in data_bytes


def test_evidence_store_path_traversal_rejection(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))

    # Path traversal in investigation_id
    with pytest.raises(ValueError):
        store.store_evidence(
            investigation_id="../../etc",
            evidence_id="evi-attack",
            source_type="TEST",
            content="malicious payload",
        )

    # Path traversal in relative_path on read
    with pytest.raises((ValueError, FileNotFoundError)):
        store.read_evidence("../../windows/system32/cmd.exe")


def test_evidence_store_missing_file_raises_not_found(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    with pytest.raises(FileNotFoundError):
        store.read_evidence("inv-test/non_existent.raw.txt")


def test_evidence_store_does_not_overwrite_reused_identifier(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    rel_path, original_hash, _ = store.store_evidence("inv-safe", "same-id", "DNS", "original")

    with pytest.raises(FileExistsError):
        store.store_evidence("inv-safe", "same-id", "DNS", "replacement")

    data, stored_hash = store.read_evidence(rel_path)
    assert data == b"original"
    assert stored_hash == original_hash


def test_default_store_uses_isolated_temp_root_not_configured_evidence_path(
    isolated_evidence_storage,
):
    """Implicit evidence writes in tests cannot reach configured persistent storage."""
    store = EvidenceStore()
    configured_root = Path(get_settings().EVIDENCE_STORAGE_PATH).resolve()
    test_root = Path(isolated_evidence_storage).resolve()
    unique_id = f"evi-isolation-{uuid.uuid4().hex}"

    assert store.base_dir == test_root
    assert store.base_dir != configured_root

    relative_path, _, _ = store.store_evidence(
        investigation_id=f"inv-isolation-{uuid.uuid4().hex}",
        evidence_id=unique_id,
        source_type="TEST",
        content={"isolated": True},
    )

    assert (test_root / relative_path).is_file()
    assert not (configured_root / relative_path).exists()


def test_evidence_read_reports_tampered_content_hash(tmp_path):
    store = EvidenceStore(base_path=str(tmp_path))
    relative_path, original_hash, _ = store.store_evidence(
        "inv-integrity", "evi-integrity", "TEST", "original"
    )
    stored_file = tmp_path / relative_path
    stored_file.write_bytes(b"tampered")

    content, computed_hash = store.read_evidence(relative_path)

    assert content == b"tampered"
    assert computed_hash != original_hash
