"""Deep verification tests for durable reconciliation ledger, multi-process writers, and crash recovery."""

import concurrent.futures
import json
import os
from pathlib import Path
from typing import Dict, List
import pytest

from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.services.storage_reconciliation import StorageReconciliationService
from app.storage.filesystem import LocalFilesystemStorageAdapter


def _ledger_write_worker(ledger_path: str, worker_id: int, count: int) -> int:
    """Multiprocess worker appending entries to the shared JSONL ledger."""
    recon = StorageReconciliationService(ledger_path=Path(ledger_path))
    written = 0
    for i in range(count):
        recon.record_inconsistency(
            event_type="multiprocess_test",
            evidence_id=f"evi-p{worker_id}-{i}",
            investigation_id="inv-test-recon",
            storage_key=f"inv-test-recon/p{worker_id}_{i}.raw.txt",
            details={"worker": worker_id, "idx": i},
        )
        written += 1
    return written


def test_multiprocess_concurrent_ledger_writers(tmp_path: Path):
    """Verifies that multiple independent OS processes writing to the same JSONL ledger
    produce valid, uncorrupted, parseable entries without line interleaving.
    """
    ledger_file = tmp_path / "mp_recon.jsonl"
    num_processes = 4
    writes_per_process = 15
    total_expected = num_processes * writes_per_process

    with concurrent.futures.ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [
            executor.submit(_ledger_write_worker, str(ledger_file), p_id, writes_per_process)
            for p_id in range(num_processes)
        ]
        results = [f.result() for f in futures]

    assert sum(results) == total_expected

    # Parse ledger using service reader
    recon = StorageReconciliationService(ledger_path=ledger_file)
    entries = recon.read_ledger_entries()
    assert len(entries) == total_expected

    # Verify every line in the raw file is valid JSON
    with open(ledger_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == total_expected
        for line in lines:
            parsed = json.loads(line)
            assert "id" in parsed
            assert parsed["event_type"] == "multiprocess_test"


def test_malformed_and_partial_records_do_not_drop_valid_entries(tmp_path: Path):
    """Verifies that malformed, truncated, or garbage lines in the ledger are skipped
    without dropping or corrupting surrounding valid records.
    """
    ledger_file = tmp_path / "corrupt_recon.jsonl"
    recon = StorageReconciliationService(ledger_path=ledger_file)

    # Valid entry 1
    id1 = recon.record_inconsistency(
        event_type="valid_event_1",
        evidence_id="evi-01",
        investigation_id="inv-01",
        storage_key="inv-01/file1.txt",
        details={"val": 1},
    )

    # Manually inject corrupted lines (process crash, disk truncation, garbage)
    with open(ledger_file, "a", encoding="utf-8") as f:
        f.write('{"truncated_json": "abrupt_eof\n')
        f.write('\n')  # Blank line
        f.write('GARBAGE NON-JSON CHARACTERS\n')
        f.write('{"valid_key_missing_braces": 123\n')

    # Valid entry 2
    id2 = recon.record_inconsistency(
        event_type="valid_event_2",
        evidence_id="evi-02",
        investigation_id="inv-02",
        storage_key="inv-02/file2.txt",
        details={"val": 2},
    )

    entries = recon.read_ledger_entries()
    assert len(entries) == 2
    assert entries[0]["id"] == id1
    assert entries[1]["id"] == id2


def test_duplicate_entries_deduplication(tmp_path: Path):
    """Verifies that duplicate entries with identical IDs are deduplicated on read."""
    ledger_file = tmp_path / "dedup_recon.jsonl"
    recon = StorageReconciliationService(ledger_path=ledger_file)

    rec_id = "rec-fixed-dedup-id-001"
    entry = {
        "id": rec_id,
        "event_type": "dedup_test",
        "evidence_id": "evi-dup",
        "investigation_id": "inv-dup",
        "storage_key": "inv-dup/dup.txt",
        "details": {"test": True},
    }

    # Write identical entry twice
    with open(ledger_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
        f.write(json.dumps(entry) + "\n")

    entries = recon.read_ledger_entries()
    assert len(entries) == 1
    assert entries[0]["id"] == rec_id


def test_repeated_reconciliation_execution_is_idempotent(db_session, tmp_path: Path):
    """Verifies that running reconciliation repeatedly on a static DB state produces
    deterministic, identical results without spurious drift.
    """
    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    recon = StorageReconciliationService(ledger_path=tmp_path / "idempotent_scan.jsonl")

    inv = InvestigationModel(
        id="inv-recon-idem",
        name="Idempotent Scan Lab",
        organization_name="Org",
        description="Testing idempotency",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    # 1 valid file on disk and in DB
    valid_key = "inv-recon-idem/valid.raw.txt"
    adapter.put_object(valid_key, b"Valid payload")
    db_session.add(EvidenceModel(
        id="evi-idem-valid",
        investigation_id="inv-recon-idem",
        source_type="nmap",
        source_name="Nmap",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path=valid_key,
        storage_backend="filesystem",
        content_hash=adapter.get_object_metadata(valid_key).content_hash,
        content_size_bytes=13,
    ))
    db_session.commit()

    # Run 1
    report1 = recon.reconcile_evidence_inventory(db=db_session, storage_adapter=adapter)
    # Run 2
    report2 = recon.reconcile_evidence_inventory(db=db_session, storage_adapter=adapter)

    assert report1["checked_records"] == report2["checked_records"] == 1
    assert report1["valid_records"] == report2["valid_records"] == 1
    assert len(report1["missing_objects"]) == len(report2["missing_objects"]) == 0
    assert len(report1["corrupted_objects"]) == len(report2["corrupted_objects"]) == 0

