"""Tests for Storage Monitoring and Reconciliation Service."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base
from app.models.audit import AuditLogModel
from app.models.recon import EvidenceModel
from app.services.storage_reconciliation import StorageReconciliationService
from app.storage.base import (
    BaseStorageAdapter,
    StorageHealthStatus,
    StorageObjectMetadata,
)


class MockStorageAdapter(BaseStorageAdapter):
    """In-memory mock adapter for testing reconciliation workflows."""

    def __init__(self, backend_name="mock_seaweedfs"):
        self._name = backend_name
        self.store = {}
        self.is_healthy = True

    @property
    def backend_name(self) -> str:
        return self._name

    def object_exists(self, key: str) -> bool:
        return key in self.store

    def put_object(self, key: str, data, **kwargs):
        if isinstance(data, (bytes, bytearray)):
            self.store[key] = bytes(data)
        else:
            self.store[key] = data.read()
        return StorageObjectMetadata(
            key=key,
            size_bytes=len(self.store[key]),
            content_hash="mock",
            content_type="text/plain",
            backend=self.backend_name,
        )

    def get_object(self, key: str):
        if key not in self.store:
            raise FileNotFoundError(key)
        return self.store[key], {}

    def get_object_stream(self, key: str, chunk_size: int = 65536):
        data, _ = self.get_object(key)
        yield data

    def delete_object(self, key: str) -> bool:
        return self.store.pop(key, None) is not None

    def get_object_metadata(self, key: str):
        if key not in self.store:
            raise FileNotFoundError(key)
        return StorageObjectMetadata(
            key=key,
            size_bytes=len(self.store[key]),
            content_hash="mock",
            content_type="text/plain",
            backend=self.backend_name,
        )

    def verify_object_integrity(self, key: str, expected_hash: str) -> bool:
        return True

    def health_check(self) -> StorageHealthStatus:
        return StorageHealthStatus(
            is_healthy=self.is_healthy,
            backend=self.backend_name,
            details="Mock adapter healthy" if self.is_healthy else "Mock adapter simulated down",
            latency_ms=1.5,
        )


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_record_inconsistency_and_ledger_resilience(tmp_path: Path, in_memory_db: Session):
    ledger_file = tmp_path / "test_ledger.jsonl"
    service = StorageReconciliationService(ledger_path=ledger_file)

    rec_id = service.record_inconsistency(
        event_type="test_event",
        evidence_id="evi-001",
        investigation_id="inv-001",
        storage_key="inv-001/evi-001.txt",
        details={"reason": "unit_test"},
        db=in_memory_db,
    )

    assert rec_id.startswith("rec-")
    entries = service.read_ledger_entries()
    assert len(entries) == 1
    assert entries[0]["id"] == rec_id
    assert entries[0]["event_type"] == "test_event"

    # Verify audit log in database
    audit_entry = in_memory_db.query(AuditLogModel).filter_by(id=rec_id).first()
    assert audit_entry is not None
    assert audit_entry.event_type == "storage.test_event"

    # Simulate trailing corrupted line
    with open(ledger_file, "a", encoding="utf-8") as f:
        f.write('{"truncated": "inval\n')

    # Reading again should tolerate corruption and return prior valid entry
    recovered = service.read_ledger_entries()
    assert len(recovered) == 1
    assert recovered[0]["id"] == rec_id


def test_reconcile_orphans(in_memory_db: Session):
    # Add an active evidence record
    ev = EvidenceModel(
        id="evi-100",
        investigation_id="inv-100",
        source_type="TOOL",
        source_name="nmap",
        target="example.com",
        raw_content_path="inv-100/active.txt",
        content_hash="dummy",
        content_size_bytes=10,
        storage_backend="seaweedfs",
    )
    in_memory_db.add(ev)
    in_memory_db.commit()

    service = StorageReconciliationService()
    physical_keys = ["inv-100/active.txt", "inv-999/orphaned_blob.raw.txt"]

    orphans = service.reconcile_orphans(in_memory_db, physical_keys=physical_keys)
    assert len(orphans) == 1
    assert orphans[0]["storage_key"] == "inv-999/orphaned_blob.raw.txt"
    assert orphans[0]["requires_manual_review"] is True


def test_reconcile_evidence_inventory_and_health_report(tmp_path: Path, in_memory_db: Session):
    ledger_file = tmp_path / "ledger_report.jsonl"
    service = StorageReconciliationService(ledger_path=ledger_file)
    mock_adapter = MockStorageAdapter(backend_name="seaweedfs")

    # Seed 3 records:
    # 1. Valid record (content matches)
    # 2. Corrupted record (hash mismatch)
    # 3. Missing object (not in store)
    # 4. Metadata-only record (raw_content_path is None)

    import hashlib
    valid_content = b"Valid evidence content"
    valid_hash = hashlib.sha256(valid_content).hexdigest()
    mock_adapter.store["inv-1/valid.txt"] = valid_content

    corrupt_content = b"Altered payload"
    mock_adapter.store["inv-1/corrupt.txt"] = corrupt_content

    ev_valid = EvidenceModel(
        id="ev-1",
        investigation_id="inv-1",
        source_type="TOOL",
        source_name="nmap",
        target="example.com",
        raw_content_path="inv-1/valid.txt",
        content_hash=valid_hash,
        content_size_bytes=len(valid_content),
        storage_backend="seaweedfs",
    )
    ev_corrupt = EvidenceModel(
        id="ev-2",
        investigation_id="inv-1",
        source_type="TOOL",
        source_name="nmap",
        target="example.com",
        raw_content_path="inv-1/corrupt.txt",
        content_hash="expected_different_hash_000000000000000000000000000000000000000000",
        content_size_bytes=len(corrupt_content),
        storage_backend="seaweedfs",
    )
    ev_missing = EvidenceModel(
        id="ev-3",
        investigation_id="inv-1",
        source_type="TOOL",
        source_name="nmap",
        target="example.com",
        raw_content_path="inv-1/missing.txt",
        content_hash="missing_hash",
        content_size_bytes=50,
        storage_backend="seaweedfs",
    )
    ev_meta_only = EvidenceModel(
        id="ev-4",
        investigation_id="inv-1",
        source_type="TOOL",
        source_name="nmap",
        target="example.com",
        raw_content_path=None,
        content_hash="stub_hash",
        content_size_bytes=100,
        storage_backend="filesystem",
    )

    in_memory_db.add_all([ev_valid, ev_corrupt, ev_missing, ev_meta_only])
    in_memory_db.commit()

    # Run inventory reconciliation
    inventory = service.reconcile_evidence_inventory(db=in_memory_db, storage_adapter=mock_adapter)
    assert inventory["checked_records"] == 3
    assert inventory["metadata_only_records"] == 1
    assert inventory["valid_records"] == 1
    assert len(inventory["missing_objects"]) == 1
    assert inventory["missing_objects"][0]["evidence_id"] == "ev-3"
    assert len(inventory["corrupted_objects"]) == 1
    assert inventory["corrupted_objects"][0]["evidence_id"] == "ev-2"

    # Run full health report (should be DEGRADED due to missing/corrupted objects)
    report = service.get_storage_health_report(db=in_memory_db, storage_adapter=mock_adapter)
    assert report["overall_status"] == "DEGRADED"
    assert report["database"]["is_healthy"] is True
    assert report["storage_adapter"]["is_healthy"] is True

    # Now make adapter simulate outage -> status becomes CRITICAL
    mock_adapter.is_healthy = False
    crit_report = service.get_storage_health_report(db=in_memory_db, storage_adapter=mock_adapter)
    assert crit_report["overall_status"] == "CRITICAL"
    assert crit_report["storage_adapter"]["is_healthy"] is False
