"""Non-Destructive Evidence Migration from Local Filesystem to SeaweedFS (Task 04D).

Strictly migrates exactly seven authoritative, database-referenced evidence files
from local filesystem storage to SeaweedFS without modifying, deleting, renaming,
or overwriting the original local evidence files.

Phases implemented:
- Phase A: Pre-migration inventory and manifest generation.
- Phase B: Preflight infrastructure and safety checks.
- Phase C: Controlled one-by-one migration with read-back verification.
- Phase D: Resumable durable migration journal.
- Phase E: Post-migration independent verification.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.models.recon import EvidenceModel
from app.storage.base import (
    StorageConnectionError,
    StorageIntegrityError,
    StorageKeyExistsError,
    compute_sha256,
)
from app.storage.seaweedfs import SeaweedFSStorageAdapter
from app.services.evidence_store import EvidenceStore

# Configuration defaults
MSSQL_URL = (
    r"mssql+pyodbc://@localhost\SQLEXPRESS/footprintiq"
    r"?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
)
FILER_URL = "http://localhost:18888"
COLLECTION = "evidence"
EVIDENCE_LOCAL_DIR = Path("evidence_storage").resolve()
REPORT_DIR = Path("docs/migration_task_04d")
JOURNAL_DIR = Path(".data/migration_task_04d")
JOURNAL_PATH = JOURNAL_DIR / "migration_journal.jsonl"
MANIFEST_PATH = REPORT_DIR / "pre_migration_manifest.json"

AUTHORITATIVE_EVIDENCE_IDS = [
    "evi-e4f8db7dcda8",
    "ev-nmap-35023caf5f0b",
    "ev-nmap-35d756388e5d",
    "ev-nmap-3e8336e332be",
    "ev-nmap-4d7def5be5ff",
    "ev-nmap-ac7fa3cd2637",
    "ev-nmap-dbc9e08e77ba",
]


class MigrationJournal:
    """Thread-safe, append-only durable journal tracking evidence record migration states."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, evidence_id: str, state: str, details: Optional[Dict[str, Any]] = None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_id": evidence_id,
            "state": state,
            "details": details or {},
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

    def get_latest_state(self, evidence_id: str) -> Optional[str]:
        if not self.path.exists():
            return None
        latest = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("evidence_id") == evidence_id:
                        latest = data.get("state")
                except json.JSONDecodeError:
                    continue
        return latest


def hash_file(file_path: Path) -> Tuple[str, int]:
    """Computes hex SHA-256 and byte size of a file."""
    h = hashlib.sha256()
    size = 0
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def phase_a_pre_migration_inventory(engine, adapter: SeaweedFSStorageAdapter) -> List[Dict[str, Any]]:
    """Phase A: Inventory verification and immutable manifest generation."""
    print("\n--- PHASE A: PRE-MIGRATION INVENTORY ---")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    JOURNAL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Query SQL Server for authoritative records
    with engine.connect() as conn:
        query = text(
            "SELECT id, investigation_id, source_type, source_name, target, "
            "collection_status, raw_content_path, content_hash, content_size_bytes, "
            "collected_at, storage_backend FROM evidence WHERE raw_content_path IS NOT NULL"
        )
        rows = [dict(r._mapping) for r in conn.execute(query).fetchall()]

    if len(rows) != 7:
        raise ValueError(f"Expected exactly 7 authoritative records, found {len(rows)}")

    found_ids = [r["id"] for r in rows]
    if set(found_ids) != set(AUTHORITATIVE_EVIDENCE_IDS):
        raise ValueError(f"Database records {found_ids} do not match authoritative IDs {AUTHORITATIVE_EVIDENCE_IDS}")

    # 2. Check 4 metadata-only records are excluded
    with engine.connect() as conn:
        meta_only = conn.execute(text("SELECT id FROM evidence WHERE raw_content_path IS NULL")).fetchall()
    if len(meta_only) != 4:
        raise ValueError(f"Expected exactly 4 metadata-only records, found {len(meta_only)}")

    manifest = []
    destination_keys = set()

    for r in sorted(rows, key=lambda x: x["id"]):
        local_rel_path = r["raw_content_path"]
        local_abs_path = (EVIDENCE_LOCAL_DIR / local_rel_path).resolve()

        if not local_abs_path.exists():
            raise FileNotFoundError(f"Local evidence file missing: {local_abs_path}")

        file_hash, file_size = hash_file(local_abs_path)
        if file_hash.lower() != r["content_hash"].lower():
            raise ValueError(f"Hash mismatch on {r['id']}: disk={file_hash} vs db={r['content_hash']}")
        if file_size != r["content_size_bytes"]:
            raise ValueError(f"Size mismatch on {r['id']}: disk={file_size} vs db={r['content_size_bytes']}")

        dest_key = local_rel_path.replace("\\", "/")
        if dest_key in destination_keys:
            raise ValueError(f"Duplicate destination key detected: {dest_key}")
        destination_keys.add(dest_key)

        entry = {
            "evidence_id": r["id"],
            "investigation_id": r["investigation_id"],
            "source_type": r["source_type"],
            "source_name": r["source_name"],
            "target": r["target"],
            "collection_status": r["collection_status"],
            "original_storage_backend": r["storage_backend"],
            "original_local_path": str(local_abs_path),
            "destination_key": dest_key,
            "byte_size": file_size,
            "original_sha256": file_hash,
            "database_sha256": r["content_hash"],
            "collected_at": r["collected_at"].isoformat() if r["collected_at"] else None,
        }
        manifest.append(entry)
        print(f"  [VALIDATED] {r['id']} | {dest_key} | {file_size} bytes | SHA256: {file_hash[:16]}...")

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Manifest written to: {MANIFEST_PATH}")
    return manifest


def phase_b_migration_preflight(engine, adapter: SeaweedFSStorageAdapter):
    """Phase B: Verify infrastructure health, transactions, and namespace permissions."""
    print("\n--- PHASE B: MIGRATION PREFLIGHT ---")

    # 1. SQL Server Health & Transaction support
    with engine.connect() as conn:
        ver = conn.execute(text("SELECT @@VERSION")).scalar()
        print(f"  [PREFLIGHT] SQL Server connected: {ver.splitlines()[0]}")
        # Test transaction rollback
        conn.rollback()
        trans = conn.begin()
        conn.execute(text("SELECT 1"))
        trans.rollback()
        print("  [PREFLIGHT] SQL Server transaction rollback verified.")

    # 2. SeaweedFS Filer Health
    health = adapter.health_check()
    if not health.is_healthy:
        raise ConnectionError(f"SeaweedFS Filer unhealthy: {health.details}")
    print(f"  [PREFLIGHT] SeaweedFS Filer healthy ({health.latency_ms:.2f}ms).")

    # 3. Test preflight object in disposable namespace
    test_key = "preflight_test/probe.txt"
    test_data = b"Preflight connectivity probe"
    adapter.put_object(test_key, test_data)
    read_data, _ = adapter.get_object(test_key)
    if read_data != test_data:
        raise AssertionError("SeaweedFS preflight probe read-back mismatch")
    adapter.delete_object(test_key)
    print("  [PREFLIGHT] SeaweedFS write/read/delete probe verified.")


def phase_c_controlled_migration(
    engine,
    adapter: SeaweedFSStorageAdapter,
    manifest: List[Dict[str, Any]],
    journal: MigrationJournal,
) -> List[Dict[str, Any]]:
    """Phase C: Execute controlled record-by-record migration with read-back verification."""
    print("\n--- PHASE C: CONTROLLED MIGRATION ---")
    migration_results = []

    for item in manifest:
        evi_id = item["evidence_id"]
        inv_id = item["investigation_id"]
        dest_key = item["destination_key"]
        local_path = Path(item["original_local_path"])
        expected_hash = item["original_sha256"]
        expected_size = item["byte_size"]

        print(f"\nProcessing record: {evi_id} ({dest_key})...")
        journal.log(evi_id, "PENDING", {"destination_key": dest_key})

        # 1. Read original local file
        local_bytes = local_path.read_bytes()
        computed_hash = compute_sha256(local_bytes)
        if computed_hash.lower() != expected_hash.lower():
            journal.log(evi_id, "FAILED", {"reason": "Local file hash differs from manifest"})
            raise ValueError(f"Integrity error: local file {local_path} modified during migration!")

        # 2. Check if object already exists in SeaweedFS (Idempotency / Resumability check)
        already_uploaded = False
        if adapter.object_exists(dest_key):
            existing_bytes, existing_meta = adapter.get_object(dest_key)
            existing_hash = existing_meta.content_hash or compute_sha256(existing_bytes)
            if existing_hash.lower() == expected_hash.lower() and len(existing_bytes) == expected_size:
                print(f"  [IDEMPOTENT] Object already exists in SeaweedFS with matching digest.")
                already_uploaded = True
            else:
                journal.log(evi_id, "FAILED", {"reason": "Object exists with divergent content"})
                raise StorageKeyExistsError(
                    f"Collision: SeaweedFS object {dest_key} exists with DIFFERENT digest {existing_hash}!"
                )

        if not already_uploaded:
            # Upload payload
            meta = adapter.put_object(
                key=dest_key,
                data=local_bytes,
                content_type="text/plain; charset=utf-8",
                metadata={"investigation_id": inv_id, "evidence_id": evi_id},
            )
            journal.log(evi_id, "UPLOADED", {"content_hash": meta.content_hash, "size": meta.size_bytes})
            print(f"  [UPLOADED] Stored in SeaweedFS: {dest_key}")

        # 3. Read back from SeaweedFS
        readback_bytes, readback_meta = adapter.get_object(dest_key)
        readback_hash = compute_sha256(readback_bytes)
        journal.log(evi_id, "VERIFIED", {"readback_hash": readback_hash, "readback_size": len(readback_bytes)})

        if readback_hash.lower() != expected_hash.lower():
            journal.log(evi_id, "FAILED", {"reason": "Read-back SHA-256 mismatch"})
            raise StorageIntegrityError(f"Read-back hash mismatch: got {readback_hash}, expected {expected_hash}")
        if len(readback_bytes) != expected_size:
            journal.log(evi_id, "FAILED", {"reason": "Read-back byte size mismatch"})
            raise ValueError(f"Read-back size mismatch: got {len(readback_bytes)}, expected {expected_size}")

        print(f"  [VERIFIED] Read-back matched original bytes and SHA-256 ({readback_hash[:16]}...).")

        # 4. Conditional transactional database update in SQL Server
        with Session(engine) as session:
            record = session.get(EvidenceModel, evi_id)
            if not record:
                journal.log(evi_id, "REQUIRES_MANUAL_REVIEW", {"reason": "Evidence record missing from DB"})
                raise ValueError(f"Record {evi_id} missing from SQL Server!")

            if record.storage_backend == "seaweedfs":
                print(f"  [DB_ALREADY_UPDATED] Database already set to seaweedfs for {evi_id}.")
            else:
                if record.storage_backend != "filesystem" or record.raw_content_path != dest_key:
                    journal.log(evi_id, "REQUIRES_MANUAL_REVIEW", {"reason": "DB record metadata altered"})
                    raise ValueError(f"DB record {evi_id} state changed unexpectedly!")

                # Perform conditional update
                record.storage_backend = "seaweedfs"
                session.commit()
                journal.log(evi_id, "DATABASE_UPDATED", {"storage_backend": "seaweedfs"})
                print(f"  [DB_UPDATED] SQL Server evidence record {evi_id} storage_backend updated to 'seaweedfs'.")

        journal.log(evi_id, "COMPLETE", {"status": "SUCCESS"})
        migration_results.append({
            "evidence_id": evi_id,
            "destination_key": dest_key,
            "size_bytes": expected_size,
            "sha256": expected_hash,
            "status": "COMPLETE",
        })

    return migration_results


def phase_e_post_migration_verification(engine, adapter: SeaweedFSStorageAdapter):
    """Phase E: Independently verify all 7 records, SeaweedFS objects, and local file preservation."""
    print("\n--- PHASE E: POST-MIGRATION INDEPENDENT VERIFICATION ---")

    # 1. SQL Server Database State
    with Session(engine) as session:
        records = session.query(EvidenceModel).filter(EvidenceModel.raw_content_path.isnot(None)).all()
        if len(records) != 7:
            raise AssertionError(f"Expected 7 authoritative records, found {len(records)}")

        for rec in records:
            if rec.storage_backend != "seaweedfs":
                raise AssertionError(f"Record {rec.id} backend is {rec.storage_backend}, expected 'seaweedfs'")
            print(f"  [VERIFIED DB] {rec.id}: backend={rec.storage_backend}, path={rec.raw_content_path}")

        # Check metadata-only records remained untouched
        meta_only = session.query(EvidenceModel).filter(EvidenceModel.raw_content_path.is_(None)).all()
        if len(meta_only) != 4:
            raise AssertionError(f"Expected 4 metadata-only records, found {len(meta_only)}")
        for m in meta_only:
            if m.storage_backend != "filesystem":
                raise AssertionError(f"Metadata-only record {m.id} was modified!")
        print("  [VERIFIED DB] 4 metadata-only records remain unchanged (filesystem / NULL path).")

    # 2. SeaweedFS Object Presence and Content Hash Match
    for evi_id in AUTHORITATIVE_EVIDENCE_IDS:
        with Session(engine) as session:
            rec = session.get(EvidenceModel, evi_id)
            key = rec.raw_content_path
            expected_hash = rec.content_hash
            expected_size = rec.content_size_bytes

        if not adapter.object_exists(key):
            raise AssertionError(f"SeaweedFS object missing: {key}")

        sw_bytes, sw_meta = adapter.get_object(key)
        sw_hash = compute_sha256(sw_bytes)

        if sw_hash.lower() != expected_hash.lower():
            raise AssertionError(f"Hash mismatch on SeaweedFS object {key}: {sw_hash} != {expected_hash}")
        if len(sw_bytes) != expected_size:
            raise AssertionError(f"Size mismatch on SeaweedFS object {key}: {len(sw_bytes)} != {expected_size}")

        print(f"  [VERIFIED SEAWEEDFS] {key} exists, {len(sw_bytes)} bytes, SHA256 matches DB digest.")

    # 3. Application EvidenceStore API retrieval verification
    store = EvidenceStore(adapter=adapter)
    for evi_id in AUTHORITATIVE_EVIDENCE_IDS:
        with Session(engine) as session:
            rec = session.get(EvidenceModel, evi_id)
            key = rec.raw_content_path
        retrieved_bytes, retrieved_hash = store.read_evidence(key)
        if retrieved_hash.lower() != rec.content_hash.lower():
            raise AssertionError(f"EvidenceStore read mismatch on {key}")
    print("  [VERIFIED API] All 7 evidence items successfully retrieved via EvidenceStore API.")

    # 4. Local File Preservation Check
    import glob
    all_local_files = [f for f in glob.glob("evidence_storage/**/*", recursive=True) if os.path.isfile(f)]
    if len(all_local_files) != 264:
        raise AssertionError(f"Local file count altered! Expected 264, found {len(all_local_files)}")
    print(f"  [VERIFIED DISK] Exactly 264 local evidence files remain intact on disk.")

    # Check 7 authoritative local files
    for evi_id in AUTHORITATIVE_EVIDENCE_IDS:
        with Session(engine) as session:
            rec = session.get(EvidenceModel, evi_id)
            local_path = EVIDENCE_LOCAL_DIR / rec.raw_content_path
        if not local_path.exists():
            raise AssertionError(f"Original local evidence file missing: {local_path}")
        l_hash, l_size = hash_file(local_path)
        if l_hash.lower() != rec.content_hash.lower():
            raise AssertionError(f"Local original evidence file was corrupted: {local_path}")
    print("  [VERIFIED DISK] All 7 original local evidence files remain 100% byte-identical to original hashes.")


def run_migration():
    print("=" * 80)
    print("FOOTPRINTIQ - TASK 04D NON-DESTRUCTIVE EVIDENCE MIGRATION")
    print("=" * 80)

    engine = create_engine(MSSQL_URL)
    adapter = SeaweedFSStorageAdapter(filer_url=FILER_URL, collection=COLLECTION)
    journal = MigrationJournal(JOURNAL_PATH)

    # Phase A
    manifest = phase_a_pre_migration_inventory(engine, adapter)

    # Phase B
    phase_b_migration_preflight(engine, adapter)

    # Phase C
    results = phase_c_controlled_migration(engine, adapter, manifest, journal)

    # Phase E
    phase_e_post_migration_verification(engine, adapter)

    print("\n" + "=" * 80)
    print("MIGRATION COMPLETE: ALL 7 AUTHORITATIVE RECORDS SUCCESSFULLY MIGRATED")
    print("=" * 80)


if __name__ == "__main__":
    run_migration()
