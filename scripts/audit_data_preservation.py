import hashlib
import json
import pathlib
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.models.recon import EvidenceModel

def main():
    print("=" * 80)
    print("FOOTPRINTIQ - TASK 04D DATA PRESERVATION AUDIT")
    print("=" * 80)

    # 1. Check all 264 local evidence files
    evidence_dir = pathlib.Path("evidence_storage")
    local_files = [f for f in evidence_dir.rglob("*") if f.is_file()]
    print(f"1. Total local evidence files: {len(local_files)} (Expected: 264)")
    total_local_bytes = sum(f.stat().st_size for f in local_files)
    print(f"   Total local bytes: {total_local_bytes} (Expected: 102076)")

    # 2. Check all seven original local files match pre-migration hashes
    manifest_path = pathlib.Path("docs/migration_task_04d/pre_migration_manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    all_7_match = True
    for item in manifest:
        f_path = pathlib.Path(item["original_local_path"])
        f_hash = hashlib.sha256(f_path.read_bytes()).hexdigest()
        if f_hash.lower() != item["original_sha256"].lower():
            all_7_match = False
            print(f"   MISMATCH in {f_path.name}: {f_hash} != {item['original_sha256']}")
    print(f"2. All 7 original local files SHA-256 match pre-migration baseline: {all_7_match}")

    # 3. Check 257 unreferenced files remain local
    referenced_paths = {pathlib.Path(item["original_local_path"]).resolve() for item in manifest}
    unref_files = [f for f in local_files if f.resolve() not in referenced_paths]
    print(f"3. Unreferenced local files count: {len(unref_files)} (Expected: 257)")

    # 4. Check 4 metadata-only records
    MSSQL_URL = "mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
    engine = create_engine(MSSQL_URL)
    with Session(engine) as session:
        meta_only = session.query(EvidenceModel).filter(EvidenceModel.raw_content_path == None).all()
        print(f"4. Metadata-only records in SQL Server: {len(meta_only)} (Expected: 4)")
        for r in meta_only:
            print(f"   {r.id}: backend={r.storage_backend}, path={r.raw_content_path}")

    # 5. Check SQLite database file
    sqlite_path = pathlib.Path("footprintiq.db")
    sqlite_bytes = sqlite_path.read_bytes()
    sqlite_hash = hashlib.sha256(sqlite_bytes).hexdigest()
    print(f"5. SQLite footprintiq.db size: {len(sqlite_bytes)} (Expected: 565248), hash: {sqlite_hash}")

    # 6. Check SQLite WAL and SHM files
    wal_path = pathlib.Path("footprintiq.db-wal")
    shm_path = pathlib.Path("footprintiq.db-shm")
    wal_size = wal_path.stat().st_size if wal_path.exists() else 0
    shm_size = shm_path.stat().st_size if shm_path.exists() else 0
    print(f"6. WAL exists: {wal_path.exists()} (size: {wal_size}), SHM exists: {shm_path.exists()} (size: {shm_size})")

    # 7. Check cold preservation backup
    backup_dir = pathlib.Path(".data/backups/cold_preservation_20261102")
    backup_files = list(backup_dir.glob("*")) if backup_dir.exists() else []
    print(f"7. Cold preservation backup files: {len(backup_files)}")
    for bf in backup_files:
        print(f"   {bf.name}: size={bf.stat().st_size}, sha256={hashlib.sha256(bf.read_bytes()).hexdigest()[:16]}...")

    # 8. Check reconciliation ledger
    ledger_path = pathlib.Path(".data/storage_reconciliation_ledger.jsonl")
    print(f"8. Reconciliation ledger exists: {ledger_path.exists()}")
    if ledger_path.exists():
        print(f"   Ledger size: {ledger_path.stat().st_size} bytes, lines: {len(ledger_path.read_text().splitlines())}")

    return len(local_files) == 264 and total_local_bytes == 102076 and all_7_match and len(unref_files) == 257 and len(meta_only) == 4

def run_audit() -> bool:
    return main()

if __name__ == "__main__":
    main()

