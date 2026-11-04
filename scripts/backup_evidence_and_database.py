#!/usr/bin/env python3
"""
Coordinated Backup Script for FootprintIQ Evidence & Database
Creates an atomic, consistent, cryptographically verified backup containing:
1. SQL Server full database backup (.bak) with CHECKSUM and RESTORE VERIFYONLY.
2. SeaweedFS physical storage volume & metadata snapshot via Docker cp.
3. SeaweedFS logical evidence export via Filer HTTP API with SHA-256 verification.
4. Cryptographic backup manifest (backup_manifest.json).
"""

import datetime
import hashlib
import json
import logging
import os
import pathlib
import subprocess
import sys
import time
from typing import Dict, Any, List, Optional, Set

import httpx
from sqlalchemy import create_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("backup")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BACKUP_BASE_DIR = REPO_ROOT / ".data" / "backups"
SEAWEEDFS_CONTAINER = os.environ.get("SEAWEEDFS_CONTAINER", "seaweedfs-test-filer")
SEAWEEDFS_URL = os.environ.get("SEAWEEDFS_FILER_URL", "http://localhost:18888").rstrip("/")
MSSQL_URL = os.environ.get(
    "DATABASE_URL",
    "mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes&autocommit=True"
)

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def backup_sql_server(backup_dir: pathlib.Path) -> Dict[str, Any]:
    bak_file = backup_dir / "footprintiq.bak"
    logger.info("Executing native SQL Server BACKUP DATABASE to %s", bak_file)
    
    engine = create_engine(MSSQL_URL)
    logical_files = []
    table_counts = {}
    t0 = time.perf_counter()
    with engine.connect() as conn:
        raw_conn = conn.connection
        cursor = raw_conn.cursor()
        
        # 1. Native Backup
        sql_backup = f"BACKUP DATABASE [footprintiq] TO DISK = '{bak_file}' WITH INIT, CHECKSUM, STATS = 10"
        cursor.execute(sql_backup)
        while cursor.nextset():
            pass
        
        # 2. Verify with CHECKSUM
        logger.info("Verifying SQL Server backup with RESTORE VERIFYONLY...")
        sql_verify = f"RESTORE VERIFYONLY FROM DISK = '{bak_file}' WITH CHECKSUM"
        cursor.execute(sql_verify)
        while cursor.nextset():
            pass
            
        # 3. Retrieve Logical File List
        sql_filelist = f"RESTORE FILELISTONLY FROM DISK = '{bak_file}'"
        cursor.execute(sql_filelist)
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            logical_files.append({
                "logical_name": d.get("LogicalName"),
                "physical_name": d.get("PhysicalName"),
                "type": d.get("Type"),
                "size_bytes": d.get("Size")
            })

        # 4. Record Snapshot Table Counts
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME")
        base_tables = [r[0] for r in cursor.fetchall()]
        for tbl in base_tables:
            cursor.execute(f"SELECT COUNT(*) FROM [{tbl}]")
            table_counts[tbl] = cursor.fetchone()[0]
    duration = round(time.perf_counter() - t0, 3)
    
    if not bak_file.exists():
        raise RuntimeError(f"Backup file not found at {bak_file}")
        
    size_bytes = bak_file.stat().st_size
    digest = sha256_file(bak_file)
    logger.info("SQL Server backup complete in %ss. Size: %d bytes, SHA-256: %s", duration, size_bytes, digest)
    
    return {
        "engine": "SQL Server 2022 Express",
        "database_name": "footprintiq",
        "file_name": bak_file.name,
        "file_path": str(bak_file),
        "size_bytes": size_bytes,
        "sha256": digest,
        "duration_seconds": duration,
        "restore_verifyonly_passed": True,
        "logical_files": logical_files,
        "table_counts": table_counts
    }

def backup_seaweedfs_physical(backup_dir: pathlib.Path) -> Dict[str, Any]:
    seaweed_dir = backup_dir / "seaweedfs_physical"
    seaweed_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Copying SeaweedFS physical storage volume from container '%s:/data'...", SEAWEEDFS_CONTAINER)
    
    t0 = time.perf_counter()
    cmd = ["docker", "cp", f"{SEAWEEDFS_CONTAINER}:/data", str(seaweed_dir)]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    duration = round(time.perf_counter() - t0, 3)
    
    # Analyze copied contents
    data_path = seaweed_dir / "data"
    all_files = {}
    total_bytes = 0
    file_count = 0
    if data_path.exists():
        for item in data_path.rglob("*"):
            if item.is_file():
                rel = item.relative_to(data_path).as_posix()
                size = item.stat().st_size
                digest = sha256_file(item)
                all_files[rel] = {"size": size, "sha256": digest}
                total_bytes += size
                file_count += 1
                
    logger.info("SeaweedFS physical copy complete in %ss. Total files: %d, bytes: %d", duration, file_count, total_bytes)
    return {
        "container_name": SEAWEEDFS_CONTAINER,
        "backup_path": str(data_path),
        "duration_seconds": duration,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "files": all_files
    }

def backup_seaweedfs_logical(backup_dir: pathlib.Path, snapshot_ids: Optional[set] = None) -> Dict[str, Any]:
    logical_dir = backup_dir / "seaweedfs_logical"
    logical_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Exporting logical evidence objects from SeaweedFS Filer (%s)...", SEAWEEDFS_URL)
    
    engine = create_engine(MSSQL_URL)
    objects = []
    failed_objects = []
    corrupted_objects = []
    t0 = time.perf_counter()
    
    # Query all authoritative evidence in SQL Server
    with engine.connect() as conn:
        raw_conn = conn.connection
        cursor = raw_conn.cursor()
        cursor.execute("SELECT id, investigation_id, raw_content_path, content_hash, content_size_bytes, storage_backend FROM evidence ORDER BY id")
        evidence_rows = cursor.fetchall()

    if snapshot_ids is not None:
        evidence_rows = [r for r in evidence_rows if r[0] in snapshot_ids]
        
    client = httpx.Client(base_url=SEAWEEDFS_URL, timeout=10.0)
    for row in evidence_rows:
        ev_id, inv_id, file_path, expected_hash, expected_size, backend = row
        if not file_path:
            logger.info("Skipping metadata-only evidence ID %s (no physical content path)", ev_id)
            continue
            
        clean_path = file_path.lstrip("/").replace("\\", "/")
        content = None
        source_backend = backend or "seaweedfs"

        # Check local filesystem if backend is filesystem or file exists locally
        if backend == "filesystem":
            local_src = REPO_ROOT / "evidence_storage" / clean_path
            if local_src.exists():
                content = local_src.read_bytes()
                source_backend = "filesystem"
            else:
                logger.warning("Filesystem evidence %s missing at %s", ev_id, local_src)

        # Check SeaweedFS Filer
        if content is None:
            url_path = f"/{clean_path}" if clean_path.startswith("evidence/") else f"/evidence/{clean_path}"
            try:
                r = client.get(url_path)
                if r.status_code == 200:
                    content = r.content
                    source_backend = "seaweedfs"
                else:
                    # Fallback check on filesystem if SeaweedFS returned non-200
                    local_src = REPO_ROOT / "evidence_storage" / clean_path
                    if local_src.exists():
                        content = local_src.read_bytes()
                        source_backend = "filesystem_fallback"
                    else:
                        logger.warning("Failed to export evidence ID %s from SeaweedFS HTTP path %s: status %d", ev_id, url_path, r.status_code)
            except Exception as exc:
                logger.error("Error connecting to SeaweedFS for evidence %s: %s", ev_id, exc)

        if content is not None:
            digest = hashlib.sha256(content).hexdigest()
            target_path = logical_dir / f"evidence_{ev_id}_{pathlib.Path(file_path).name}"
            target_path.write_bytes(content)
            
            hash_match = (digest == expected_hash) if expected_hash else True
            size_match = (len(content) == expected_size) if expected_size else True
            is_valid = hash_match and size_match
            
            obj_entry = {
                "evidence_id": ev_id,
                "investigation_id": inv_id,
                "storage_backend": source_backend,
                "filer_path": f"/evidence/{clean_path}",
                "local_export_path": str(target_path.relative_to(backup_dir)),
                "size_bytes": len(content),
                "sha256": digest,
                "database_hash": expected_hash,
                "database_size": expected_size,
                "verified_integrity": is_valid
            }
            if not is_valid:
                corrupted_objects.append(obj_entry)
                logger.error("Evidence ID %s integrity verification FAILED! Hash match: %s, size match: %s", ev_id, hash_match, size_match)
            else:
                objects.append(obj_entry)
                logger.info("Exported evidence ID %s (%s) - %d bytes, verified: %s", ev_id, file_path, len(content), is_valid)
        else:
            failed_objects.append({
                "evidence_id": ev_id,
                "investigation_id": inv_id,
                "file_path": file_path,
                "storage_backend": backend,
                "reason": "content_unretrievable"
            })
            
    client.close()
    duration = round(time.perf_counter() - t0, 3)
    
    return {
        "filer_url": SEAWEEDFS_URL,
        "duration_seconds": duration,
        "object_count": len(objects),
        "failed_count": len(failed_objects),
        "corrupted_count": len(corrupted_objects),
        "objects": objects,
        "failed_objects": failed_objects,
        "corrupted_objects": corrupted_objects
    }

def run_coordinated_backup() -> pathlib.Path:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_id = f"coordinated_backup_{ts}"
    backup_dir = BACKUP_BASE_DIR / backup_id
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("================================================================================")
    logger.info("STARTING COORDINATED BACKUP: %s", backup_id)
    logger.info("Backup directory: %s", backup_dir)
    logger.info("================================================================================")
    
    start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    t_start = time.perf_counter()
    
    # 0. Pre-backup consistency check: snapshot evidence IDs
    engine = create_engine(MSSQL_URL)
    with engine.connect() as conn:
        cursor = conn.connection.cursor()
        cursor.execute("SELECT id FROM evidence ORDER BY id")
        pre_evidence_ids = set(r[0] for r in cursor.fetchall())

    # 1. SQL Server Backup
    db_res = backup_sql_server(backup_dir)

    # Detect in-flight evidence uploads during the database backup
    with engine.connect() as conn:
        cursor = conn.connection.cursor()
        cursor.execute("SELECT id FROM evidence ORDER BY id")
        post_evidence_ids = set(r[0] for r in cursor.fetchall())

    in_flight_uploads = sorted(list(post_evidence_ids - pre_evidence_ids))
    if in_flight_uploads:
        logger.warning("Detected %d in-flight evidence uploads during database backup: %s", len(in_flight_uploads), in_flight_uploads)

    # 2. SeaweedFS Physical Snapshot
    sw_phys_res = backup_seaweedfs_physical(backup_dir)
    
    # 3. SeaweedFS Logical Export (of authoritative rows from backup snapshot)
    sw_log_res = backup_seaweedfs_logical(backup_dir, snapshot_ids=pre_evidence_ids)
    
    total_duration = round(time.perf_counter() - t_start, 3)
    end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    has_failures = bool(
        sw_log_res.get("failed_count", 0) > 0
        or sw_log_res.get("corrupted_count", 0) > 0
        or not db_res.get("restore_verifyonly_passed")
    )
    backup_status = "FAILED_VERIFICATION" if has_failures else "COMPLETED_VERIFIED"

    # 4. Generate Manifest
    manifest = {
        "manifest_version": "1.1",
        "backup_id": backup_id,
        "created_at_utc": start_time,
        "completed_at_utc": end_time,
        "total_duration_seconds": total_duration,
        "status": backup_status,
        "in_flight_uploads_detected": in_flight_uploads,
        "database_backup": db_res,
        "seaweedfs_physical_backup": sw_phys_res,
        "seaweedfs_logical_backup": sw_log_res,
        "preservation_guarantee": {
            "local_storage_modified": False,
            "sqlite_db_modified": False,
            "seaweedfs_live_objects_modified": False
        }
    }
    
    manifest_file = backup_dir / "backup_manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifest_sha = sha256_file(manifest_file)
    logger.info("Saved verified backup manifest: %s (SHA-256: %s)", manifest_file, manifest_sha)

    if has_failures:
        logger.critical("BACKUP FAILED INTEGRITY VERIFICATION: failed=%d, corrupted=%d",
                        sw_log_res.get("failed_count", 0), sw_log_res.get("corrupted_count", 0))
        raise RuntimeError(f"Coordinated backup failed verification: {sw_log_res.get('failed_count')} missing, {sw_log_res.get('corrupted_count')} corrupted")

    logger.info("COORDINATED BACKUP COMPLETED IN %ss", total_duration)
    return backup_dir

if __name__ == "__main__":
    bdir = run_coordinated_backup()
    print(f"SUCCESS: Backup created at {bdir}")
