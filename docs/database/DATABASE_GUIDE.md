# FOOTPRINTIQ — DATABASE ARCHITECTURE & MIGRATION GUIDE

**Document ID:** `docs/database/DATABASE_GUIDE.md`  
**Date:** November 3, 2026  
**Status:** COMPLETE & AUTHORITATIVE  
**Primary Database:** Microsoft SQL Server 2022 Express (`localhost\SQLEXPRESS`, database `footprintiq`)  
**ORM:** SQLAlchemy 2.0 (Dual-Dialect mssql+pyodbc / sqlite)  

---

## 1. Database Architecture Overview

FootprintIQ uses Microsoft SQL Server 2022 Express as its primary production metadata store, with backward compatibility and developer testing support for SQLite.

```
+-----------------------------------------------------------------------------------+
|                            DATABASE CONNECTION POOL                               |
+-----------------------------------------------------------------------------------+
|  Primary: mssql+pyodbc://@localhost\SQLEXPRESS/footprintiq                        |
|  - Driver: ODBC Driver 17 / 18 for SQL Server                                     |
|  - Isolation: READ_COMMITTED_SNAPSHOT (RCSI) enabled                              |
|  - Connection Retry: Exponential backoff with jitter (app/core/db_retry.py)       |
|  - Pool Size: 10 connections (max overflow: 20)                                   |
|                                                                                   |
|  Development Fallback: sqlite:///./footprintiq.db                                 |
|  - PRAGMA journal_mode=WAL (Write-Ahead Logging)                                  |
|  - PRAGMA foreign_keys=ON                                                         |
|  - STRICTLY LOCKED OUT IN STAGING & PRODUCTION (DB_FALLBACK_TO_SQLITE=False)      |
+-----------------------------------------------------------------------------------+
```

---

## 2. Schema Evolution & Alembic Migrations

Schema migrations are strictly managed through Alembic revisions located in `migrations/versions/`:

| Revision | File Name | Description | Key Changes |
|:---:|:---|:---|:---|
| **0001** | `0001_initial_schema.py` | Initial User & Session Schema | Tables: `users`, `user_sessions` |
| **0002** | `0002_add_audit_log.py` | Tamper-Evident Audit Logging | Table: `audit_events` |
| **0003** | `0003_add_passive_recon_and_evidence.py` | Passive Recon & Evidence | Tables: `investigations`, `evidence`, `recon_entities`, `recon_artifacts` |
| **0004** | `0004_add_nmap_active_scans.py` | Active Reconnaissance | Tables: `target_authorizations`, `nmap_scans`, `nmap_ports` |
| **0005** | `0005_add_vulnerability_scans.py` | Vulnerability Scanning | Tables: `vulnerability_scans`, `vulnerability_findings` |
| **0006** | `0006_account_approval_and_passwords.py` | Account Lifecycle Hardening | Columns: `account_status`, `approved_at`, `password_changed_at` |
| **0007** | `0007_investigation_ownership.py` | Tenant Isolation & Ownership | Columns: `owner_user_id` FK to `users.id`, `team_members` JSON |
| **0008** | `0008_durable_jobs.py` | Durable Job Execution Queue | Table: `jobs` (heartbeats, worker leasing, crash recovery) |
| **0009** | `0009_evidence_storage_backend.py` | Evidence Storage Abstraction | Columns: `storage_backend`, `storage_path`, `content_type` in `evidence` |

To apply all migrations:
```powershell
alembic upgrade head
```

---

## 3. Data Migration (Task 03 ETL Verification)

During Task 03, the entire database baseline was migrated from SQLite to SQL Server 2022 Express via `scripts/migrate_sqlite_to_mssql.py`.

### Migration Parity & Integrity Metrics
- **Total Tables Migrated:** 14 tables
- **Total Records Migrated:** Exactly 375 records
- **Deterministic Checksum Match:** 100% SHA-256 parity across all 14 tables
- **Foreign Key Referential Integrity:** 8/8 checks passed with zero constraint violations
- **Preserved Baseline Record Counts:**
  - `investigations`: 15 records
  - `evidence`: 11 records (7 migrated SeaweedFS objects, 4 metadata-only records)
  - `users`: 17 records
  - `target_authorizations`: 14 records
  - `audit_events`: 110 records

---

## 4. SQLite Baseline & Data Preservation

FootprintIQ enforces a strict, non-destructive data preservation policy:
1. **SQLite Database Triplet:** `footprintiq.db` (565,248 bytes, SHA-256: `a0df074ed6e0fc53a33a6a4bd5e19857f45e8e5c8a4a24e7075c1f7db4cc004e`), along with its backup files (`footprintiq.db.backup`, `footprintiq.db.backup-shm`, `footprintiq.db.backup-wal`), is preserved bit-for-bit as an immutable historical record.
2. **Cold Backups:** Preserved in `.data/preservation_backup/` with verified cryptographic hashes.
3. **Verification Command:**
   ```powershell
   python scripts/audit_data_preservation.py
   ```

---

## 5. Core Data Dictionary

### 5.1 `investigations`
Primary entity representing digital footprint reconnaissance campaigns.
- `id` (VARCHAR(64), PK): Unique investigation UUID.
- `name` (VARCHAR(128)): Campaign name.
- `owner_user_id` (VARCHAR(64), FK to users.id): Owning investigator account.
- `status` (VARCHAR(32)): Current lifecycle state (`draft`, `ready`, `running`, `partially_completed`, `completed`, `cancelled`).
- `active_targets` (NVARCHAR(MAX) / JSON): Allowed target scope list.

### 5.2 `jobs`
Durable background execution queue.
- `id` (VARCHAR(64), PK): Job identifier.
- `investigation_id` (VARCHAR(64), FK): Associated investigation.
- `job_type` (VARCHAR(32)): Job category (`WORKFLOW_ORCHESTRATION`, `NMAP_SCAN`, `VULN_SCAN`).
- `status` (VARCHAR(32)): Job state (`QUEUED`, `CLAIMED`, `RUNNING`, `COMPLETED`, `CANCELLED`, `FAILED`).
- `worker_id` (VARCHAR(64)): Active worker identity.
- `lease_expires_at` (DATETIME2): Heartbeat lease expiration timestamp.

### 5.3 `evidence`
Forensic proof artifacts.
- `id` (VARCHAR(64), PK): Evidence ID (e.g., `ev-p7-01`).
- `investigation_id` (VARCHAR(64), FK): Investigation UUID.
- `storage_backend` (VARCHAR(32)): Storage provider (`filesystem` or `seaweedfs`).
- `storage_path` (VARCHAR(512)): Relative filesystem path or SeaweedFS URI.
- `sha256_hash` (VARCHAR(64)): Cryptographic SHA-256 hash digest.
- `file_size_bytes` (BIGINT): Binary size.

