# FOOTPRINTIQ — BACKUP & DISASTER RECOVERY GUIDE

**Document ID:** `docs/FOOTPRINTIQ_BACKUP_AND_RECOVERY_GUIDE.md`  
**Date:** November 3, 2026  
**Audience:** Database Administrators, Storage Engineers, Disaster Recovery Teams  

---

## 1. Overview & Recovery Objectives

FootprintIQ persists structured metadata in Microsoft SQL Server 2022 Express and raw binary forensic evidence in SeaweedFS Filer. A unified disaster recovery strategy ensures data durability and business continuity.

### Service Level Objectives
- **Recovery Point Objective (RPO):** < 1 hour (via hourly SQL Server transaction logs / differential backups and daily full backups).
- **Recovery Time Objective (RTO):** < 15 minutes (full automated database and volume restore).

---

## 2. Backup Architecture

```
+--------------------------------------------------------------+
|                    FootprintIQ Storage Architecture          |
+--------------------------------------------------------------+
         |                                           |
         v                                           v
+-------------------------------+      +-------------------------------+
| SQL Server 2022 Express       |      | SeaweedFS Filer               |
| Database: [footprintiq]       |      | Volume Data (.dat, .idx)      |
+-------------------------------+      +-------------------------------+
         |                                           |
         | Native Backup                             | File / Snapshot Backup
         v                                           v
+--------------------------------------------------------------+
| Automated Backup Script: scripts/backup_evidence_and_database.py
| Backup Root: .data/backups/YYYYMMDD_HHMMSS/                  |
|  - footprintiq_full.bak (SQL Server with CHECKSUM)           |
|  - seaweedfs_evidence/  (Filer meta & volume archive)        |
|  - backup_manifest.json (SHA-256 integrity manifest)         |
+--------------------------------------------------------------+
```

---

## 3. Automated Backup Execution

Use the included backup script:
```powershell
python scripts/backup_evidence_and_database.py
```

### 3.1 What the Backup Script Executes
1. **SQL Server Full Backup:**
   ```sql
   BACKUP DATABASE [footprintiq]
   TO DISK = 'D:\Desktop\HackShift\footprint\.data\backups\YYYYMMDD_HHMMSS\footprintiq_full.bak'
   WITH INIT, CHECKSUM, STATS = 10;
   ```
2. **SQL Server Backup Verification:**
   ```sql
   RESTORE VERIFYONLY
   FROM DISK = 'D:\Desktop\HackShift\footprint\.data\backups\YYYYMMDD_HHMMSS\footprintiq_full.bak'
   WITH CHECKSUM;
   ```
3. **SeaweedFS Evidence Backup:**
   Copies all active evidence objects under the `/evidence` namespace to the backup target with streaming verification.
4. **Manifest Generation:**
   Computes SHA-256 hashes of all generated backup files and records byte counts in `backup_manifest.json`.

---

## 4. Disaster Recovery & Restoration Procedures

### 4.1 SQL Server Database Restoration
To restore the database from a backup file:
```powershell
sqlcmd -S "localhost\SQLEXPRESS" -E -Q "
ALTER DATABASE [footprintiq] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
RESTORE DATABASE [footprintiq]
FROM DISK = 'D:\Desktop\HackShift\footprint\.data\backups\20261103_000000\footprintiq_full.bak'
WITH REPLACE, RECOVERY;
ALTER DATABASE [footprintiq] SET MULTI_USER;
"
```

### 4.2 SeaweedFS Evidence Restoration
1. Stop the SeaweedFS filer service.
2. Restore volume data files (`.idx`, `.dat`) into the SeaweedFS data directory.
3. Restart SeaweedFS:
   ```powershell
   weed server -dir="D:\seaweedfs_data" -filer=true -filer.port=18888
   ```

### 4.3 Post-Restoration Reconciliation & Health Verification
1. Run the storage reconciliation tool to verify synchronization:
   ```powershell
   python scripts/audit_data_preservation.py
   ```
2. Run health probes:
   ```powershell
   .\scripts\check_footprintiq_health.ps1
   ```
3. Run the automated disaster recovery probe:
   ```powershell
   python scripts/test_disaster_recovery.py
   ```

---

## 5. Preservation & Archival Data Protection

- **Cold Baseline Backups:** Legacy SQLite database snapshots (`footprintiq.db`, `footprintiq.db-wal`, `footprintiq.db-shm`) are archived under `.data/preservation_backup/` and marked read-only.
- **Unreferenced Local Files:** Exactly 257 unreferenced local evidence files and 7 migrated local files (102,076 bytes) are preserved in `evidence_storage/` to maintain forensic chain-of-custody.

