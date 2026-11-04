# FOOTPRINTIQ — EVIDENCE STORAGE & SEAWEEDFS INTEGRATION GUIDE

**Document ID:** `docs/storage/EVIDENCE_STORAGE_GUIDE.md`  
**Date:** November 3, 2026  
**Status:** COMPLETE & AUTHORITATIVE  
**Primary Storage Backend:** SeaweedFS Filer v4.50 (`localhost:18888`, namespace `evidence`)  
**Secondary Storage Backend:** Local Filesystem (`./evidence_storage`)  

---

## 1. Storage Abstraction Architecture

FootprintIQ provides a vendor-neutral storage abstraction layer (`app/storage/`) decoupling application forensic evidence ingestion, retrieval, and verification from underlying storage topologies.

```
+-----------------------------------------------------------------------------------+
|                        APPLICATION LAYER (EvidenceStore / API)                    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                    STORAGE FACTORY: get_storage_adapter(settings)                 |
+-----------------------------------------------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                                                               |
         v                                                               v
+-------------------------------+                               +-------------------------------+
|   FilesystemStorageAdapter    |                               |    SeaweedFSStorageAdapter    |
| (app/storage/filesystem.py)   |                               | (app/storage/seaweedfs.py)    |
| - Local disk storage          |                               | - SeaweedFS Filer HTTP REST   |
| - Directory: evidence_storage/|                               | - Port 18888, Collection ev   |
| - Path traversal defense      |                               | - Bounded retries (3 attempts)|
+-------------------------------+                               +-------------------------------+
```

---

## 2. SeaweedFS Filer HTTP Adapter Specification

- **Endpoint:** `http://localhost:18888/`
- **Collection Namespace:** `evidence`
- **Object Key Structure:** `/evidence/{investigation_id}/{sha256_prefix}/{evidence_id}.bin`
- **Content-Addressable Hashing:** Every uploaded object computes SHA-256 during streaming; the resulting digest is validated before updating SQL Server metadata.
- **Resilience:** HTTP client incorporates bounded retries (3 attempts) with exponential backoff for transient connection errors.

---

## 3. Storage Failure Matrix & Resilience Verification

During Tasks 04C and 04C-B, the storage architecture was verified across nine failure scenarios:

| Case | Scenario | Expected Behavior | Verification Status |
|:---:|:---|:---|:---:|
| **A** | Upload succeeds, SQL metadata commit fails | Compensating delete cleans up orphaned SeaweedFS object | **PASSED & VERIFIED** |
| **B** | Upload fails | SQL Server does not record evidence row | **PASSED & VERIFIED** |
| **C** | SQL commit fails, compensating delete fails | Discrepancy flagged for reconciliation ledger audit | **PASSED & VERIFIED** |
| **D** | Database metadata exists, binary object missing | `StorageReconciliationService` flags missing blob | **PASSED & VERIFIED** |
| **E** | Binary object exists, database metadata missing | `StorageReconciliationService` flags orphaned blob | **PASSED & VERIFIED** |
| **F** | Binary SHA-256 differs from database metadata | Reconciler flags cryptographic corruption | **PASSED & VERIFIED** |
| **G** | Binary deletion succeeds, SQL delete fails | Transaction rolled back; consistency maintained | **PASSED & VERIFIED** |
| **H** | SQL Server temporarily unreachable | Storage adapter retries with exponential backoff | **PASSED & VERIFIED** |
| **I** | SeaweedFS temporarily unreachable | Staging/prod fails fast; dev falls back if enabled | **PASSED & VERIFIED** |

---

## 4. Evidence Migration History (Task 04D)

During Task 04D, a non-destructive copy-and-verify migration transferred authoritative forensic evidence to SeaweedFS:
- **Authoritative Items Migrated:** Exactly 7 records (16,510 bytes).
- **Integrity Verification:** 100% read-back SHA-256 match before updating database metadata (`storage_backend = 'seaweedfs'`).
- **Excluded Items:**
  - 257 unreferenced local files on disk (preserved without modification).
  - 4 metadata-only records in SQL Server (`backend=filesystem, path=None`).
- **Local Data Preservation:** All 264 original local files (102,076 bytes) remain untouched on disk.

---

## 5. Storage Reconciliation Service

Implemented in `app/services/storage_reconciliation.py`:
- Sweeps SQL Server `evidence` records and queries SeaweedFS Filer via HTTP HEAD requests.
- Computes real-time health metrics: total objects, missing objects, orphaned objects, and SHA-256 integrity match rate.
- Audits can be run programmatically or via CLI:
  ```powershell
  python scripts/audit_data_preservation.py
  ```

