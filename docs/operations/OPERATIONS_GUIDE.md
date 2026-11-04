# FOOTPRINTIQ — SYSTEM OPERATIONS & MONITORING GUIDE

**Document ID:** `docs/FOOTPRINTIQ_OPERATIONS_GUIDE.md`  
**Date:** November 3, 2026  
**Audience:** DevSecOps Engineers, Database Administrators, Security Operations Center (SOC)  

---

## 1. Operational Overview

FootprintIQ is engineered for zero-downtime operations, fault-tolerant background execution, and forensic auditability. This guide defines runtime monitoring, background job inspection, storage reconciliation, and incident response procedures.

---

## 2. Health Monitoring & Observability

### 2.1 Health Check Endpoints
| Endpoint | Method | Purpose | Expected Status |
|:---|:---:|:---|:---:|
| `/health/live` | GET | Liveness probe (process responsive) | `200 {"status": "ok"}` |
| `/health/ready` | GET | Readiness probe (SQL Server & SeaweedFS accessible) | `200 {"status": "ok", "db": true, "storage": true}` |
| `/health/badge` | GET | Real-time SVG status badge for dashboard | `200 image/svg+xml` |
| `/api/v1/health` | GET | Detailed diagnostic telemetry | `200 JSON payload` |

### 2.2 Correlated Structured Logging
All application logs include request correlation IDs via `X-Request-ID`:
```json
{
  "timestamp": "2026-11-03T11:45:00.123Z",
  "level": "INFO",
  "request_id": "req-99364fced33f",
  "logger": "footprintiq.workflow",
  "message": "[inv-task05-val-1793686791] STAGE 1: Passive Reconnaissance completed.",
  "duration_ms": 1150.2
}
```
In production, set:
```ini
LOG_LEVEL="INFO"
LOG_FORMAT="structured"
```

---

## 3. Durable Job Queue & Worker Management

Background workflows execute through the durable `jobs` table in SQL Server:

### 3.1 Inspecting Active Jobs
```sql
SELECT id, investigation_id, job_type, operation, status, progress, lease_expires_at, retry_count
FROM jobs
WHERE status IN ('QUEUED', 'CLAIMED', 'RUNNING')
ORDER BY created_at DESC;
```

### 3.2 Stale Job Recovery
The worker heartbeat protocol leases jobs for 120 seconds. If a worker process abruptly crashes:
1. `JobRecoveryService` identifies jobs whose `lease_expires_at < GETUTCDATE()`.
2. Stale jobs are reset to `QUEUED` if `retry_count < max_retries`, or marked `FAILED`.
3. Recovery executes automatically during application startup lifespan:
   ```python
   recovery = get_job_recovery()
   summary = recovery.recover_stale_jobs(db_factory=SessionLocal)
   ```

---

## 4. Evidence Storage Reconciliation

Run regular reconciliation audits to verify synchronization between SQL Server metadata and SeaweedFS objects:

### 4.1 Running Storage Audit CLI
```powershell
python scripts/audit_data_preservation.py
```

### 4.2 Automated Reconciliation Execution
Invoke the reconciliation service programmatically or via scheduled maintenance tasks:
```python
from app.database import SessionLocal
from app.services.storage_reconciliation import StorageReconciliationService

with SessionLocal() as db:
    reconciler = StorageReconciliationService(db)
    ledger = reconciler.reconcile()
    print("Reconciliation Discrepancies:", ledger.total_discrepancies)
```
The reconciler detects:
- Missing SeaweedFS objects (database record exists without binary).
- Unreferenced SeaweedFS blobs (binary exists without database record).
- SHA-256 integrity corruptions.

---

## 5. Security Audit Log Inspection

Security audit records are written to the `audit_events` table with actor, request ID, client IP, action, and JSON payload.

### 5.1 Querying Security Violations & Failed Logins
```sql
SELECT TOP 50 id, timestamp, action, actor_id, client_ip, request_id, details
FROM audit_events
WHERE action IN ('AUTH_FAILURE', 'ACCOUNT_LOCKOUT', 'UNAUTHORIZED_ACCESS_ATTEMPT', 'SCOPE_VIOLATION')
ORDER BY timestamp DESC;
```

---

## 6. Maintenance & Performance Tuning

1. **SQL Server Index Maintenance:** Rebuild indexes periodically on `jobs`, `evidence`, `entities`, and `audit_events`.
2. **SeaweedFS Vacuuming:** SeaweedFS Filer automatically garbage collects deleted chunks via scheduled vacuum routines on the volume server.
3. **Session Purging:** Expired sessions in `user_sessions` can be safely cleaned up via:
   ```sql
   DELETE FROM user_sessions WHERE expires_at < GETUTCDATE();
   ```

