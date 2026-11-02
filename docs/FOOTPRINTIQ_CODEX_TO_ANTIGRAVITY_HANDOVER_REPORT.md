# FOOTPRINTIQ — CODEX TO ANTIGRAVITY HANDOVER AUDIT REPORT
**Execution Date:** 2026-11-02 (Local System Time: Asia/Calcutta)  
**Auditor / Incoming Platform Architect:** Antigravity  
**Predecessor AI Assistant:** OpenAI Codex  
**Repository:** `https://github.com/asipali/FootPrintQ_v2`  
**Branch:** `migration/python-only`  
**Baseline HEAD Commit:** `f484b09 fix modules`  
**Working Tree Status:** 10 modified files (unstaged), 2 untracked files, 0 staged files  

---

## A. Executive Summary

### 1. Current Project State
The FootprintIQ platform has transitioned away from the legacy hybrid React 19 / Express 4 prototype into a unified **Python 3.11 / FastAPI / SQLAlchemy / Jinja2 + HTMX** architecture on the `migration/python-only` branch. The codebase currently implements authentication, server-managed sessions, RBAC, investigation dossiers, target allowlist authorizations, passive reconnaissance (DNS, RDAP, CRT.sh, theHarvester), Nmap port/service scanning, Greenbone/OpenVAS vulnerability assessments, forensic evidence storage, 5-factor exposure scoring, and ReportLab PDF / GraphML export capabilities.

Persistence is currently configured for a local SQLite database (`footprintiq.db`) operating with Write-Ahead Logging (WAL) enabled, and forensic evidence artifacts are stored on the local filesystem (`./evidence_storage`). Target architectures require migration to **SQL Server 2022 Express** for application metadata and **SeaweedFS** for scalable object storage.

### 2. Last Confirmed Completed Task
**Task 00 — Initial Engineering Audit & Baseline Review**: A comprehensive 16-module architectural audit was completed across `docs/` (`MODULE_05_*` through `MODULE_16_*`, `GROUP_4_*` through `GROUP_6_*`), documenting all capabilities, limitations, and identifying security and persistence deficiencies.

### 3. Current Active Task
**Task 01 / Task 01A — Security Hardening and Data Preservation Review**: Codex implemented CSRF hardening across authenticated REST mutation routes, validated server-side Bearer sessions for the CSRF exemption, isolated test evidence storage, and redirected test application startup database probes. However, during initial test execution prior to fixture isolation, the tracked SQLite sidecar file `footprintiq.db-shm` was modified. Task 01A recommended that the worktree **NOT BE APPROVED** until the SQLite sidecar issue is investigated and data preservation decisions are formalized. Task 01B was proposed as a read-only preservation and repository hygiene review.

### 4. Codex Stopping Point
Codex completed implementation and local testing of Task 01, authored `docs/FOOTPRINTIQ_TASK_01_SECURITY_HARDENING_REPORT.md` disclosing the `footprintiq.db-shm` modification as a "data-handling exception", and suggested Task 02 in Section 11 of that report. Codex stopped immediately after writing that report. Codex did **NOT** begin Task 01B, did **NOT** produce a Task 02 implementation plan, and did **NOT** begin implementation of Task 02, Task 03, or Task 04.

### 5. Overall Handover Verdict
**APPROVAL BLOCKED / PENDING DATA PRESERVATION & REPOSITORY HYGIENE DECISION**: The application source code changes for Task 01 are technically sound, well-tested (250 unit/integration tests passing in isolated test environments), and strictly enforce CSRF and test isolation. However, the repository worktree cannot be committed in its current state because binary SQLite files (`footprintiq.db-shm`, `footprintiq.db.backup*`) are improperly tracked in Git while `*.db` and `*.db-wal` are gitignored, and the active `footprintiq.db-wal` holds 3.6 MB of uncheckpointed data. A non-destructive preservation procedure (Task 01B) must be executed before Task 01 is committed and before Task 02 is planned.

---

## B. Git and Working Tree State

### 1. Repository Identifiers
- **Local Workspace Root:** `D:\Desktop\HackShift\footprint`
- **Active Branch:** `migration/python-only`
- **Upstream Tracking:** `origin/migration/python-only` (synchronized with remote HEAD)
- **HEAD Commit Hash:** `f484b0945fc7534b190d1a32ec53d5b5d9742ee2`
- **HEAD Commit Message:** `fix modules` (Committed: Mon Nov 2 13:40:25 2026 +0530 by Asip Ali)

### 2. Recent Commit History
```
f484b09 (HEAD -> migration/python-only, origin/migration/python-only) fix modules
3f3c798 update landingpage
dfea49d Add Login System
046e3fa Update UI
24d6b53 Update UI
847386f (tag: pre-python-only-2026-11-01, origin/main, main) Initial Commit from IDE
```

### 3. Status of Working Tree
- **Staged Changes (`git diff --cached`):** `0` files (Clean index).
- **Unstaged Changes (`git diff`):** `10` modified files.
- **Untracked Files:** `2` files.

#### Detailed File Delta Breakdown:
| File Path | Status | Author/Source | Description of Changes |
|---|---|---|---|
| `app/api/deps.py` | Modified | Codex (Task 01) | Updated `verify_csrf_token` to validate that `Authorization: Bearer <token>` resolves to an active, unexpired, unrevoked session in `user_sessions` and that the account is active/unlocked before exempting from CSRF. |
| `app/api/nmap_scans.py` | Modified | Codex (Task 01) | Attached `csrf_ok: None = Depends(verify_csrf_token)` to `dispatch_nmap_scan` (POST) and `cancel_scan_job` (POST). |
| `app/api/recon.py` | Modified | Codex (Task 01) | Attached `verify_csrf_token` to `trigger_passive_recon` (POST) and `validate_target` (POST). |
| `app/api/users.py` | Modified | Codex (Task 01) | Attached `verify_csrf_token` to `create_user` (POST), `update_user_role` (PATCH), and `update_user_status` (PATCH). |
| `app/api/vulnerability.py` | Modified | Codex (Task 01) | Attached `verify_csrf_token` to `dispatch_vulnerability_assessment` (POST) and `cancel_vulnerability_assessment` (POST). |
| `app/models/__init__.py` | Modified | Codex / Environment | Normalization of line endings (CRLF/LF); semantic model imports identical. |
| `footprintiq.db-shm` | Modified | Test Runtime Artifact | Tracked binary SQLite shared-memory index modified when tests touched the real database before startup probe isolation was implemented. |
| `tests/conftest.py` | Modified | Codex (Task 01) | Added `isolated_test_settings` fixture; added `isolated_evidence_storage` autouse fixture redirecting implicit `EvidenceStore` writes to `tmp_path`; monkeypatched `app.main.check_database_connection` so app startup probes query `test_engine` rather than module-global `engine`. |
| `tests/test_csrf_and_cookies.py` | Modified | Codex (Task 01) | Added `test_safe_get_with_cookie_session_does_not_require_csrf` regression test. |
| `tests/test_evidence_storage.py` | Modified | Codex (Task 01) | Added `test_default_store_uses_isolated_temp_root_not_configured_evidence_path` and `test_evidence_read_reports_tampered_content_hash`. |
| `tests/test_mutation_csrf.py` | Untracked | Codex (Task 01) | New test suite with 8 regression tests verifying CSRF enforcement, Bearer header validation, role isolation, and ensuring rejected mutations write zero jobs or evidence files. |
| `docs/FOOTPRINTIQ_TASK_01_SECURITY_HARDENING_REPORT.md` | Untracked | Codex (Task 01) | Detailed Task 01 report documenting rationale, test commands, results, risks, and disclosing the `footprintiq.db-shm` modification. |

### 4. Database-Related Working Tree Changes
- `footprintiq.db-shm` is **tracked by Git** (committed in `24d6b53` and `f484b09`). Its SHA-256 in `HEAD` was `2D93EAC0AAA2BDB88130CB21454ED461EFA062B8E908AE41ADCCFDDFCAB68D66`. Its current SHA-256 on disk is `28BF8315C97B5A74E4B1AE61DC44F54B94AAF9034A9C37CFC08DC124D12D77C9`.
- `footprintiq.db` (516,096 bytes) and `footprintiq.db-wal` (3,666,832 bytes) are **ignored** by `.gitignore` (`*.db`, `*.db-wal`), creating an asymmetric tracking state where the WAL index is versioned but the database and WAL log are not.

### 5. Files That Must Be Preserved
1. `footprintiq.db` (516 KB): Primary SQLite database containing application users, investigations, and scopes.
2. `footprintiq.db-wal` (3.6 MB): Write-Ahead Log containing uncheckpointed application transactions. Must never be deleted, truncated, or decoupled from `footprintiq.db`.
3. `footprintiq.db-shm` (32 KB): Active shared memory index corresponding to `footprintiq.db-wal`.
4. `footprintiq.db.backup`, `footprintiq.db.backup-shm`, `footprintiq.db.backup-wal`: Cold database backup snapshot committed in the repository.
5. `.data/backups/footprintiq-pre-module05-06-20261102-115349.db`: Standalone SQLite snapshot taken during the Module 05/06 audit.
6. `evidence_storage/`: Directory containing 29 authentic forensic evidence files (raw DNS JSON, RDAP responses, CRT.sh certificates, Nmap outputs, and Greenbone reports) referenced by database foreign keys.
7. All 22 existing audit and documentation files located in `docs/` and root `PYTHON_ONLY_MIGRATION_AUDIT.md`.

---

## C. Task Completion Matrix

| Task | Expected Work | Actual Status | Evidence | Remaining Work |
|---|---|---|---|---|
| **Task 00** | Initial engineering audit and module-by-module baseline review. | **IMPLEMENTED** | 16 module reports in `docs/` (`MODULE_05_*` to `MODULE_16_*`), `GROUP_4_*`, `GROUP_5_*`, `GROUP_6_FINAL_AUDIT_REPORT.md`, `FOOTPRINTIQ_FEATURE_MATRIX.md`. | None. Audit completed and documented. |
| **Task 01** | Security hardening: CSRF across mutation routes, Bearer session validation, per-test evidence isolation, startup DB probe isolation, regression tests. | **APPROVAL REQUIRED** | Source changes in `app/api/deps.py`, `users.py`, `nmap_scans.py`, `vulnerability.py`, `recon.py`; tests in `tests/conftest.py`, `test_mutation_csrf.py`; report `docs/FOOTPRINTIQ_TASK_01_SECURITY_HARDENING_REPORT.md`. | Worktree approval blocked due to `footprintiq.db-shm` modification. Awaits formal user decision and repository hygiene resolution. |
| **Task 01A** | Data integrity and security review regarding `footprintiq.db-shm` modification. | **IMPLEMENTED** | Documented in Task 01 report Section 1 and Section 8; verified binary diff on `footprintiq.db-shm`. | Precursor to Task 01B. Completed at audit level. |
| **Task 01B** | Read-only SQLite preservation and repository-hygiene review. | **NOT STARTED** | Zero files, reports, branches, or commits exist for Task 01B. Proposed in Task 01A review but never initiated by Codex. | Must perform cold non-destructive database backup, analyze WAL checkpoint safety, and formulate `.gitignore` / `git rm --cached` plan for `*.db-shm`. |
| **Task 02** | Durable job execution, persistent DB-backed records, worker claiming, retry handling, cancellation, restart recovery, automated tests. | **NOT STARTED** | Code review confirms scan jobs execute via in-memory `asyncio.create_task()` in `app/api/nmap_scans.py` and `app/api/vulnerability.py`. Zero worker, queue, or recovery logic exists. | Inspection & architecture plan must be produced FIRST; implementation pending user approval. |
| **Task 03** | SQL Server 2022 Express integration, SQLAlchemy dialect configuration, schema compatibility, Alembic migrations, data migration plan. | **NOT STARTED** | Codebase has zero SQL Server drivers (`pyodbc`), connection strings, or dialect-specific branches. Migrations in `migrations/versions/` use SQLite batch syntax exclusively. | Pre-implementation audit and migration plan must be produced FIRST; implementation pending user approval. |
| **Task 04** | SeaweedFS evidence storage integration, provider-neutral abstraction, S3/filer adapter, metadata integration, integrity verification. | **NOT STARTED** | `app/services/evidence_store.py` interacts exclusively with local filesystem paths (`Path.mkdir`, `Path.write_bytes`). No SeaweedFS client or configuration exists. | Architecture and implementation plan must be produced FIRST; implementation pending user approval. |

---

## D. Codex Stopping Point

### 1. Last Known Action
Codex completed the implementation of Task 01 (CSRF route protection and test environment isolation), ran the full automated test suite (reporting `250 passed, 1 skipped, 20 warnings`), noted that `footprintiq.db-shm` remained modified in `git status`, and authored the comprehensive report `docs/FOOTPRINTIQ_TASK_01_SECURITY_HARDENING_REPORT.md`.

### 2. Last Modified Source Files
- Implementation files: `app/api/deps.py`, `app/api/users.py`, `app/api/nmap_scans.py`, `app/api/vulnerability.py`, `app/api/recon.py`.
- Test files: `tests/conftest.py`, `tests/test_csrf_and_cookies.py`, `tests/test_evidence_storage.py`, `tests/test_mutation_csrf.py`.
- Documentation: `docs/FOOTPRINTIQ_TASK_01_SECURITY_HARDENING_REPORT.md`.

### 3. Last Verified Test Result
- Full suite execution: `python -m pytest -q` (with `DEBUG=false` and `RUN_LOCALHOST_NMAP` unset).
- Result: **250 passed, 1 skipped, 20 warnings in 43.41s** (Exit code 0).
- The single skipped test was `test_real_localhost_nmap_scan_integration` (requires opt-in environment flag `RUN_LOCALHOST_NMAP=1` and live Nmap binary execution against loopback).
- Warnings consisted of Starlette/HTTPX deprecations, Starlette `HTTP_422_UNPROCESSABLE_ENTITY` deprecations, and a SQLAlchemy session rollback warning.

### 4. Incomplete Work
- Task 01 source code was left uncommitted in the working tree.
- The `footprintiq.db-shm` sidecar modification was acknowledged but left unresolved in Git.
- Task 01B was proposed but never started.
- Task 02, Task 03, and Task 04 were never planned or implemented.

### 5. Exact Reason Handover Is Required
The previous reviewer/auditor issued a stop-work recommendation on Task 01A:
> *"DO NOT APPROVE the current worktree for commit until the SQLite sidecar issue has been investigated and the data-preservation decision has been made."*
Codex stopped at this exact boundary to allow an independent senior engineering inspection to verify data integrity, evaluate the sidecar risk, and formulate a safe path forward without risking data loss.

---

## E. Security Review

| Identifier | Vulnerability / Defect | Severity | Status | Technical Detail & Remediation |
|---|---|---|---|---|
| **SEC-01** | Tracking SQLite WAL index (`footprintiq.db-shm`) in Git while ignoring database and WAL files | **HIGH** | **CONFIRMED RISK** | `footprintiq.db-shm` is checked into Git, but `footprintiq.db` and `footprintiq.db-wal` are in `.gitignore`. The SHM file contains dynamic memory-mapped index offsets into the local WAL file. Committing, pulling, or rebasing this file across environments or branches can lead to frame index misalignment, transaction desynchronization, or `SQLITE_CORRUPT`. **Remediation:** Remove `*.db-shm` and `*.db.backup*` from Git tracking (`git rm --cached`), add `*.db-shm` to `.gitignore`, and preserve database files exclusively through dedicated external backups. |
| **SEC-02** | Uncheckpointed WAL File Accumulation (3.6 MB WAL vs 516 KB base DB) | **HIGH** | **CONFIRMED RISK** | The WAL file `footprintiq.db-wal` contains 3,666,832 bytes of transaction logs while `footprintiq.db` is only 516,096 bytes. In SQLite WAL mode, database reads require replaying the WAL frames against the shared memory index. If an uncoordinated write, git checkout, or accidental truncation occurs, all uncheckpointed transactions are lost. **Remediation:** Create an isolated cold file copy of the full triplet (`.db`, `.db-wal`, `.db-shm`) prior to any repository modification. Once backed up, safely execute a passive WAL checkpoint (`PRAGMA wal_checkpoint(PASSIVE)`) to flush committed pages to disk. |
| **SEC-03** | In-Process Ephemeral Job Execution without Durable Queue or Restart Recovery | **HIGH** | **CONFIRMED DEFECT** | Active Nmap scans (`app/services/active/runner.py`) and Greenbone scans (`app/services/vuln/orchestrator.py`) are dispatched via `asyncio.create_task()`. State is maintained in-process and in SQLite status columns. If the application server process terminates, restarts, or crashes during a scan, running tasks are terminated without cleanup, leaving database records in `RUNNING` or `QUEUED` state indefinitely with no supervisor process to recover, retry, or resume them. **Remediation:** Implemented in Task 02 via durable database-backed worker architecture, heartbeat/lease claiming, and startup stale-job reconciliation. |
| **SEC-04** | Ephemeral Cancellation State | **MEDIUM** | **CONFIRMED DEFECT** | Cancellation requests for Nmap and Greenbone scans rely on in-memory asyncio task dictionaries and subprocess handles (`self._active_scans[job_id]`). A cancellation request issued after a server restart or to an alternate worker process cannot reach the underlying process, leaving orphans. **Remediation:** Track OS process IDs (PIDs) and task UUIDs durably in the database, with worker-level lease management. |
| **SEC-05** | Missing Dependency Lockfile | **MEDIUM** | **CONFIRMED RISK** | The repository contains `pyproject.toml` with permissive minimum version constraints (`>=`), but no lockfile (`poetry.lock`, `requirements.lock`, or `Pipfile.lock`). Deployments or CI builds install the latest floating minor/patch releases of dependencies (such as FastAPI, Starlette, ReportLab, or SQLAlchemy), exposing the application to upstream breaking changes or supply-chain regressions. **Remediation:** Generate and enforce a pinned `requirements.lock` using `pip-tools` or `uv`. |
| **SEC-06** | REST Mutation Route CSRF Vulnerabilities | **LOW** | **RESOLVED IN TASK 01** | Multiple authenticated REST mutation endpoints (user management, scan dispatch, scan cancellation, passive recon) previously omitted `verify_csrf_token`. Codex successfully attached `Depends(verify_csrf_token)` to all mutation routes, verified that session cookies enforce double-submit CSRF, and confirmed that Bearer tokens require a valid, unexpired server session to qualify for exemption. Regression tests in `tests/test_mutation_csrf.py` confirm coverage. |
| **SEC-07** | CSP and Advanced Web Headers | **INFORMATIONAL** | **PLANNED** | Content Security Policy (CSP) and Multi-Factor Authentication (MFA) are not yet implemented. Documented in Task 00/Task 01 as post-foundation roadmap items. |

---

## F. Database and Evidence Preservation

### 1. SQLite File Physical State
Inspection of the SQLite database files in the repository root confirms the following attributes:

| File Name | File Size | Last Modified (Local Time) | Git Tracking Status | SHA-256 Digest |
|---|---|---|---|---|
| `footprintiq.db` | 516,096 bytes | 2026-11-02 11:18:36 | **Untracked / Ignored** (`*.db`) | `8A76DE892695600F09CDBC6627A381279134B63FF393BA4D94789E9C3F7D4F57` |
| `footprintiq.db-wal` | 3,666,832 bytes | 2026-11-02 14:54:22 | **Untracked / Ignored** (`*.db-wal`) | `089871B42AB9B84058D884B3577A7BA543758B2309ADFA036960E661ED301232` |
| `footprintiq.db-shm` | 32,768 bytes | 2026-11-02 17:56:40 | **Tracked in Git (Modified)** | `28BF8315C97B5A74E4B1AE61DC44F54B94AAF9034A9C37CFC08DC124D12D77C9` |
| `footprintiq.db.backup` | 466,944 bytes | 2026-10-28 03:06:34 | **Tracked in Git (Unmodified)** | `B11B4F58EB092DF7F3C8CDCC0DDEC4E0B9672C3358C66C093DBC78E75421F0D6` |
| `footprintiq.db.backup-shm` | 32,768 bytes | 2026-11-02 13:12:40 | **Tracked in Git (Unmodified)** | `FD4C9FDA9CD3F9AE7C962B0DDF37232294D55580E1AA165AA06129B8549389EB` |
| `footprintiq.db.backup-wal` | 0 bytes | 2026-11-02 13:11:17 | **Tracked in Git (Unmodified)** | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |

### 2. SHM and WAL Structural Relationship
In SQLite WAL mode, database mutations are written sequentially to the `-wal` file. The `-shm` file contains the hash table index mapping page numbers in the database to frame numbers in the WAL file, allowing concurrent reader connections to locate the latest version of any page without locking.
- The `footprintiq.db-wal` file is currently **3.66 MB**, indicating hundreds of pages of uncheckpointed data.
- The Git commit `f484b09` tracked an older state of `footprintiq.db-shm` (hash: `2D93EAC0...`).
- When test runners or application workers connect to `footprintiq.db`, SQLite inspects the WAL header, detects that the shared memory index does not match the active WAL file, and automatically regenerates/updates the `-shm` file to maintain internal consistency.
- Because `footprintiq.db-shm` is tracked in Git, Git flags it as a modified binary file. If a developer runs `git checkout -- footprintiq.db-shm`, the SHM file will be reverted to an obsolete revision from `f484b09`, creating a desynchronization between the SHM index and the 3.66 MB WAL file.

### 3. Data Preservation Protocol & Required User Approvals
To maintain data integrity without violating safety guidelines:
1. **Cold Preservation Backup:** Before executing any Git checkout, commit, or checkpoint operation, the triplet (`footprintiq.db`, `footprintiq.db-wal`, `footprintiq.db-shm`) must be copied directly to a timestamped backup directory (e.g., `.data/backups/cold_preservation_20261102/`).
2. **Untracking Binary Sidecars:** The user must explicitly approve untracking `footprintiq.db-shm` and `footprintiq.db.backup*` via `git rm --cached` and updating `.gitignore` to ignore `*.db-shm` and `*.db.backup*`.
3. **Passive Checkpointing:** Following cold preservation, an authorized SQLite checkpoint (`PRAGMA wal_checkpoint(PASSIVE)`) should be executed to integrate all 3.6 MB of WAL frames into the main database file `footprintiq.db` cleanly.

### 4. SQL Server & SeaweedFS Integration Status
- **SQL Server 2022 Express (Task 03):** Currently **NOT STARTED**. No schema or migration files support T-SQL syntax. Alembic migrations in `migrations/versions/` rely on `batch_alter_table` which is specific to SQLite table rebuilding.
- **SeaweedFS Object Storage (Task 04):** Currently **NOT STARTED**. Evidence storage uses `app/services/evidence_store.py`, writing raw JSON/XML files directly to disk under `evidence_storage/<investigation_id>/`. No S3 or SeaweedFS Filer APIs are integrated.

---

## G. Remaining Work Implementation Backlog

The following backlog defines the sequential, prioritized roadmap required to complete the FootprintIQ system:

### Phase 1: Repository Hygiene & Data Preservation (Task 01B)
- **Priority:** P0 (Immediate prerequisite before any commit or new feature).
- **Description:** Execute cold preservation of existing SQLite database and WAL files; untrack binary database artifacts from Git; update `.gitignore`; verify worktree cleanliness; obtain formal approval to commit Task 01.
- **Dependencies:** None.
- **Affected Files:** `.gitignore`, `footprintiq.db-shm`, `footprintiq.db.backup*`, `.data/backups/`.
- **Acceptance Criteria:** Cold backup verified; `git status` shows zero database binaries tracked; Task 01 changes committed with clean message; 250 tests pass.
- **Risks:** Accidental database truncation or loss of 3.6 MB WAL data if cold copy is omitted.

### Phase 2: Durable Job Execution and Restart Recovery (Task 02)
- **Priority:** P1 (Core architecture).
- **Description:** Replace ephemeral `asyncio.create_task` execution with a database-backed job engine. Implement worker claiming with leases/heartbeats, explicit state machine transitions (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `TIMED_OUT`), startup stale-job recovery (detecting jobs stranded in `RUNNING` on reboot), retry limits, and duplicate execution guards.
- **Dependencies:** Task 01B approval and clean worktree.
- **Affected Files:** `app/models/scan.py`, `app/models/vulnerability.py`, `app/models/recon.py`, `app/services/active/runner.py`, `app/services/vuln/orchestrator.py`, `app/services/jobs/` (new module), `tests/test_durable_jobs.py` (new).
- **Acceptance Criteria:** A kill/restart of the FastAPI server during an active Nmap or Greenbone scan leaves the job recoverable on boot; cancellation terminates OS subprocesses durably; 100% test pass rate.
- **Risks:** Concurrency race conditions between worker polling loops; deadlocks on job status updates.

### Phase 3: SQL Server 2022 Express Integration (Task 03)
- **Priority:** P2.
- **Description:** Implement dialet-agnostic SQLAlchemy engine configuration supporting SQL Server 2022 Express via `pyodbc` / `mssql+aioodbc`. Adapt JSON columns (`JSON` vs `NVARCHAR(MAX)` with JSON check constraints), UUID columns, and timezone-aware DateTime types. Rewrite Alembic migrations to support standard SQL Server DDL instead of SQLite `batch_alter_table`. Provide an audited data migration script transferring all users, investigations, authorizations, findings, and scores from SQLite to SQL Server.
- **Dependencies:** Task 02 completion.
- **Affected Files:** `app/database.py`, `app/config.py`, `app/models/*.py`, `migrations/env.py`, `migrations/versions/*.py`, `scripts/migrate_sqlite_to_sqlserver.py` (new).
- **Acceptance Criteria:** Full test suite passes against a disposable SQL Server 2022 Express instance; all foreign keys, indexes, and constraints verified; data migration script validates record parity and SHA-256 integrity.
- **Risks:** Dialect-specific type differences (e.g., Boolean vs BIT, JSON serialization); transaction deadlocks on concurrent writes.

### Phase 4: SeaweedFS Evidence Storage Integration (Task 04)
- **Priority:** P2.
- **Description:** Implement a provider-neutral `StorageAdapter` interface (`store_object`, `get_object`, `delete_object`, `get_metadata`). Implement a `SeaweedFSStorageAdapter` using S3-compatible API or Filer REST API. Update `EvidenceStore` to use the adapter with fallback to local filesystem for development. Provide an audited migration script transferring all 29 existing forensic files from `./evidence_storage/` to SeaweedFS buckets, validating SHA-256 hashes and updating database URIs.
- **Dependencies:** Task 03 completion.
- **Affected Files:** `app/services/storage/` (new abstraction), `app/services/evidence_store.py`, `app/config.py`, `scripts/migrate_evidence_to_seaweedfs.py` (new), `tests/test_seaweedfs_storage.py` (new).
- **Acceptance Criteria:** Evidence files successfully stored, retrieved, and verified with SHA-256 against SeaweedFS; zero local disk leakage during tests.
- **Risks:** Network latency on large scan reports; orphaned object storage files if database commits fail.

---

## H. Recommended Next Step

### Exactly One Next Action:
**Execute Task 01B (SQLite Preservation & Repository Hygiene Review)**:
1. Create a non-destructive cold backup of `footprintiq.db`, `footprintiq.db-wal`, and `footprintiq.db-shm` into `.data/backups/cold_preservation_20261102/`.
2. Prepare a Git hygiene plan to untrack `footprintiq.db-shm` and `footprintiq.db.backup*` via `git rm --cached` and add them to `.gitignore`.
3. Submit the Task 01 implementation and the Task 01B preservation plan to the user for formal approval before staging, committing, or starting Task 02.

---

## I. Verification Limitations

1. **Live Network Scanning Omitted:** In accordance with the strict audit rules (Section 10), no real Nmap network scans were launched against external targets or loopback. The Nmap unit and API test suites were verified using mocked subprocess outputs. The single skipped test (`test_real_localhost_nmap_scan_integration`) was intentionally left skipped.
2. **Greenbone GMP Service Omitted:** No live Greenbone OpenVAS daemon or Unix domain socket was connected. Greenbone XML parsing, orchestrator state handling, and error branches were evaluated using pre-recorded XML report fixtures (`openvas_sample.xml`).
3. **External Services (SQL Server & SeaweedFS) Offline:** SQL Server 2022 Express and SeaweedFS daemons were not connected, configured, or probed, as the required drivers and adapters do not yet exist in the codebase.
4. **SQLite PRAGMA Integrity Checks Omitted:** Direct execution of `PRAGMA integrity_check` or `PRAGMA wal_checkpoint` on `footprintiq.db` was intentionally withheld to eliminate any possibility of triggering write operations or altering the 3.66 MB WAL file prior to the completion of a cold backup.
