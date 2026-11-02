# FootprintIQ Task 01 — Security Hardening and Test Isolation

**Date:** 2026-11-02 (Asia/Calcutta)  
**Branch:** `migration/python-only`  
**Baseline commit:** `f484b09 fix modules`  
**Scope:** CSRF hardening, pytest database/evidence isolation, focused security regressions. No dependency, environment, scanner-service, database migration, or storage-backend change was made.

## 1. Executive summary

Added CSRF checks to REST mutation routes that also accept ambient session cookies, and tightened the Bearer exemption so an arbitrary `Authorization` header is not enough to bypass CSRF. Existing cookie-based HTML flows continue to use their form-token validation, while verified Bearer clients remain exempt.

Pytest now directs implicit evidence-store construction to a per-test temporary evidence root. The application startup database probe is also directed to the isolated test engine. A regression confirms that an implicit store uses pytest’s temporary path, writes there, and does not write at the configured evidence root. Test-created files remain under pytest-managed temporary paths.

Final verification: **250 passed, 1 skipped, 20 warnings** (`python -m pytest -q`, with process-only `DEBUG=false` and `RUN_LOCALHOST_NMAP` unset), exit code 0. The skip is the opt-in real loopback Nmap integration test; no scan was launched.

**Data-handling exception:** Initial focused test runs occurred before the app startup database probe was isolated. Git subsequently showed the tracked `footprintiq.db-shm` sidecar modified. I did not restore, overwrite, or delete it. The main `footprintiq.db` was not shown as modified, and the final full suite confirmed `footprintiq.db-shm`’s hash was unchanged before versus after that run. The fixture was corrected so subsequent tests use the temporary test DB even for startup probes. The sidecar modification remains in the worktree and is disclosed below; no database restore/reset was attempted.

## 2. Baseline and implementation plan

The initial Git status was not clean because the prior audit report existed as an untracked `audit_output/` directory. Per user direction, that report was preserved and implementation proceeded with this known exception. Current branch and baseline commit were recorded before edits.

Source review found that HTML form mutations already call `_validate_csrf`, investigation and target-authorization REST mutations already use `verify_csrf_token`, but user provisioning/role/status, Nmap dispatch/cancel, Greenbone dispatch/cancel, and passive recon/target validation REST POST routes did not. The old CSRF dependency exempted any sufficiently long `Bearer` header without verifying it. Test fixtures used temporary SQLite but did not override global evidence storage; the app lifespan also probed the module-global DB engine.

Implementation plan followed:

1. Add consistent CSRF dependency coverage to authenticated REST state-changing routes.
2. Validate Bearer session tokens before granting the CSRF exemption.
3. Isolate per-test evidence storage and application startup DB probes.
4. Add regression coverage for CSRF, authorization, mutation prevention, and storage containment.
5. Run focused suites and the complete suite after isolation was verified; record exact outcomes.

## 3. Original issues and root causes

| Issue | Root cause | Resolution |
|---|---|---|
| CSRF protections differed across API mutations | `verify_csrf_token` was attached route-by-route; several authenticated mutation endpoints omitted it. | Added the dependency to user create/role/status, Nmap dispatch/cancel, Greenbone dispatch/cancel, passive recon dispatch and target validation. Existing investigation and target-authorization mutation protection remains. |
| Bearer exemption depended on header text | Any `Authorization: Bearer <long string>` passed the CSRF dependency without checking a server-side session. | Check the SHA-256 session key in `user_sessions`; exemption requires a valid, unrevoked, unexpired session and active, unlocked account. Invalid or unrecognized bearer values do not qualify. |
| Tests could write to persistent evidence storage | `EvidenceStore()` called global settings, while tests only isolated SQL. Some scanner/recon tests construct the store implicitly. | Autouse fixture patches the evidence-store settings provider per test, resets the default-store singleton, and gives each test a pytest temporary evidence root. |
| Test application startup could touch configured DB | `app.main.lifespan` used the process-global database probe, despite the test DB dependency override. | Test fixture routes app startup probes through the temporary `test_engine`; tests using a DB session probe that injected session. |

## 4. CSRF policy and route coverage

Policy: authenticated state-changing requests using the session cookie require the double-submit CSRF cookie plus matching `X-CSRF-Token` header or form token. Safe methods remain exempt. A Bearer request is exempt only when its token resolves to a valid application session. Authentication and role/permission checks remain in place and are not skipped by CSRF validation.

| Route category | Current policy after change |
|---|---|
| User administration: create, role, status | CSRF dependency added; administrator role remains required. Approve/reject already had CSRF. |
| Nmap dispatch and cancellation | CSRF dependency added; `recon.active`, investigation ownership, target scope and authorization checks remain. |
| Greenbone dispatch and cancellation | CSRF dependency added; `vulnerability.scan`, investigation ownership, target scope and authorization checks remain. |
| Passive recon dispatch and target validation POST | CSRF dependency added; relevant permissions and investigation access remain. Validation is read-only apart from audit logging, but uses POST and is protected consistently. |
| Investigation create/update | Existing CSRF dependency retained. |
| Target authorization create/update/revoke | Existing CSRF dependency retained. |
| Auth logout/password and account changes | Existing API CSRF dependencies retained. Web login/signup/logout continue their existing form-token validation. |
| Public JSON login/signup | Remain unauthenticated API operations that do not use ambient authenticated sessions; existing behavior is retained. Browser form login/signup still validate their CSRF forms. |
| GET/HEAD/OPTIONS/TRACE | CSRF helper does not block safe methods. |

## 5. Files changed

- `app/api/deps.py` — verified Bearer session before exemption.
- `app/api/users.py` — CSRF on user provisioning, role and status changes.
- `app/api/nmap_scans.py` — CSRF on scan dispatch and cancellation.
- `app/api/vulnerability.py` — CSRF on assessment dispatch and cancellation.
- `app/api/recon.py` — CSRF on passive dispatch and target validation POST.
- `tests/conftest.py` — per-test evidence root; startup database probe uses test engine; app fixture receives isolated settings.
- `tests/test_csrf_and_cookies.py` — safe GET regression.
- `tests/test_evidence_storage.py` — implicit-store isolation and tampered-content hash regressions.
- `tests/test_mutation_csrf.py` — new route-level CSRF, role, Bearer, dispatch/cancel, no-mutation and no-evidence-write regressions.
- `docs/FOOTPRINTIQ_TASK_01_SECURITY_HARDENING_REPORT.md` — this implementation report; prior reports preserved.
- `audit_output/2026-11-02-engineering-audit/FOOTPRINTIQ_ENGINEERING_AUDIT.md` — pre-existing untracked audit report preserved.
- `footprintiq.db-shm` — tracked SQLite shared-memory sidecar changed during initial tests before startup probe isolation was added. Preserved without restoration; see data-handling exception above.

No `.env`, source database, WAL file, evidence file, backup, or Docker service was intentionally changed. No dependencies were installed/upgraded. No migrations or scans were run.

## 6. Tests added or updated

- Cookie CSRF missing/invalid token requests for user create/role/status are rejected with 403 and do not change user records.
- Valid cookie CSRF token permits legitimate administrator user creation.
- Arbitrary Bearer text does not bypass CSRF/authentication; unauthenticated admin mutation returns 401 without creating a user.
- Authenticated non-admin role mutation remains denied.
- Nmap and Greenbone dispatch without CSRF return 403, create no scan jobs and write no evidence.
- Nmap and Greenbone cancellation without CSRF return 403 and leave running job states unchanged.
- Passive recon and target-validation POST without CSRF are rejected before any evidence write.
- Safe GET with cookie session remains accepted without CSRF; existing valid Bearer API tests continue to pass.
- Default `EvidenceStore()` uses the per-test temporary root rather than the configured persistent evidence root; evidence write/read/hash and traversal tests run in temp storage. Tampered bytes yield a computed hash different from the original digest.
- Test app lifespan DB probes use the temporary test engine. Final full-suite hash check showed the SQLite shared-memory sidecar did not change during that run.

## 7. Commands and actual results

All successful test commands used a process-only PowerShell override `$env:DEBUG = 'false'`; no `.env` file was edited. `RUN_LOCALHOST_NMAP` was unset for the complete suite.

| Command | Exit | Result |
|---|---:|---|
| `python -m pytest -q tests/test_csrf_and_cookies.py tests/test_mutation_csrf.py` (initial attempt without process override) | 1 | Pytest could not load `Settings`: process environment `DEBUG=release` was invalid. No tests collected. |
| `$env:DEBUG='false'; python -m pytest -q tests/test_csrf_and_cookies.py tests/test_mutation_csrf.py` | 0 | 13 passed, 1 warning. |
| `$env:DEBUG='false'; python -m pytest -q tests/test_auth.py tests/test_rbac.py tests/test_account_management.py` | 0 | 41 passed, 8 warnings. |
| `$env:DEBUG='false'; python -m pytest -q tests/test_evidence_storage.py` | 0 | 6 passed, 1 warning. |
| `$env:DEBUG='false'; python -m pytest -q tests/test_nmap_api.py tests/test_vulnerability_api.py tests/test_authorizations_api.py tests/test_target_authorization.py tests/test_passive_recon_orchestrator.py` | 0 | 32 passed, 1 warning. |
| First full run after adding evidence isolation, before startup DB probe fix: `python -m pytest -q` with `DEBUG=false`, live Nmap flag unset | 1 | 247 passed, 1 failed, 1 skipped, 20 warnings. `test_htmx_health_badge_component` failed because the test probe wrapper did not accept its `Session` argument. The wrapper was corrected. This run preceded the final test additions. |
| `$env:DEBUG='false'; python -m pytest -q tests/test_dashboard.py::test_htmx_health_badge_component` | 0 | 1 passed, 1 warning after probe-wrapper correction. |
| Final full run: `$env:DEBUG='false'; Remove-Item Env:RUN_LOCALHOST_NMAP -ErrorAction SilentlyContinue; python -m pytest -q` | 0 | **250 passed, 1 skipped, 20 warnings in 43.41s.** Warning set: Starlette/httpx TestClient deprecation, deprecated HTTP 422 constant, one SQLAlchemy transaction deassociation warning. |
| Final full-run sidecar guard: SHA-256 of `footprintiq.db-shm` before/after final pytest | 0 | `SHM_UNCHANGED=True`. |
| `git diff --check` | 0 | No whitespace errors. Git emitted line-ending normalization warnings (LF will be replaced with CRLF) for edited Python files. |

The skipped test is explicitly opt-in for real localhost Nmap (`RUN_LOCALHOST_NMAP=1`); it was not enabled. Scanner/provider API tests mock execution. No external or live scan was run.

## 8. Remaining risks and limitations

- The previously mentioned `footprintiq.db-shm` worktree change from initial tests remains. It was not restored due the prohibition on overwriting existing database files. No main DB or WAL modification is shown in `git status`; only this sidecar is shown. The final full run did not change the sidecar further.
- Login lockout and authorization-denial audit events may intentionally update audit/session-related state even when the requested business mutation is rejected; tests assert protected user/job/evidence state is not changed by failed CSRF checks.
- CSRF remains an explicit dependency for REST routes, so new mutation routes must include it. Future route additions should be covered by a route-policy audit or centralized safe enforcement.
- No CSP, MFA, durable job queue/recovery, combined DB/evidence backup, dependency lock/security scan, SQL Server driver, or SeaweedFS backend was added. These remain outside Task 01 scope.
- `DEBUG=release` can still cause test startup failure unless the process environment is corrected; local `.env` was not modified by this task.
- Suite warnings remain and should be addressed in a later maintenance task. The skipped real Nmap test was not run to avoid scanner execution.
- This work does not establish production readiness.

## 9. SQL Server 2022 Express compatibility assessment

SQL Server migration was not attempted. Current persistence is SQLite-centric. Before SQL Server use, a separate phase must select and approve a SQLAlchemy SQL Server driver, define URL/ODBC configuration and secret handling, validate SQLAlchemy type compilation for JSON/list and timezone-aware columns, review all constraints/indexes/defaults, rewrite and test SQLite batch-specific Alembic behavior, and run upgrade/downgrade/data-integrity tests against a disposable SQL Server 2022 Express instance. SQLite PRAGMAs, WAL assumptions, connection arguments, transaction behavior and concurrency settings must be isolated behind dialect-aware configuration. No `pyodbc`/ODBC installation or SQL Server connection was made.

## 10. SeaweedFS compatibility assessment

SeaweedFS migration was not attempted. Current call sites instantiate `EvidenceStore` directly or use its singleton, and SQL rows retain relative filesystem paths. A future phase should introduce an injectable storage interface with stable object keys, adapt passive/Nmap/GVM writers and raw-download readers, define content-hash/size metadata and streaming behavior, reconcile object writes with SQL commits/orphan cleanup, provide credentials/TLS/health checks/retention, and design a verified copy/backfill from local evidence without deleting originals. No SeaweedFS client, service, configuration or evidence copy was created.

## 11. Recommended Task 02

**Design and implement durable job execution and restart recovery.** Start with a decision record for worker/queue technology and job state transitions, then add persisted dispatch/retry/cancel semantics, stale-job recovery and concurrency control. Keep database and evidence-store abstractions injectable so the later SQL Server and SeaweedFS phases do not bind new worker code to SQLite or local paths. Verify with isolated failure/restart tests before deployment work.

## 12. Git summary and suggested commit

`git diff --check` passed. At report time, application/test source changes are listed in Section 5; the prior `audit_output/` report remains untracked and preserved. The tracked `footprintiq.db-shm` sidecar is also modified as disclosed. No push, merge, commit, migration or reset was performed.

**Suggested commit message:** `Harden CSRF checks and isolate test evidence storage`
