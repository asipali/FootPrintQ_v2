# FootprintIQ Complete Application Audit

**Audit date:** 2026-11-02 (Asia/Calcutta)  
**Repository:** `D:\Desktop\HackShift\footprint`  
**Scope:** Source and configuration review, existing SQLite schema/migration inspection, automated suite, and read-only local HTTP verification. No application source, dependencies or configuration were modified. The automated suite wrote synthetic test evidence into the configured repository `evidence_storage/` directory (259 files total after the run); this side effect was discovered after execution. No existing database rows were intentionally changed. Two audit documents were added.

## 1. Executive summary

FootprintIQ is a Python 3.11+ FastAPI application with server-rendered Jinja2/HTMX pages, SQLAlchemy persistence, six Alembic revisions, investigator authentication, role checks, passive OSINT collectors, evidence storage, Nmap and Greenbone workflows, and PDF/GraphML exports. The SQLite database was already at Alembic head `0006_account_approval` and contains the tables expected by the models.

The full automated suite passed: **209 passed, 0 failed, 10 warnings** (`python -m pytest -q`, with process-only `DEBUG=false` to work around the local `.env` parsing defect). Live read-only checks returned 200 for the public pages, static CSS and health endpoints, and 401 for unauthenticated `/api/v1/investigations`. The service is running at **http://127.0.0.1:8000**.

This is not release-ready. The checked-in runtime configuration file `.env` contains `DEBUG=release`, which is invalid for the boolean setting and prevents an ordinary import/startup. Nmap is not installed/discoverable, Greenbone has no configured endpoint, and theHarvester is not configured; therefore those live integrations are not verified. Code review also found a broken Nmap XML download call (`retrieve_evidence_bytes` does not exist), no investigation creator/ownership field or per-investigation access isolation, and state-changing user/authorization API handlers without the CSRF dependency used elsewhere. These are the highest-value next fixes.

The test suite is strong for isolated application logic and simulated integrations, but uses temporary test databases and mocked collectors/scanners. It does not prove the configured production-like database workflows, real provider connectivity, real scan execution, browser theme persistence, responsive layout, or all live API authorization combinations. No production readiness claim is made.

## 2. Architecture and component inventory

| Layer | Components and evidence | Audit notes |
|---|---|---|
| Runtime | `app/main.py:create_app`, lifespan and middleware; `app/config.py:Settings`; `app/database.py`; `app/logging_config.py` | FastAPI; correlation/request timing; startup DB probe; exception handlers; static mount; public and protected pages. |
| Authentication/security | `app/core/auth.py`, `app/core/security.py`, `app/api/deps.py`; `app/api/auth.py`, `users.py`, `audit.py` | Argon2 password hashing, server-side hashed session identifiers, role/permission dependencies, CSRF dependency, account lockout, audit events. |
| REST API | `app/api/{health,auth,users,audit,investigations,recon,authorizations,nmap_scans,vulnerability}.py` | API v1 routes are registered; full list is summarized in section 6 and the feature matrix. |
| HTML application | `app/api/web_dashboard.py`; `app/templates/*.html`; `app/static/css/main.css`, `static/js/theme.js`, `htmx.min.js` | Public informational pages, login/signup, workspace, investigation pages, findings/scans/evidence, admin and settings. HTMX is vendored. |
| Domain/data services | `app/services/passive/orchestrator.py`, `normalizer.py`, `target_authorization.py`, `evidence_store.py`, `active/*`, `vuln/*`, `reporting/*`, `scoring/*` | Passive collection, target controls, local evidence, subprocess scan execution, XML parsing, risk scoring, PDF and GraphML. |
| External integrations | `app/services/collectors/{dns_collector,rdap,whois_client,crtsh,theharvester,search_collector}.py`; `app/integrations/greenbone_{client,adapter}.py` | RDAP/WHOIS/DNS/CT have code; public search is explicitly NOT_CONFIGURED; scanner/provider connectivity unavailable or unverified here. |
| Models | `app/models/{user,audit,investigation,recon,scan,vulnerability}.py` | 14 database tables: `users`, `user_sessions`, `audit_logs`, `investigations`, `target_authorizations`, `collection_jobs`, `evidence`, `entities`, `active_scan_jobs`, `scan_hosts`, `scan_ports`, `vuln_scan_jobs`, `vuln_findings`, plus `alembic_version`. |
| Schemas | `app/schemas/{auth,health,investigation,recon,scan,vulnerability}.py` | Pydantic request/response validation. |
| Migrations | `migrations/env.py`; `migrations/versions/0001` through `0006` | Existing DB reports `0006_account_approval (head)` via `python -m alembic current`. No migration was applied. |
| Tests | `tests/` (31 test modules plus fixtures) | 209 tests pass. Many external behaviors are mocked; see section 7. |
| Operations | `pyproject.toml`, `README.md`, `Dockerfile`, `.dockerignore`, `.gitignore`, `scripts/`, `docs/` | Dockerfile uses Python 3.11 slim, installs Nmap, runs as non-root, expects a production secret through environment; Docker build not run. README startup commands include migration/provisioning and were not run against live data. |

### Database and relationships

SQLite was confirmed by the configured engine. Tables and migration state were inspected read-only. Foreign keys connect session to user, approval actors back to users, investigation data to investigations, scan ports to hosts/jobs, and findings to vulnerability jobs/evidence. JSON columns hold investigation scope, team members, authorization operations, collector metadata and normalized evidence provenance. Several models use indexes on identifiers, statuses and query fields. No declared relationship or creator FK ties investigations to their creator; evidence/entity linkage to evidence IDs is JSON rather than a relational join. SQLite is the configured local store; raw evidence is stored on the local filesystem under the configured evidence directory. Backup/restore automation is not present in the reviewed operational files.

## 3. Feature implementation inventory

Status meanings follow the requested definitions. Functional outcomes are distinct from implementation status.

| Feature | Implementation status | Functional status | Evidence and missing components | Priority |
|---|---|---|---|---|
| Public pages, signup/login UI, theme | Implemented | Partial | `web_dashboard.py`, Jinja templates and `theme.js`; public pages/CSS returned HTTP 200. Visual responsiveness and theme persistence not browser-tested. | P2 |
| Authentication, sessions, password changes | Implemented | Partial | `core/auth.py`, `core/security.py`, auth API; unit coverage in `test_auth.py`, `test_csrf_and_cookies.py`, `test_account_management.py`. Live credential workflow not run to avoid DB mutation. | P1 |
| Approval workflow and roles | Implemented | Partial | `api/users.py`, admin pages, account transition logic; tests cover approvals and RBAC. Direct live role/API matrix not executed. | P1 |
| Investigation CRUD/workspace | Partially Implemented | Partial | Create/list/get and UI workflows exist. No update/delete API evident; no creator/ownership field. Restart persistence was not tested. | P1 |
| Target authorization | Implemented | Partial | `services/target_authorization.py`, API and UI records; active workflows revalidate authorization. Mutation endpoint CSRF gap and live scanning authorization scenario not exercised. | P1 |
| DNS, RDAP/WHOIS, crt.sh passive collection | Implemented | Partial | Collectors and orchestrator; tests use mocks for orchestration. No real external provider run during audit. | P2 |
| theHarvester | Partially Implemented | Blocked | subprocess collector exists; no configured binary found in settings. Live execution unavailable. | P2 |
| Public search | Placeholder / Mock | Not Tested | `search_collector.py` returns `NOT_CONFIGURED`; provider integration is explicitly a stub. | P2 |
| Evidence storage and hash verification | Implemented | Partial | `EvidenceStore.store_evidence/read_evidence`; tests cover write/read/hash/path traversal. Existing evidence content and all live retrievals were not read. | P1 |
| Nmap detection, profiles, runner, XML parsing | Implemented | Blocked | Detector/runner/parser and tests exist; Nmap binary not found/configured. No localhost scan performed. Nmap XML download endpoint calls nonexistent `retrieve_evidence_bytes`. | P1 |
| Greenbone/GVM vulnerability scans | Implemented | Blocked | client/adapter/orchestrator/XML parser and mocked tests; no GVM endpoint/socket configured. No real connection or scan. | P1 |
| PDF report | Implemented | Partial | ReportLab generator, web/API routes and tests verify PDF signature/content disposition. Tests do not parse rendered pages; no live report generated from existing records. | P2 |
| GraphML export | Implemented | Partial | exporter and endpoint; tests cover export. No live export from existing records. | P2 |
| Risk scoring | Implemented | Not Tested | `services/scoring/calculator.py`; included in report generation, but no focused live validation in this audit. | P3 |
| Admin/security audit log | Implemented | Partial | audit model, API/UI and event logging; tests cover generation/redaction. Live audit records not inspected for privacy. | P2 |
| Database migrations and persistence | Implemented | Partial | Six migrations, database tests, current DB at head. DB connectivity passed; no writes/restart persistence test against existing DB. | P1 |
| Docker deployment | Partially Implemented | Not Tested | Dockerfile and healthcheck exist; Docker build/container startup not attempted. No Compose file found. | P2 |

## 4. Functional verification results

### Startup and public website

- Initial normal import/test discovery failed because `.env` sets `DEBUG=release`; Pydantic reports `DEBUG Input should be a valid boolean` (`app/config.py`, `tests/conftest.py` import path). No configuration file was changed.
- Starting with process-only `DEBUG=false` and `DEMO_ACCOUNTS_ENABLED=false` succeeded. The latter prevents documented startup provisioning from writing demo accounts to the existing database. Logs confirmed startup and SQLite connectivity.
- `python -m alembic current`: `0006_account_approval (head)`.
- HTTP: `/`, `/features`, `/how-it-works`, `/use-cases`, `/security`, `/about`, `/faq`, `/login`, `/signup`, `/register`, `/health/live`, `/health/ready`, `/api/v1/health`, and `/static/css/main.css` all returned 200. `/api/v1/investigations` returned 401 without credentials. The browser-facing protected `/dashboard` redirects to login (HTTP client followed redirect and ended at login with 200).
- HTML/CSS delivery is confirmed. Responsive behavior, actual browser rendering, light/dark toggling and localStorage persistence were not verified.
- App exposes `/docs`, `/redoc`, and `/openapi.json` in development; this is intentional per `create_app` environment check, but should be disabled in production (code does so).

### Authentication, authorization and investigation data

Automated tests cover password hashing, login/logout, session expiration/revocation, lockout, pending approval, admin actions, RBAC and CSRF paths (`test_auth.py`, `test_account_management.py`, `test_rbac.py`, `test_csrf_and_cookies.py`, `test_admin_provisioning.py`). Because the configured `.env` has demo provisioning enabled and the existing users are real local data, live login, registration, approval, password changes and role mutation were not run. Live unauthenticated API rejection passed. No test was run against every role on the running database.

Investigation queries generally require `investigation.view` permission, but there is no owner/tenant column in `InvestigationModel` and list/get flows do not filter to a creator. This is a shared-workspace policy in effect; if investigations are intended to be private per investigator, this is a data-isolation gap. The app does not expose evident update/delete REST operations for investigations.

### Reconnaissance, scans, evidence and reports

- Passive collector/orchestrator tests validate normalized and deduplicated data using controlled mocked results and simulated failures. They establish orchestration behavior, not real DNS/RDAP/crt.sh availability or real external result quality.
- Nmap: source and unit tests cover discovery, profile validation, execution/parser behavior. `NMAP_BIN` is not configured and no `nmap` executable was found. No real scan was run, including localhost; actual integration is environment-blocked.
- Greenbone: GVM host/socket and credentials are not configured. Client/parser and API tests use mocks/fixtures. Connection, authentication, profile discovery, task lifecycle and real report retrieval are blocked/unverified.
- Evidence storage tests verify local write/read SHA-256 and traversal rejection. No file upload endpoint was found; evidence is ingested by collector/scanner workflows and stored locally. The suite unexpectedly wrote 259 synthetic evidence files into the configured `evidence_storage/` path, so test isolation is incomplete. No live user-facing evidence access-control matrix was run.
- PDF tests assert valid PDF magic/EOF, size and download response; they do not render pages or extract text. Existing-data report accuracy was not checked. GraphML has unit coverage.

## 5. Security findings

| ID | Severity | Finding and evidence | Impact | Recommended remediation |
|---|---|---|---|---|
| S-01 | HIGH | Local `.env` has malformed `DEBUG=release`; application config declares `DEBUG: bool` (`config.py`) and settings import fails before app startup. | Normal local startup/test discovery fails unless environment override is supplied; risks confusing environment setup and emergency recovery. | Correct local config to `true`/`false`; add a safe startup/config validation check and document it. Keep debug false for production. |
| S-02 | HIGH | Investigation records have no creator/tenant field; `investigations.py` lists all rows for any role with `investigation.view` and individual retrieval similarly lacks owner filter. | Any permitted investigator can access other investigators' investigations and associated findings/evidence if private isolation is expected. | Decide shared-vs-private policy explicitly; if private, add ownership/tenant model, migration, query scoping and cross-user denial tests. |
| S-03 | MEDIUM | State-changing user endpoints `POST /api/v1/users`, `PATCH .../role`, and `PATCH .../status`, plus target authorization create/revoke endpoints, do not depend on `verify_csrf_token` (unlike approval/rejection and password endpoints). | Cookie-authenticated browser requests have inconsistent CSRF enforcement; risk depends on browser content-type/CORS constraints and deployment. | Require CSRF on every mutation that accepts ambient cookie authentication, or require bearer-only auth for API mutation; add regression tests for cookie vs bearer calls. |
| S-04 | MEDIUM | `GET /api/v1/nmap-scans/{job_id}/xml` calls `EvidenceStore.retrieve_evidence_bytes`; the class only implements `read_evidence` (`evidence_store.py:82`). | Downloading raw Nmap XML raises `AttributeError` and returns 500 once a scan has evidence. | Use the implemented retrieval method and verify the stored hash against metadata; add endpoint test with persisted evidence. |
| S-05 | MEDIUM | The runtime `.env` enables `DEMO_ACCOUNTS_ENABLED`; startup calls `provision_demo_accounts` if true (`main.py` lifespan). | Starting the server can create demo users in the existing database; demo identities/passwords are documented public defaults. | Keep provisioning off outside disposable local demos; disable for this audit server process. Replace/disable any demo credentials before shared exposure. |
| S-06 | LOW | PDF and raw-evidence route exception branches include exception text in HTTP details (`web_dashboard.py`, `recon.py`). | Some filesystem/library exception strings may reveal internal paths or implementation details. | Return a generic client error with request ID and retain detailed diagnostics only in protected logs. |
| S-07 | INFO | The development OpenAPI/Swagger docs are exposed when `APP_ENV` is not production; `create_app` disables them in production. | Route/schema metadata is visible in non-production deployments. | Ensure production `APP_ENV` is set correctly; optionally restrict docs in staging/shared demos. |
| S-08 | MEDIUM | Automated tests use the configured repository evidence directory; running `pytest` created 259 untracked synthetic files under `evidence_storage/` (for example `inv-e2e-recon`, `inv-scan-*`, `inv-vuln-*`). | Audit/test execution dirties the working tree and mixes synthetic artifacts with persistent evidence. | Inject a temporary evidence-store path in fixtures; add cleanup confined to that temporary directory; verify the repository evidence directory is untouched. |\n| S-09 | INFO | Existing test run emitted 10 warnings: Starlette/httpx TestClient deprecation, deprecated 422 constant, and SQLAlchemy transaction deassociation. | No current test failures, but dependency evolution may break the suite or make transaction behavior harder to diagnose. | Upgrade TestClient compatibility, use current status constant and review fixture rollback warning. |

No actual credential/key values were printed or included in this report. No external targets were scanned. `ALLOWED_HOSTS`, CORS configuration and production deployment settings require environment-specific verification; no production environment was available. No dependency vulnerability scanner (`pip-audit`/equivalent) was available/run, so dependency vulnerability status is unverified.

## 6. API inventory and verification

All registered REST paths appear in `/openapi.json` (40 paths). OpenAPI does not declare an HTTP bearer security scheme, so its `security` metadata is empty for all listed operations; source dependencies enforce authentication/roles on operational handlers. This is a documentation gap, not evidence that endpoints are public. The live request to `/api/v1/investigations` returned 401.

| Method and path | Purpose | Access/control from source | Verification |
|---|---|---|---|
| `GET /health/live`, `/health/ready`, `/api/v1/health` | Liveness/readiness/metadata | Public | All live 200; readiness DB connected. |
| `POST /api/v1/auth/login`, `/signup` | Login/registration | Public; signup policy/password validation | Tests; live form pages only. |
| `POST /api/v1/auth/logout`, `/password`; `GET /api/v1/auth/me` | Session/profile/password | Auth; logout/password CSRF dependency | Tests; live workflow not run. |
| `GET /api/v1/users`, `/pending-investigators`, `/{user_id}` | User/admin reads | Administrator role | Role tests; not live-auth tested. |
| `POST /api/v1/users`, `/{user_id}/approve`, `/{user_id}/reject`; `PATCH /api/v1/users/{user_id}/role`, `/{user_id}/status` | User management | Admin; CSRF present on approve/reject only | Unit tests; create/role/status CSRF gap noted. |
| `GET /api/v1/audit-logs` | Audit log query | Administrator role | Unit coverage; not live-auth tested. |
| `GET /api/v1/investigations`, `/{investigation_id}` | List/detail | `investigation.view`; lacks owner scoping | Unauthenticated live 401; tests. |
| `POST /api/v1/investigations` | Create | `investigation.create` | Unit tests; no live write. |
| `GET /api/v1/investigations/{id}/export/graphml` | GraphML export | `investigation.view` | Export tests. |
| `POST/GET /api/v1/investigations/{id}/passive-recon` | Start/list recon | Permissioned | Mock collector/orchestrator tests; no real provider test. |
| `POST /api/v1/investigations/{id}/validate-target` | Scope check | `investigation.view` | Unit tests; no live target check. |
| `GET /api/v1/investigations/{id}/entities`, `/evidence`, `/evidence/{evidence_id}/raw` | Findings/evidence | `investigation.view`; investigation association checked | Store/path tests; no live existing-data retrieval. |
| `POST/GET /api/v1/investigations/{id}/authorizations`, `DELETE .../{authorization_id}` | Scope records | `scope.manage` to mutate; `investigation.view` read | Unit tests; mutation CSRF dependency absent. |
| `GET /api/v1/tools/nmap/status`, `/api/v1/nmap/profiles` | Tool status/profiles | Authenticated | Unit tests; runtime binary absent. |
| `POST/GET /api/v1/investigations/{id}/nmap-scans` | Dispatch/list scan | `recon.active`/`investigation.view`; target authorization | Mock tests; no live scan. |
| `GET /api/v1/nmap-scans/{job_id}`, `/results`, `/xml`; `POST .../{job_id}/cancel` | Scan status/results/cancel/XML | Permissioned | Tests cover jobs/results; XML download defect S-04. |
| `GET /api/v1/tools/greenbone/status`, `/api/v1/vulnerability-profiles` | GVM status/profiles | Authenticated | Mock tests; GVM unavailable. |
| `POST/GET /api/v1/investigations/{id}/vulnerability-assessments` | Start/list assessment | `vulnerability.scan`/auth | Unit and simulated tests; real service blocked. |
| `GET /api/v1/vulnerability-assessments/{job_id}`, `/findings`, `/report`; `POST .../{job_id}/cancel` | Job/findings/report/cancel | Permissioned | Unit tests; real service blocked. |

The browser pages and form routes are in `app/api/web_dashboard.py` and are excluded from OpenAPI: `/`, six public information pages, `/login`, `/signup`, `/register`, `/dashboard`, `/admin/dashboard`, `/investigations` and detail/create, target authorization, passive recon, Nmap and vulnerability workflows, PDF/GraphML download, `/settings`, approval/rejection, `/findings`, `/scans`, `/evidence`, `/audit`, `/admin/authorizations`, and `/admin/tools`. Public page live checks passed; protected forms and mutations were not exercised against existing data.

## 7. Automated tests and code quality

- Command: `python -m pytest -q` with process-only `$env:DEBUG='false'`.
- Result: **209 passed, 0 failed, 10 warnings in 30.92s**.
- Without the override, pytest collection failed during `tests/conftest.py` import due to invalid `DEBUG=release` in `.env`.
- Test modules cover auth, RBAC, CSRF/cookies, approvals, migrations, DB models, collectors/orchestration, target authorization, Nmap, GVM, vulnerability API/parser, evidence, dashboard, PDF and GraphML.
- Mocked tests establish local logic and parsers; external integration test claims are not inferred from mocks.
- No lint/type-check command was configured or run. No dependency audit tool was run. Docker build was not run.

## 8. Deployment and operational readiness

The README documents editable install, Alembic upgrade, demo provisioning and Uvicorn. Migration/provision commands were deliberately not run because the existing DB and user data must remain unchanged. Runtime startup was run with process overrides (`DEBUG=false`, `DEMO_ACCOUNTS_ENABLED=false`) and bound to loopback only. Dockerfile has a non-root runtime user, Nmap package, persistent `/var/lib/footprintiq` volume and liveness check. No Compose file is present. Production deployment still depends on a secure secret, correct environment values, persistent DB/evidence backups, a configured external GVM service if vulnerability scanning is required, and operational monitoring/backup procedures not demonstrated here.

## 9. Prioritized roadmap

Effort scale: S <1 day, M 1–3 days, L >3 days. All changes below are recommendations; none were implemented in this audit.

| Priority | Problem / category | Proposed work and dependencies | Acceptance criteria | Effort |
|---|---|---|---|---|
| P0 | Fixes: startup config parser failure (S-01) | Correct `.env` boolean and validate all local environment values; no schema dependency. | Clean start and pytest collection work without shell overrides; production remains debug-off. | S |
| P1 | Bug: Nmap XML download runtime error (S-04) | Align endpoint with `EvidenceStore.read_evidence`; verify hash and add response test. | Authenticated download returns correct bytes/hash; missing/corrupt evidence has safe status. | S |
| P1 | Security/data isolation: no investigation ownership (S-02) | Decide shared access policy; if tenant-private, add creator/tenant column and migration, enforce filters across scans/evidence/reports. | Cross-investigator access is denied where policy requires; admin/shared behavior explicit; migration tested. | M-L |
| P1 | Security: inconsistent CSRF on mutations (S-03) | Apply CSRF or bearer-only policy to all user and authorization writes. | Cookie mutation without valid CSRF rejected; bearer clients continue to work; tests cover each route. | S-M |
| P1 | Operational: demo provision enabled and public demo credentials (S-05) | Disable outside disposable demo; review local DB accounts and rotation policy. | Default shared/runtime config cannot provision public demo accounts; docs align with policy. | S |
| P1 | Operational: missing scanner integrations | Install/configure only on authorized lab host; establish GVM credentials/certs; run localhost Nmap and controlled GVM test after authorization. | Status endpoint reports usable binary/service; scan lifecycle and result persistence demonstrated on authorized lab. | M-L |
| P2 | Tests: live collector and report gaps | Add opt-in, network-authorized contract tests; render/extract PDF text and verify report sections; include evidence endpoint hash. | Test reports distinguish mocked and real; reproducible results and no public target scans. | M |
| P2 | Documentation/API schema | Add OpenAPI bearer security scheme and endpoint permission descriptions; clarify investigation sharing semantics. | OpenAPI describes auth and role permissions; docs match observed routes/config. | S-M |
| P2 | Deployment/operations | Add backup/restore runbook, migration preflight, structured log retention and readiness checks; validate container build. | Restore tested from backup; container health/volume behavior verified; deployment variables enumerated. | M |
| P3 | UX/quality | Browser-check responsive layouts and light/dark persistence; address deprecation warnings. | Browser verification across viewport/theme; suite warnings reduced without behavior regression. | S-M |

## 10. Readiness assessment

**Current assessment: functional development/demo foundation, not production-ready.** The main app starts with a temporary environment override, database readiness passes, public site and health checks pass, and 209 automated tests pass. The unconfigured scanner integrations are blocked; Nmap evidence download is broken; CSRF consistency and investigation isolation need decisions/remediation; local config must be corrected for reliable startup. This assessment is limited to the checked-out repository and local environment on 2026-11-02.

## 11. Command and test record

1. Read pasted audit instructions, repository tree, `pyproject.toml`, README and app source; `git status --short` was clean before documentation creation.
2. `python -m pytest --collect-only -q` without environment override: blocked at collection by `.env` `DEBUG=release` boolean validation error.
3. `python -m pytest -q` with process-only `DEBUG=false`: 209 passed, 10 warnings, 30.92s.
4. `python -m alembic current` with process-only `DEBUG=false`: `0006_account_approval (head)`; read-only.
5. Introspected SQLAlchemy table names; 14 application tables plus Alembic version table.
6. Started `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000` with process-only `DEBUG=false` and `DEMO_ACCOUNTS_ENABLED=false`; startup DB probe succeeded.
7. Read-only local HTTP checks against public routes, health, CSS, protected dashboard redirect, unauthenticated investigations API, and OpenAPI. No user-facing state mutations or scans performed.
8. Inspected `nmap` command availability; not found. Inspected sanitized configuration flags: GVM and theHarvester endpoints/binaries not configured.
9. No migrations, account provisioning, intentional database record writes, source modifications, dependency installation, Docker build, or external-target scans were performed. However, the automated suite wrote 259 synthetic files under the configured evidence directory; this side effect is recorded as S-08. The tracked SQLite shared-memory sidecar `footprintiq.db-shm` also appears modified after application access.


