# Module 16 — Security, Testing and Deployment Audit

**Date:** 2026-11-02  
**Scope:** Authentication, authorization, API/file security, configuration, tests, Docker, and operations. Baseline: [Group 6 Baseline Report](GROUP_6_BASELINE_REPORT.md).

## Security results

- Authentication uses Argon2 password hashing, server-side sessions stored by token hash, expiry/revocation checks, login throttling/lockout, account approval, and password-change session revocation. CSRF checks use constant-time comparison for state-changing browser/API flows. Existing tests cover authentication, signup approval, password lifecycle, CSRF, RBAC, investigation ownership, and download access.
- Admin/Investigator authorization is enforced server-side by route dependencies and owner checks; middleware also protects operational pages and administrative paths. Cross-investigation access and role restrictions have regression tests.
- Evidence retrieval is owner checked, path-contained and SHA-256 checked. No generic client file-upload route was found; MIME/extension policy therefore does not apply to a general upload API. No stored internal path is exposed through the evidence API.
- `ALLOWED_HOSTS` existed but was unused. `TrustedHostMiddleware` now enforces it (with `testserver` allowed only for test settings). Staging/production now require a nonempty, non-wildcard host list, a >=32-character non-default signing secret with basic diversity checks, disabled debug, disabled demo provisioning, and Secure session cookies. `SameSite=None` with an explicitly insecure cookie is rejected. `cookie_secure` defaults true for both staging and production.
- Database rollback logs and the central unhandled-error log previously included exception text/tracebacks. They now log only exception type and request path/method; request-validation logging no longer records submitted validation payloads. Response errors remain sanitized and correlation IDs are retained.
- `.env.example` now has demo provisioning disabled, empty demo password placeholders, and no explicit insecure cookie setting. README demo credential values were removed. Historical Git revisions contain nonempty demo credential fields; no history rewrite or account password mutation was performed. The ignored local `.env` retains its existing demo credential entries, but provisioning is disabled there; the file and existing account passwords were preserved. Rotate any account still using an exposed credential and any reuse elsewhere.
- Content type, frame, referrer, and HSTS (production only) headers are set. CORS is not enabled/configured. There is no CSP policy. HTTPS termination must be provided by the deployment edge; HSTS is emitted only for production.

## Dependency and code security

- Direct dependencies are declared in `pyproject.toml` with lower-bound versions; no lockfile was found. `pip check` reports no broken installed requirements.
- `pip-audit`, Bandit, Safety, and Gitleaks are not installed in the environment. No dependency CVE scan or secret scanner result is claimed. No broad dependency upgrade was attempted.
- Source review covered subprocess use, SQLAlchemy parameterization, file path containment, evidence integrity, secret representation, and exception/log handling. The active scanner uses argument-list subprocess invocation and explicit authorization checks; full penetration testing was not performed.

## Testing

- Baseline before changes: **233 passed, 0 failed, 1 skipped, 20 warnings**.
- Post-change full suite: **239 passed, 0 failed, 1 skipped, 20 warnings** (after the final verification run). The optional live Nmap test is skipped. Warnings are Starlette/httpx deprecations and an existing SQLite test-transaction warning.
- Focused security/RBAC/storage suite: **36 passed** before the final logging regression was added.
- Isolated migration test: fresh upgrade → downgrade base → upgrade head; successful, final revision `0007_investigation_ownership`, SQLite integrity `ok`.
- Automated tests and mocks are not evidence of live Greenbone, SeaweedFS, or passive provider availability.

## Docker and deployment

- Dockerfile uses Python 3.11 slim, installs Nmap, creates/runs as a non-root `footprintiq` user, exposes 8000, declares persistent `/var/lib/footprintiq`, and probes `/health/live`.
- The Docker CLI is installed, but Docker Engine is unavailable in this environment. `docker info` cannot connect; image build, container run, volume persistence, and non-root runtime were therefore **blocked**, not passed. No Compose file was found.
- Docker startup does not run Alembic migrations. Deployment must run `alembic upgrade head` as a separate controlled step before serving traffic, provide a strong `SECRET_KEY`, configure correct `ALLOWED_HOSTS`, persistent storage and HTTPS, and arrange database+evidence backup/restore. Container defaults use SQLite; PostgreSQL lacks a declared driver.
- Deployment is not production-ready until backup/restore is implemented and tested, dependency scanning is established, secrets are rotated where needed, real service dependencies are configured and verified, and Docker runtime is verified.

## Health, logging and monitoring

`/health/live` reports process liveness. `/health/ready` checks the database and returns 503 on a failed DB probe; the current local response was ready with the database connected. Startup currently logs a database probe warning rather than failing process startup. Structured request logs carry request IDs and avoid exception detail after this change. Audit and job records exist, but there is no metrics/alerting integration or external monitoring configuration. Health checks do not verify the evidence filesystem or optional scanners.

## Defects and fixes

| ID | Severity | Finding and fix | Evidence |
| --- | --- | --- | --- |
| G6-16-01 | P1 | `ALLOWED_HOSTS` was not enforced. Added TrustedHostMiddleware and tests for accepted/rejected hosts. | Host regression tests pass. |
| G6-16-02 | P1 | Staging defaulted to insecure cookies and permitted debug/demo provisioning. Secure cookie defaults and staging/production validation added. | New settings tests; full suite passes. |
| G6-16-03 | P1 | Database/application exception logs could contain error detail, and validation logging included submitted input. Sanitized to type/path/method only. | Regression asserts a sentinel secret is absent from logs; full suite passes. |
| G6-16-04 | P1 residual | Demo credential values were present in README/example configuration and historical Git revisions. Current README/example values were removed; historical account credentials were not rotated to preserve accounts. | Current tracked text scan and revision inspection; rotate if reused. |
| G6-16-05 | P2 | User model metadata did not describe named unique constraints in Alembic history. Added matching model metadata. | Fresh migration cycle; only SQLite FK comparison limitation remains in `alembic check`. |
| G6-16-06 | P1 operational | Invalid local `.env` boolean prevented startup without override. Local `DEBUG` set to false and demo provisioning disabled; existing DB accounts/data were not altered. | Local app restart and health probes. |

## Remaining limitations

No live Docker build/run, dependency CVE scan, Git history scrub, credential rotation, PostgreSQL verification, live scanner/provider tests, CSP/CORS policy, combined backup restore, metrics/alerting, upload limits, or full controlled end-to-end active-scan/report-retrieval scenario was completed. The suite’s one skip and these infrastructure gaps should be treated as blocked or not tested, never as a pass.
