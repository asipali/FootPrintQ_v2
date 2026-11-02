# Group 6 Baseline Audit

**Scope:** Module 15 (database, storage and integrations) and Module 16 (security, testing and deployment).  
**Baseline captured:** 2026-11-02, before Group 6 source changes.

## Repository and safety state

The working tree already contained substantial uncommitted work from Groups 1–5, including application code, tests, docs, evidence files, and a SQLite shared-memory file. Those changes and all user data are preserved. No database reset, evidence deletion, restore-over-live, commit, push, or deployment was performed.

## Baseline verification

- Full automated suite: **233 passed, 0 failed, 1 skipped, 20 warnings** (`pytest -q`).
- The optional Nmap live test was skipped; the rest of this is not a claim of real external-provider verification.
- The existing localhost server was running at `http://127.0.0.1:8000` (PID 29764) with process-only `DEBUG=false` and demo provisioning disabled.
- The repository `.env` has invalid `DEBUG=release`; importing settings without an override fails Pydantic boolean validation. This prevents a clean default local startup until corrected in the local environment. No `.env` values are reproduced here.
- The database is SQLite via SQLAlchemy. Alembic revisions are ordered through `0007_investigation_ownership`; the live DB had previously been verified at head with no FK violations. Fresh schema/migration checks will use an isolated temporary database.
- Evidence is stored on the local filesystem with database metadata and SHA-256 verification. No SeaweedFS adapter/configuration or report artifact persistence was found.
- `footprintiq.db.backup` and prior backup mentions exist, but no supported automated backup/restore workflow was found. A database-only file is not proof of recoverability of database plus evidence.
- Existing security tests cover auth, CSRF and RBAC. Source inspection identified unused `ALLOWED_HOSTS`, staging cookie defaults that are not Secure, raw exception text in session error logs, and a checked-in `.env.example` with demo provisioning enabled and concrete demo password entries. Values were intentionally not printed.
- Dockerfile specifies a non-root runtime, Nmap, a persistent `/var/lib/footprintiq` volume and a liveness healthcheck. Docker CLI exists, but the Docker Engine is unavailable (`docker info` cannot connect), so image build/container verification is blocked at baseline.

## Baseline risk summary

Confirmed concerns for remediation or explicit limitation reporting: insecure staging cookie defaults, host allowlist not enforced, sensitive exception text in DB/application logs, credential-shaped examples in tracked configuration, SQLite-only runtime packaging (no PostgreSQL driver found), no automated combined DB/evidence backup restore, and unavailable Docker Engine. Subsequent Group 6 changes and tests are recorded in the module reports and final report.
