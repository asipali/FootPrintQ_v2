# FootprintIQ — Group 6 Final Audit Report

**Date:** 2026-11-02  
**Scope:** Group 6 Module 15 (database, storage and integrations) and Module 16 (security, testing and deployment). See the [baseline report](GROUP_6_BASELINE_REPORT.md), [Module 15 audit](MODULE_15_DATABASE_STORAGE_INTEGRATIONS_AUDIT.md), and [Module 16 audit](MODULE_16_SECURITY_TESTING_DEPLOYMENT_AUDIT.md).

## Executive summary

Core local application functionality remains operational. SQLite data integrity, current migration head, evidence integrity, authorization-focused tests, and the complete automated suite pass. Confirmed application security defects were corrected: host validation now runs, staging is secure by default, insecure staging/production configurations are rejected, and exception/validation logs no longer include raw error or submitted values. A committed demo credential was removed from current documentation/config examples; historical Git history and any already-provisioned account still need credential rotation where applicable.

The system is **not production-ready**. It has no tested combined backup/restore for SQLite plus evidence, no SeaweedFS integration, no durable job queue, no verified live Greenbone service, no dependency CVE scanner, and Docker Engine was unavailable for build/runtime verification. The existing database backup is readable but stale and omits evidence.

## Module results

### Module 15 — Database, Storage and Integrations

- Engine: SQLite. Live connection/readiness: PASS. Schema revision: `0007_investigation_ownership`.
- Integrity: `PRAGMA integrity_check=ok`, zero live FK violations. Fresh isolated Alembic upgrade/downgrade/re-upgrade passed. Alembic’s remaining FK diff is an SQLite comparison false positive; SQLite reports both self-referential `SET NULL` actions correctly.
- Storage: local filesystem. Five referenced evidence files passed presence/hash/size verification; four evidence rows have no raw-content path. SeaweedFS absent. Reports generated on demand and not persisted.
- Recovery: no supported combined backup/restore. Existing SQLite backup passes file integrity but is at an older schema revision and has one investigation/no evidence; no restore over the live database was performed.
- Integrations: prior authorized local Nmap scan verified in Module 08; Greenbone not configured; passive providers mocked only; theHarvester unavailable; no external scan/provider request made in this audit.

### Module 16 — Security, Testing and Deployment

- Auth, session, CSRF, account lifecycle, and RBAC implementation has broad regression coverage. Host allowlisting, secure staging/production settings, and sanitized logging fixes were added.
- Current `.env.example` has demo provisioning disabled and blank password placeholders. README no longer publishes demo passwords. Historical credential exposure remains a rotation concern; the ignored local `.env` retains prior credential entries with provisioning disabled, and no user account was modified.
- Dependency `pip check`: clean. Vulnerability/secret scanner tools unavailable, so CVE and secret scans are unverified.
- Dockerfile source review: non-root user, Nmap, persistent data volume, liveness check. Docker Engine unavailable; image build/container execution blocked.
- Readiness health check correctly verified local DB connectivity. No metrics/alerting; startup degrades to warning if DB unavailable. Deployment setup does not run migrations automatically.

## Regression results

- Baseline: **233 passed, 1 skipped, 20 warnings**.
- Final full suite: **239 passed, 0 failed, 1 skipped, 20 warnings**.
- Isolated migration cycle: PASS. `pip check`: PASS. Local `/health/live`: 200. Local `/health/ready`: ready/database connected.
- Tests include mocked integrations and local SQLite; the optional live Nmap test is skipped. No unauthorized scan was run.
- Not tested/blocked: Docker build/runtime, dependency CVE scan, real Greenbone/SeaweedFS/passive provider services, combined backup recovery, PostgreSQL, metrics/alerts, and a full live role-by-role end-to-end user workflow.

## Critical remaining work and recommendation

1. Rotate any account still using credentials that appeared in repository history; scrub history only through an explicitly planned repository maintenance because it is disruptive to collaborators.
2. Implement a versioned backup procedure covering DB and evidence together, with encryption/retention and an isolated restore drill.
3. Start Docker Engine and verify image build, startup, volume persistence, migration procedure, health, and non-root behavior.
4. Add a pinned dependency lock and run a maintained vulnerability scanner; review and remediate findings deliberately.
5. Configure/verify production hostnames, HTTPS termination, secret management, persistence, and monitoring before any deployment.

**Recommendation:** Suitable for controlled local demonstration after reviewing the login/account setup. Do not deploy to production until recovery and deployment blockers above are closed.

## Changes made

- Security/configuration: `app/config.py`, `app/main.py`, `app/database.py`, `.env`, `.env.example`, `README.md`.
- Schema metadata: `app/models/user.py`.
- Regression tests: `tests/test_error_handling_and_config.py`.
- Reports: Group 6 baseline, Module 15, Module 16, and this final report; Group 6 feature matrix rows updated.
- No migration file was added, and no existing database, user, investigation, job, evidence, or report record was changed by audit verification.
