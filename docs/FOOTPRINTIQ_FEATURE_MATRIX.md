# FootprintIQ Feature Matrix

**Last verified:** 2026-11-02. This concise index links the [complete audit](FOOTPRINTIQ_COMPLETE_APPLICATION_AUDIT.md) and the [Module 05 audit](MODULE_05_INVESTIGATION_AUDIT.md), [Module 06 audit](MODULE_06_AUTHORIZATION_AUDIT.md), and [integration report](MODULE_05_06_INTEGRATION_REPORT.md).

| Feature | Implementation status | Latest functional status | Evidence / verification |
|---|---|---|---|
| Public website and informational pages | Implemented | PASS | `app/api/web_dashboard.py`; `/`, `/features`, `/how-it-works`, `/use-cases`, `/security`, `/about`, `/faq` returned 200. |
| Login/signup pages and theme | Implemented | PARTIAL | Templates, `theme.js`; pages returned 200; actual visual/theme persistence not browser-tested. |
| Application configuration/startup | Implemented | FAIL (without override) / PASS (with process override) | `.env` has invalid `DEBUG=release`; `DEBUG=false` process override starts Uvicorn. |
| SQLite connectivity/readiness | Implemented | PASS | `/health/ready` 200; Alembic `0007_investigation_ownership (head)`. |
| Authentication/session/password lifecycle | Implemented | PARTIAL | `core/auth.py`, `core/security.py`; auth/account/CSRF test coverage; live credential mutation not run. |
| Investigator registration and admin approval | Implemented | PARTIAL | `api/auth.py`, `api/users.py`, admin UI; unit tests pass; no live account changes. |
| RBAC and role enforcement | Implemented | PARTIAL | `api/deps.py`, route dependencies; RBAC tests pass; live full-role API matrix not run. |
| Investigation management (Module 05) | Implemented | PASS WITH LEGACY LIMITATION | Owner-scoped create/list/detail/update/archive and exports; backup + migration 0007; 6 owners backfilled, 9 historical rows remain admin-only. See Module 05 audit. |
| Target authorization/scope (Module 06) | Implemented | PASS WITH OPERATIONAL LIMITATIONS | Explicit target/operation/time authorization, scope/type validation, CSRF, owner/RBAC checks, audit records; no active scans run. See Module 06 audit. |
| DNS passive collector (Module 07) | Implemented | READY WITH LIMITATIONS | A/AAAA/MX/NS/CNAME/TXT/SOA collector; mocked DNS success/NXDOMAIN tests; no external domain queried in this audit. See [Module 07 audit](MODULE_07_PASSIVE_RECON_AUDIT.md). |
| RDAP/WHOIS collector (Module 07) | Implemented | READY WITH LIMITATIONS | RDAP parser and WHOIS fallback covered by mocks; provider not live-tested. See [Module 07 audit](MODULE_07_PASSIVE_RECON_AUDIT.md). |
| crt.sh collector (Module 07) | Implemented | READY WITH LIMITATIONS | Certificate transparency parser/dedup tests pass; no authorized external domain query was run. |
| theHarvester (Module 07) | Partially Implemented | BLOCKED | Executable/provider configuration unavailable; missing-binary and mocked subprocess tests pass. |
| Public search provider (Module 07) | Placeholder | NOT CONFIGURED | No provider implementation/API configuration; returns `NOT_CONFIGURED`. |
| Recon orchestration/normalization (Module 07) | Implemented | READY WITH LIMITATIONS | Per-collector statuses, partial failure, dedupe, invalid collector and evidence-write failure regressions pass; no durable worker. |
| Evidence storage/hash verification (Module 07 integration) | Implemented | PASS WITH LIMITATIONS | Evidence downloads fail closed on digest mismatch; isolated storage/normalization tests pass. |
| Nmap detector/profiles/runner/parser (Module 08) | Implemented | READY WITH LIMITATIONS | Nmap 7.98 detected; basic TCP and service/version scan completed against authorized 127.0.0.1. See [Module 08 audit](MODULE_08_NMAP_AUDIT.md). |
| Nmap XML download (Module 08) | Implemented | PASS | Uses `read_evidence`, verifies stored SHA-256, and enforces investigation ownership. |
| Greenbone/GVM client and lifecycle (Module 09) | Implemented | BLOCKED | python-gvm 27.10.1 installed; no configured endpoint or service credentials. See [Module 09 audit](MODULE_09_GREENBONE_AUDIT.md). |
| Vulnerability report parser/normalizer (Module 09) | Implemented | READY WITH LIMITATIONS | XML fixtures, normalization and evidence persistence tests pass; live GVM report blocked by missing service. |
| Evidence management (Module 10) | Implemented | PASS WITH LIMITATIONS | Evidence rows and local file store, SHA-256 checked on retrieval; owner-scoped `/evidence`; exclusive create prevents evidence ID overwrite. No WORM guarantee or generic job FK. See [Module 10 audit](MODULE_10_EVIDENCE_AUDIT.md). |
| Findings and intelligence (Module 11) | Partially Implemented | PASS WITH LIMITATIONS | Greenbone vulnerability findings with normalization and per-job history; owner-scoped findings page. Generic lifecycle and cross-source correlation are not implemented. See [Module 11 audit](MODULE_11_FINDINGS_AUDIT.md). |
| Exposure scoring (Module 12) | Implemented | PASS WITH LIMITATIONS | Five-factor observed-data heuristic; duplicate finding rows deduplicated for V and assessment state shown. No score history or coverage model. See [Module 12 audit](MODULE_12_EXPOSURE_SCORING_AUDIT.md) and [Group 4 integration report](GROUP_4_INTEGRATION_REPORT.md). |
| Job execution and management (Module 13) | Implemented | READY WITH LIMITATIONS | Nmap subprocess and Greenbone assessment jobs with persisted status, timeout/cancellation and authorization rechecks. In-process `asyncio.create_task`; no durable queue or restart recovery. See [Module 13 audit](MODULE_13_JOB_EXECUTION_AUDIT.md). |
| Workflow orchestration (Module 14) | Not Implemented | NOT READY | No workflow model/API/state machine exists; passive collection only orchestrates collectors and returns a non-persisted ID. See [Module 14 audit](MODULE_14_WORKFLOW_ORCHESTRATION_AUDIT.md). |
| Reporting and export (Group 5 scope) | Implemented | READY WITH LIMITATIONS | On-demand ReportLab PDF and GraphML exports with owner/permission checks; state/content fixes applied. No artifact persistence/history. See [Module 15 audit](MODULE_15_REPORTING_AUDIT.md) and [Group 5 integration report](GROUP_5_INTEGRATION_REPORT.md). |
| PDF reports | Implemented | PARTIAL | `services/reporting/pdf_generator.py`; tests assert binary/signature/download; no visual/text extraction. |
| GraphML reports | Implemented | PARTIAL | `services/reporting/graphml_generator.py`; export tests; no live existing-data export. |
| Audit logs | Implemented | PARTIAL | `models/audit.py`, `api/audit.py`, `core/auth.py`; logging/redaction tests pass; no live audit data reviewed. |
| Database, storage and integrations (Group 6 Module 15) | Implemented with limitations | PASS WITH LIMITATIONS | SQLite is active at Alembic head; fresh upgrade/downgrade/upgrade and integrity checks pass. Five referenced evidence files match stored SHA-256/size; four evidence rows have no raw file path. Local filesystem only; no SeaweedFS adapter, combined backup/restore, or persisted report artifacts. See [Module 15 audit](MODULE_15_DATABASE_STORAGE_INTEGRATIONS_AUDIT.md). |
| Security, testing and deployment (Group 6 Module 16) | Implemented with limitations | PASS WITH BLOCKERS | Session/RBAC/CSRF tests pass; secure staging defaults, trusted-host enforcement and sanitized error logging added. Full suite: 239 passed, 1 skipped. Docker Engine unavailable, dependency vulnerability scanner unavailable, and historical demo credential requires rotation if reused. See [Module 16 audit](MODULE_16_SECURITY_TESTING_DEPLOYMENT_AUDIT.md). |
| Docker deployment | Partially Implemented | BLOCKED | `Dockerfile` uses a non-root user, Nmap, persistent `/var/lib/footprintiq` volume and liveness healthcheck; Docker Engine is unavailable, so image build/container runtime could not be verified. No Compose file. |

## Current verification snapshot

- Automated suite after Group 5: **233 passed, 0 failed, 1 skipped, 20 warnings** (`pytest -q`). Run used process-only `DEBUG=false` and temporary evidence storage; no user database reset. The skip is the optional live Nmap test.
- Local app: running at `http://127.0.0.1:8000` with `DEBUG=false` and demo provisioning disabled for the server process.
- Public pages, CSS, and health checks: PASS. Unauthenticated investigations API: 401 as expected.
- Live Nmap/GVM/theHarvester integrations: BLOCKED or unverified due to missing local configuration/tools.
- Readiness: development/demo foundation; **not production-ready**.




