# Module 07 — Passive Reconnaissance Audit

**Date:** 2026-11-02  
**Status:** READY WITH LIMITATIONS

## Architecture and API

`app/api/recon.py` exposes:

- `POST /api/v1/investigations/{investigation_id}/passive-recon` — synchronous request/response orchestration (collectors run concurrently inside the request).
- `GET .../passive-recon` — persisted collector jobs.
- `GET .../entities` — normalized findings.
- `GET .../evidence` and `GET .../evidence/{evidence_id}/raw` — evidence metadata/content with hash validation.
- `POST .../validate-target` — shared target/scope/operation authorization validation.

The request accepts a target and optional collector key list; response returns overall status, per-collector jobs/status/errors, evidence and finding counts. All API and web routes require an authenticated owner/admin with the relevant permission. Execution calls Module 06 `verify_target_authorization` for `RECON_PASSIVE` before collector work.

## Collector inventory

| Collector | Source and behavior | Dependency/configuration | Test/functional status |
|---|---|---|---|
| DNS | `DNSCollector.collect`, queries A, AAAA, MX, NS, CNAME, TXT, SOA, normalizes hosts/IPs/records | dnspython and configured resolver; per-query timeout | Mocked success/NXDOMAIN tests pass; no external DNS queries used in this audit. |
| RDAP / WHOIS | `RDAPCollector.collect`, parses registry JSON and uses WHOIS fallback on unsupported/unavailable RDAP | HTTPX; bootstrap/registry endpoint; WHOIS TCP referral client | Mocked RDAP and WHOIS fallback tests pass. Registration fields are naturally provider-dependent. |
| Certificate transparency | `CertificateTransparencyCollector.collect`, crt.sh response and unique subdomain extraction | HTTPX; crt.sh reachability | Mocked success/unconfigured tests pass; no external-domain query performed. |
| theHarvester | `TheHarvesterCollector.collect`, executable detection, argument-list subprocess, timeout, JSON/stdout parsing | Optional `THEHARVESTER_BIN`; upstream providers/API keys configured by the tool | Missing binary and mocked process tests pass; executable not configured locally, so live status is NOT_CONFIGURED. |
| Public search | `PublicSearchCollector.collect` | Provider/API key not implemented/configured | Explicit placeholder returns NOT_CONFIGURED; not a functioning provider. |
| Orchestration | `PassiveReconOrchestrator.run`; concurrent isolated collectors, per-collector status, normalized entities and evidence persistence | SQLAlchemy, evidence filesystem, app concurrency setting | Failure isolation, dedupe, invalid collector selection and storage failure regression tests pass. |

There is no standalone WHOIS API route; WHOIS is the fallback path in RDAP. No extra domain intelligence provider was found beyond these sources.

## Defects fixed

| ID / priority | Root cause and impact | Fix and verification |
|---|---|---|
| M07-P0 | Dashboard passive form silently fell back to an administrator identity when unauthenticated, and did not verify investigation ownership/permission. | Removed impersonation fallback; require authenticated passive permission and owner/admin access before orchestration. Covered by backend authorization checks. |
| M07-P1 | Web form swallowed collector/authorization exceptions and redirected as if the action succeeded. | Failed requests now return an error response; jobs persist per-collector failure status for refresh/history. |
| M07-P1 | Unknown collector names silently selected zero collectors, returning a misleading empty partial result. | Unknown and duplicate collector keys are rejected before jobs are created. Added regression coverage. |
| M07-P1 | Evidence write failures created synthetic evidence records with placeholder hash/path and still ingested findings, yielding false success/orphan provenance. | Failed persistence now marks the job failed and does not fabricate evidence or ingest findings. Added regression test. |
| M07-P1 | Recon, entity and evidence reads authenticated only by broad role and could disclose another investigation’s data. | Added shared Module 05 owner/admin checks for recon jobs, entities, evidence metadata and raw evidence. |
| M07-P1 | theHarvester stderr was copied into persisted diagnostic metadata and could echo provider API keys. | Persist only stderr byte counts and a generic error category/message; regression test verifies a mocked key is not exposed. |
| M07-P2 | Raw evidence route returned a body even when computed hash differed from the stored hash. | Raw evidence is returned only after hash equality; otherwise 500 integrity failure. |

## Job and UI behavior

Execution is synchronous at the HTTP operation level, though collectors run concurrently. There is no durable background queue or cancellation mechanism. Per-collector rows and statuses persist and partial collector success is retained. The detail UI reads persisted collector jobs/entities/evidence on refresh. The web UI now surfaces a failed submission as an error rather than reporting implicit success.

## Verification and limitations

- Suite baseline before edits: **217 passed**.
- Final suite: **225 passed, 1 skipped, 20 warnings**; the skipped case is the opt-in real Nmap loopback test, run separately and passed.
- Collector tests are mocks; no public or non-authorized domain was queried. DNS/RDAP/crt.sh provider connectivity and actual theHarvester operation remain unverified locally.
- `search` is a placeholder and theHarvester is not configured. These are declared limitations, not claimed as fixed.

**Readiness:** READY WITH LIMITATIONS for configured DNS/RDAP/crt.sh workflows. theHarvester and public search remain NOT_CONFIGURED/placeholder capabilities.



