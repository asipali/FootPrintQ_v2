# Modules 07–09 — Integration Report

**Date:** 2026-11-02  
**Overall:** Partially verified: Module 07 READY WITH LIMITATIONS, Module 08 READY WITH LIMITATIONS, Module 09 BLOCKED.

## Combined execution flow

1. Authenticated user selects an investigation they own (or has administrator access) and a target.
2. Module 06 validates exact target/scope and the operation-specific explicit approval: `RECON_PASSIVE`, `SCAN_ACTIVE`, or `SCAN_VULN`.
3. Passive recon runs registered collectors concurrently and persists individual collector statuses, evidence and normalized findings. Unknown collector choices and failed evidence persistence no longer generate misleading success records.
4. Nmap dispatch persists a job; the in-process worker repeats authorization immediately before process launch, uses a fixed profile argv, runs Nmap under bounded timeout, parses XML, and persists evidence/results.
5. GVM dispatch persists a job; the in-process worker rechecks authorization and account status before service work and task start, then retrieves/parses report data when configured.
6. Job, findings and raw evidence routes recheck investigation ownership. Evidence downloads compare the calculated SHA-256 to the stored digest.
7. UI refresh reads persisted collector/scan jobs and reports actual no-scan, queued/running, failed or completed-empty states.

## Test and environment results

- Baseline before Module 07–09 changes: **217 passed**.
- Final automated suite: **225 passed, 1 skipped, 20 warnings**. The one skip is an opt-in real Nmap test.
- Live authorized loopback integration: **1 passed** separately with `RUN_LOCALHOST_NMAP=1`; `basic_tcp` and `service_inventory` executed only against `127.0.0.1` in an isolated test DB, then parsed/persisted results and evidence to temporary storage.
- Nmap 7.98 detected and executable.
- python-gvm 27.10.1 installed; Greenbone status `NOT_CONFIGURED` because no endpoint/service credentials are configured. GVM live functional tests are BLOCKED.
- Passive collector tests use mocked external providers. No Internet/public or non-authorized domain queries were made. theHarvester is not installed/configured; public-search collector is an explicit placeholder.
- Database was not reset or migrated for this audit; test workflows use isolated rollback fixtures. No existing scan/evidence rows were deleted.

## Confirmed fixes

Removed unauthenticated admin fallback in passive web launch; repaired outdated Nmap/GVM form handlers and profile IDs; no silent success after failed launch; owner-bound all job/result/evidence APIs; repeat operation authorization at background execution; fail closed on evidence hash mismatch; correct Nmap evidence reader; improve GVM TLS verification and task report ID parsing; distinguish completed zero findings from never-run/failed jobs; reject unknown passive collector selection and avoid fake evidence on storage failure.

## Remaining constraints

- Passive third-party provider connectivity, real DNS/RDAP/CT responses and theHarvester live execution were not exercised because no authorized external domain/provider setup was provided.
- Public search is NOT_CONFIGURED/placeholder; theHarvester is NOT_CONFIGURED.
- Nmap profiles remain limited to three vetted profiles; no full-port, selected-port, SYN or OS-detection option exists.
- Nmap/GVM jobs use in-process `asyncio.create_task`, not durable workers. Restart can interrupt active work; stale-job reconciliation is not implemented.
- Greenbone cannot be considered functionally ready until configured service, authentication, scanner, feeds and scan configurations are verified against an authorized lab target.


