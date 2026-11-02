# Module 08 — Nmap Active Network Reconnaissance Audit

**Date:** 2026-11-02  
**Status:** READY WITH LIMITATIONS

## Architecture and environment

`app/api/nmap_scans.py` provides authenticated status/profile endpoints, investigation-bound dispatch/list, per-job status/cancel/results, and raw XML download. `NmapDetector` resolves `NMAP_BIN`, PATH, and common OS locations, then invokes `nmap --version` without a shell. `NmapRunner` revalidates authorization, builds a fixed vetted argument list, executes via `asyncio.create_subprocess_exec`, enforces profile timeout/concurrency, parses bounded XML, and persists host/port findings and XML evidence.

**Environment:** Nmap 7.98 is installed and executable; detector returned READY. The actual binary path is intentionally not recorded. The current process can execute it without elevated privileges for the supported TCP connect profiles. A real, explicit-authorization loopback run completed on `127.0.0.1` with both the basic TCP and service/version profiles. No other host was contacted.

## Supported profiles

| ID | Actual options | Purpose / limitations |
|---|---|---|
| `basic_tcp` | `-sT -T3 --top-ports 100 -Pn` | Conservative TCP connect top-100 discovery; no raw SYN privilege required. |
| `service_inventory` | `-sT -sV --version-intensity 2 -T3 --top-ports 100 -Pn` | TCP connect plus version/service detection on top 100 ports. |
| `quick_ping` | `-sn -T3` | Host discovery without port enumeration. |

No full TCP 1–65535, selected-port parameter, SYN, or OS-detection profile is implemented. The API intentionally accepts only a profile ID; it does not accept user-supplied Nmap flags. Profiles have bounded time/output settings; Nmap receives separate argv items, not a shell string.

## Authorization and job lifecycle

Before dispatch and again at the background execution boundary, Module 06 validates authenticated requester, current active account, investigation owner/admin access, active investigation, `recon.active` role permission, exact target/scope, explicit `SCAN_ACTIVE` authorization window and revocation. If authorization has expired/revoked while queued, the job is marked `FAILED/AUTHORIZATION_REVOKED`, audited, and no process is started.

Jobs are created in SQL and execution is dispatched using in-process `asyncio.create_task`; the subprocess itself is managed asynchronously with timeout/kill, cancellation and cleanup. This is not a durable queue: process restart may interrupt a scan and leave a nonterminal persisted status. Findings, job records and evidence persist in SQLite/filesystem after completion.

## Defects fixed

| ID / priority | Root cause and impact | Fix and verification |
|---|---|---|
| M08-P0 | Job status/results/XML API authenticated by role but did not verify investigation ownership; unauthorized account could read/cancel scan data by ID. | Apply owner/admin access on list/status/cancel/results/XML paths. Cross-owner API regression checks pass. |
| M08-P0 | Authorization was checked at dispatch only; job could start after the record was revoked/expired or requester disabled. | Repeat owner, role, account, scope and `SCAN_ACTIVE` checks immediately before subprocess launch. Revocation regression asserts no subprocess call. |
| M08-P1 | Detail form sent stale profile IDs; form handler called an obsolete runner signature, caught all errors, then redirected as success. | Correct profile IDs and route form to current queue/runner methods; failed submissions now return an error. |
| M08-P1 | XML download used nonexistent `retrieve_evidence_bytes`, so download failed; hash was not recomputed. | Use `read_evidence`, compare SHA-256 with stored digest, fail closed on mismatch; API regression test passes. |
| M08-P2 | Empty ports UI implied no findings without distinguishing no scan, running, failure, and completed empty output. | Render state-specific empty messages; completed host-discovery profile explains absent port results. |

## Verification

- Mocked runner, detector, XML parser and API coverage pass.
- Real test `RUN_LOCALHOST_NMAP=1 python -m pytest -q tests/test_nmap_runner.py::test_live_nmap_scan_is_confined_to_authorized_loopback`: **1 passed**; basic TCP and service/version scans completed, host/result XML and evidence persisted in an isolated test DB and temporary evidence directory.
- Full suite: **225 passed, 1 skipped, 20 warnings**. The skip is the opt-in live test (executed separately above).

**Readiness:** READY WITH LIMITATIONS. The implemented profiles work locally; durable job recovery and unimplemented scan profiles remain out of scope.

