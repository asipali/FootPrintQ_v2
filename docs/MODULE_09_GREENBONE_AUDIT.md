# Module 09 — Greenbone / OpenVAS Vulnerability Assessment Audit

**Date:** 2026-11-02  
**Status:** BLOCKED (external service not configured)

## Architecture and configuration

The API in `app/api/vulnerability.py` reports service status, lists vetted profiles, dispatches assessments, lists/reads/cancels jobs, returns findings and downloads raw reports. `VulnerabilityAssessmentOrchestrator` creates SQL jobs, invokes `GreenboneAdapter`, manages target/task/start/poll/report stages, parses XML, and persists evidence/findings. The adapter uses **python-gvm 27.10.1** and GMP. `GreenboneClient` supports network TLS and Unix socket connections.

Required configuration: either `GVM_HOST` + `GVM_PORT` (default 9390) or `GVM_UNIX_SOCKET`, plus `GVM_USERNAME` and `GVM_PASSWORD`; TLS uses `GVM_TLS_VERIFY` and optional `GVM_CA_FILE`. Secret values are not printed or recorded in this report. TLS verification is now actually enabled by default with CA-chain and hostname validation; the installed python-gvm default connection disabled certificate checks, so the app now supplies a verified standard-library TLS socket. Set `GVM_TLS_VERIFY=false` only when a deliberately unverified link is required.

**Environment result:** `python-gvm` is installed, but configured endpoint/credentials are absent; status is `NOT_CONFIGURED`, endpoint `none`, authenticated false. No connection, authentication, target creation or scan task was attempted. Scanner, feed, config UUID and report format availability cannot be verified without GVM.

## Configured profile catalog

- `openvas-basic` → Greenbone `Base` UUID `daba56c8-73ec-11df-a475-002264764ceb`.
- `openvas-full-and-fast` → `Full and fast` UUID `daba56c8-73ec-11df-a475-002264764cea`.
- `openvas-discovery` → `Discovery` UUID `daba56c8-73ec-11df-a475-002264764cec`.

These are static application profile definitions; server-side configuration presence is unverified while GVM is absent. The UI now distinguishes no assessment, pending/running, failed, completed with zero findings, and findings present.

## Authorization and execution

The dispatcher checks `vulnerability.scan`; job creation checks active investigation ownership, profile, exact target scope and an explicit `SCAN_VULN` record. The background worker reloads the persisted requester and job and repeats owner/account/role/operation/validity/revocation checks after dispatch, before GVM setup and again immediately before starting the task. Findings, status and report retrieval APIs enforce investigation ownership. Cancellation is owner/permission checked. Jobs use in-process `asyncio.create_task`; they are not durable across application restarts.

## Defects fixed

| ID / priority | Root cause and impact | Fix and verification |
|---|---|---|
| M09-P0 | Job/status/findings/report/cancel endpoints exposed another investigation’s scan data via ID to any authenticated user with broad route access. | Owner/admin checks now bind every job operation to its investigation; cross-owner status/findings tests pass. |
| M09-P0 | Background GVM start relied on dispatch-time authorization and did not re-load requester or re-check a revoked/expired record. | Revalidate the persisted actor, investigation, target, status, permission, and `SCAN_VULN` approval at worker start and before GVM task launch. Revocation regression confirms no connection is attempted. |
| M09-P1 | Configured `GVM_TLS_VERIFY=True` had no effect because python-gvm’s default TLS connection used `CERT_NONE`. | Verified TLS wrapper uses system or configured CA, TLS 1.2+, and hostname checking. Unit test verifies server name and TLS context. |
| M09-P1 | XML task report lookup used Element truthiness (`element_a or element_b`); leaf report elements evaluate false and could drop a valid report ID. | Use explicit `is None` fallback; report ID regression passes. |
| M09-P1 | API report retrieval ignored computed hash and exposed read errors. | Compare computed/stored SHA-256 and fail closed, with generic error text. |
| M09-P2 | Web UI used obsolete assessment-service arguments and displayed a generic “no vulnerabilities” state before any scan completed. | Route form through current owner/permission-checked job API service; render distinct no-scan, running, failed, and completed-empty states. |

## Verification and dependencies

- Mocked GVM client connection/authentication/status, task state, XML parser, finding normalization and execution tests pass.
- TLS verification and last-report-ID regression tests pass.
- Full suite: **225 passed, 1 skipped, 20 warnings**.
- No real GVM operation could be run. Required next step is provide a reachable GVM service, valid service account, trusted CA (if private), a scanner and the three configured scan configs; then rerun connection, target/task/report integration using an expressly authorized lab target.

**Readiness:** BLOCKED until the external Greenbone service and credentials/configurations are available. Mock tests do not establish real-service compatibility.

