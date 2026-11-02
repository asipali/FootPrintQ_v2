# Group 5 Integration Report — Modules 13, 14, 15

**Audit date:** 2026-11-02. Workflow orchestrator, queue, report history, or migration was not added.

## Actual integration flow

Investigation and authorization are validated at the standalone dispatch APIs. Passive collectors execute concurrently inside the request orchestration and persist per-collector job/evidence/entity records. Nmap and Greenbone create investigation-linked rows, then launch best-effort in-process asyncio tasks. Nmap invokes a vetted subprocess profile; GVM invokes its external task/report flow. Evidence and findings are persisted by those modules. Score is calculated on demand from stored records. PDF and GraphML exports query the selected investigation and stream outputs after permission/ownership checks.

There is **no persisted cross-module workflow** connecting those steps, no prerequisite ordering, no workflow completion state, and no workflow-level failure/retry/recovery. The passive orchestration response ID is not a durable workflow record. End-to-end Group 5 workflow is therefore not available; separate existing module flows were fixture-tested.

## Job and reporting corrections

- GVM progress now uses only the scanner-reported, bounded percentage instead of fabricated stage/scale values.
- PDF now represents job/assessment states honestly, hides a zero/minimal score when no successful assessment exists, and records provenance/timestamps without claiming to re-verify stored files.
- PDF escapes database text before ReportLab markup parsing and marks long finding descriptions when truncated.
- Export exceptions are logged internally and generic details are returned to clients.
- Existing active-scan authorization, cancellation, timeout, duplicate prevention and job/evidence persistence remain in place. No retry or restart recovery is claimed.

## Verification

- Baseline full suite before Group 5 edits: **230 passed, 1 skipped, 20 warnings**.
- Focused job/report tests: **21 passed**. Final full suite: **233 passed, 0 failed, 1 skipped, 20 warnings**; the skip is the optional live Nmap test.
- Controlled empty-report generation was checked with `pdfinfo` and `pdftotext`; the PDF parsed as two pages, clearly stated not assessed/not performed, and omitted the Minimal score.
- Nmap/GVM execution tests use controlled fixtures/mocks. Live GVM was blocked by missing service configuration; optional live Nmap remains skipped. No authorized network scan or external passive-provider lookup was run as part of Group 5.
- Local application health and login/public pages returned expected responses; app startup requires process-only `DEBUG=false` due existing invalid `.env` value. No database/evidence changes were made by the local report QA; report fixture used in-memory SQLite.

Read-only final database check: 15 investigations, 8 evidence rows, 17 entities, 6 GVM jobs, 8 vulnerability findings, 6 Nmap jobs, 0 passive collection jobs, and 15 authorizations; SQLite foreign-key check reported zero violations. Four evidence rows have raw files; all four files were present, path-contained, and matched their stored SHA-256 and byte length. The prior Group 4 report recorded 7 evidence rows, 5 GVM jobs, and 5 Nmap jobs. Group 5 verification used isolated test databases, an in-memory PDF fixture, and GET-only localhost checks; it did not create these live rows. The difference from the earlier snapshot is preserved and its exact source was not inferred or “cleaned up.”

## Readiness

- Module 13: **READY WITH LIMITATIONS** — standalone best-effort single-process jobs; no durable worker/restart recovery.
- Module 14: **NOT READY** — executable workflow orchestration is absent.
- Module 15: **READY WITH LIMITATIONS** — on-demand PDF/GraphML exports; no report persistence/history and arbitrary Unicode font support is limited.

No database migration was created. Prior user changes and history were preserved; no commit, push, deployment, or database reset occurred.
