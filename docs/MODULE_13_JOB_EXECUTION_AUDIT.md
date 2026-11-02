# Module 13 — Job Execution and Management Audit

**Verified:** 2026-11-02. No user DB, scan history, evidence, or reports were reset or deleted.

## Architecture and supported job types

There is no generic `Job` model or queue. The database has three job record types: `CollectionJobModel` (`collection_jobs`) per passive collector, `ActiveScanJobModel` (`active_scan_jobs`) for Nmap, and `VulnerabilityScanJobModel` (`vuln_scan_jobs`) for Greenbone. Each is linked to an investigation; scan jobs record target and requester. Nmap/GVM link evidence via `evidence_id`; passive collection links `EvidenceModel.job_id` to a collection job.

- **Passive collection:** `PassiveReconOrchestrator.run_recon()` executes inside the request coroutine and concurrently awaits supported collectors with a semaphore. Jobs/evidence/entities are committed as collectors finish. Its returned `orch-...` ID is response-only; there is no persisted orchestration record.
- **Nmap:** API and web dispatch create/commit a queued job, then launch `NmapRunner.execute_scan()` through `asyncio.create_task`. Execution is an asyncio subprocess with a vetted command profile, a profile timeout, bounded concurrency, XML parsing, and persisted results/evidence. Nmap jobs prevent a duplicate queued/running job for the same investigation, target, and profile.
- **Greenbone:** dispatch creates a queued job and launches `execute_assessment_job()` with `asyncio.create_task`. The service creates/polls GVM tasks, parses a report, stores evidence, then persists findings. Polling has a configured attempt bound. Duplicate active target jobs are rejected. GVM client calls are synchronous inside the async coroutine, so slow GVM network calls can block the event loop; live service behavior could not be checked because GVM is unconfigured.

There is no persistent queue, worker, `BackgroundTasks` usage, workflow model, retry subsystem, or restart recovery. Nmap/GVM task references, active subprocesses, and cancellation requests are in memory. A process restart can leave queued/running rows with no executor, and cannot restore a running subprocess or reliably finish its evidence transaction. Treat these as best-effort single-process background jobs, not durable execution. No queue or implicit recovery mutation was introduced.

## Status, progress, cancellation, and authorization

The job models persist status, timestamps, duration, error category/message, and scanner-specific metadata. Nmap supports queued/running/completed/partial/failed/cancelled/timed-out/rejected states in its runner. GVM records setup/running/report/parsing stages plus completed/failed/cancelled/timed-out/not-configured states. Passive jobs are per-collector and end in success/partial/failed/not-configured. There is no shared state-transition service or retry history.

Nmap uses an asyncio subprocess timeout and can terminate the in-process process. GVM uses bounded polling, asks GVM to stop on cancellation/timeout, and records the terminal status. Cancellation cannot be recovered after restart. Both active scan workers reload the requester/investigation and repeat target authorization checks at execution boundaries; GVM additionally rechecks before task creation and start. Dispatch endpoints enforce permissions and investigation ownership. Passive authorization is checked by its orchestrator.

**Progress defect fixed (P2):** GVM worker had displayed fabricated stage percentages (5, 15, 20, 85, 90) and scaled service progress into an arbitrary 20–80 range. Setup-stage values are now left unchanged, and a valid scanner-reported percentage is clamped to 0–100 and stored directly. Invalid/missing GVM percentages do not overwrite the last actual value. Regression checks cover values, bounds, and malformed input.

## Test results and limitations

Baseline before Group 5 changes: **230 passed, 1 skipped, 20 warnings**. Existing Nmap and GVM runner/API suites cover fixture/mock execution, status, timeout/error/cancellation paths, authorization revalidation, and evidence/finding persistence. New unit tests cover reported-progress bounds. No live GVM worker test was possible; the optional live Nmap test remains skipped. There is no restart-recovery test because no recovery mechanism exists. See [Group 5 integration report](GROUP_5_INTEGRATION_REPORT.md).

**Readiness:** READY WITH LIMITATIONS for existing single-process job functions; not durable across restart and not a generalized job platform.
