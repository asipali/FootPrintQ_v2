# Group 4 Integration Report — Modules 10, 11, 12

**Audit date:** 2026-11-02  
**Workflow:** baseline → source/data audit → fixes → regression tests → documentation → final verification.

## Cross-module data flow

Passive collectors and authorized scanners persist source payloads into `evidence`; Greenbone parses evidence XML into `vuln_findings` and vulnerability entity summaries; Nmap persists hosts/ports separately; scoring reads entities, evidence, open ports, and Greenbone findings for an investigation. Investigation association is direct on all these tables. Target is persisted as a string on evidence/findings/jobs and is not a foreign-key asset relationship. The system does not yet provide a general evidence-to-finding relational graph or cross-source intelligence correlation service.

## Baseline and data preservation

Read-only baseline before Group 4 edits: 15 investigations, 7 evidence rows, 17 entities, 5 vulnerability jobs, 8 vulnerability findings, 5 active scan jobs, 0 passive collection jobs, and 15 target authorizations. SQLite `foreign_key_check` returned 0 violations. Of 3 evidence rows with raw paths, no file was missing and no digest, byte-size, or path-containment discrepancy was found. Four evidence records had no raw file path. Existing database content, evidence files, findings, and authorizations were preserved; no migration or deletion was performed.

Prior Module 05–09 changes and user work were retained. Dependency status remains: passive providers are fixture/mock verified rather than live queried; Nmap was previously tested against authorized loopback; Greenbone service is not configured. No finding or score was fabricated.

## Group 4 defects addressed

- P1: evidence, findings, and scan monitor pages lacked login and owner scoping; dashboard aggregates also counted Group 4 records globally. All are now login-gated where appropriate and scoped to accessible investigation IDs (admins retain all-record view).
- P1: empty investigations displayed “Minimal” exposure without any assessment. UI now distinguishes not assessed, in progress, failed, and partial observed-data results.
- P2: evidence storage overwrote deterministic paths on key reuse. Exclusive file creation now preserves existing bytes and returns an explicit error on collision.
- P2: UI/PDF made unsupported immutability claims. Language now describes retrieval-time digest verification and its limit.
- P2: duplicate equivalent vulnerability records could inflate the score and QOD had no bounds enforcement. Scoring deduplicates calculation inputs with the existing stable key and clamps QOD while retaining per-job historical records.
- P2: “unified/correlated findings” UI implied missing functionality. It now accurately describes Greenbone vulnerability findings; Nmap observations remain a separate result type.

## Test and local verification

Targeted regression set: **23 passed** (Module 10–12 regressions, dashboard phase 7, evidence storage, PDF report). Full suite: **230 passed, 0 failed, 1 skipped, 20 warnings**. Tests use isolated SQLite and temporary evidence storage; scanner/parser integrations are controlled fixtures/mocks. Optional live Nmap test remains skipped. The local application remains at `http://127.0.0.1:8000`; `/health/ready` returned 200 and unauthenticated `/evidence` returned the expected 303 login redirect.

## Deferred architecture work

No score history/persistence, general finding lifecycle, evidence FK from vulnerability findings, generic scanner job FK on evidence, evidence deletion/retention/size policy, WORM storage, generalized correlation graph, or coverage model exists. Those gaps are documented in the module audits; no database migration was justified for this pass.
