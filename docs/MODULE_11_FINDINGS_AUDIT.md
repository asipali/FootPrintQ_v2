# Module 11 — Findings and Intelligence Audit

**Verified:** 2026-11-02. Scope is implemented findings and direct evidence/score integrations; no new intelligence sources or detections were added.

## Supported implementation

- The only dedicated persisted finding model is `VulnerabilityFindingModel` (`app/models/vulnerability.py`, table `vuln_findings`), linked by foreign keys to an investigation and a vulnerability scan job. It stores host, optional port/protocol, name/description/solution, normalized and raw severity, CVSS, CVE references, NVT OID, QOD, source finding ID, evidence ID string, and first/last-seen timestamps.
- Greenbone report parsing/normalization is in `app/services/vuln/xml_parser.py`, `app/services/vuln/normalizer.py`, and `app/services/vuln/orchestrator.py`. Severity is normalized to critical/high/medium/low/info/unknown; port/protocol is parsed from scanner data.
- Nmap services are persisted as scan host/port observations, not `VulnerabilityFindingModel` records. Passive reconnaissance stores entities/evidence; there is no generic finding extractor or cross-source finding/correlation engine.
- `/findings` lists Greenbone vulnerability records only. It requires login and scopes both rows and investigation filter options to the user’s accessible investigations. It no longer claims to be a unified correlated matrix.

## Findings and fixes

| ID | Priority | Finding and root cause | Fix / verification |
|---|---|---|---|
| F11-1 | P1 | `/findings` returned findings and investigation names across owners without login. | Added login gate and owner/admin query scoping; existing filter page tests now explicitly create owned investigations, and regression checks non-owner isolation through the shared page policy. |
| F11-2 | P2 | Dashboard “findings” copy promised cross-module correlation not backed by a generic finding/correlation model. | UI copy now describes the actual Greenbone source and points Nmap observations to scan results. No unsupported correlation behavior was introduced. |
| F11-3 | P2 | A stable finding deduplication key existed but was not used by the scorer; repeated equivalent scanner results could inflate the vulnerability component. | Scoring now applies that key to calculation inputs while retaining all historical per-job finding rows and provenance. QOD is clamped to 0–100; missing QOD retains the existing 100 default. |

The key normalizes host, port, protocol, finding name, NVT OID, and primary CVE before hashing. Scoring deduplication is intentionally calculation-only: rows from different jobs remain available as history and continue to reference their report evidence. There is no status/lifecycle field, so no resolved/closed policy can be applied. Invalid or unknown severity currently contributes the lowest one-point base weight; this is reflected in the scoring audit.

## Data integrity and lifecycle

Baseline: 8 vulnerability finding rows; zero findings without a matching job and zero job/investigation mismatches. The database has no generic Finding API, update/status/history operations, category taxonomy, evidence FK on findings, or explained cross-evidence correlation graph. The report evidence reference is a string, so referential integrity is enforced in orchestration rather than SQL. Scanner findings are linked to investigation and host/port in-row, and to evidence by ID; entity-level vulnerability summaries are persisted separately with evidence IDs in JSON metadata.

No lifecycle or cross-source correlation feature was represented as implemented. Live Greenbone execution remains unavailable because GVM is not configured; Greenbone parser/orchestrator coverage is fixture/mock-based. Nmap/passive dependencies and their live-provider limitations are recorded in the Module 07–09 integration report.

## Verification

Finding filters, ownership scoping, vulnerability parser/normalizer fixtures, GVM orchestration fixtures, evidence linkage, PDF reporting, and score aggregation are covered by the automated suite. These tests do not establish live scanner coverage or real target findings.
