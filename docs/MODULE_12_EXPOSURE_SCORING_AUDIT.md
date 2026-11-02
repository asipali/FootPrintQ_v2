# Module 12 — Exposure Scoring Audit

**Verified:** 2026-11-02. Scoring remains a heuristic over persisted application records; this audit did not invent risk data or introduce a new scoring model.

## Exact implemented formula

`ExposureScorer` (`app/services/scoring/calculator.py`) computes component values, each capped at 100:

- **P — Public Footprint:** 12 per email entity + 8 per person + 18 per document + 10 per evidence whose source type contains `search`.
- **D — Domain Hygiene:** 10 per domain/subdomain entity + 25 when DNS evidence exists and no DNS evidence metadata string contains `dmarc`. Despite older descriptive copy, SPF is not evaluated.
- **S — Service Exposure:** 14 per open port + 20 for each exposed database port, else 15 for each admin port, else 5 for port 80.
- **V — Vulnerability Severity:** critical 35, high 22, medium 12, low 5, other/unknown/info 1; multiplied by `QOD/100`. Missing QOD defaults to 100. The same stable host/port/protocol/name/NVT/primary-CVE key is counted once in this component; underlying per-scan rows are retained. QOD is clamped to 0–100.
- **C — Correlation Confidence:** 20 per distinct evidence source name + 5 per evidence row, with the evidence-row contribution capped at 40, then total capped at 100. This is evidence/source diversity, not a graph correlation measure.

Composite: `round(0.20*P + 0.15*D + 0.25*S + 0.35*V + 0.05*C)`, clamped 0–100. Python’s standard `round` behavior applies. Tiers: Minimal 0–19, Low 20–39, Moderate 40–59, High 60–79, Critical 80–100. Calculation timestamp and formula version are returned, but no score snapshot/history is persisted.

## Findings and fix

| ID | Priority | Finding and root cause | Fix / verification |
|---|---|---|---|
| S12-1 | P1 | An investigation with no completed job displayed a calculated 0 / Minimal score, conflating no assessment with a clean result. | Scorer now exposes an assessment state from persisted jobs. UI labels no jobs “Not assessed,” jobs in flight “Assessment in progress,” only failed terminal jobs “Assessment failed,” and observed data after a successful job “Partial coverage.” Regression checks empty vs completed zero-result collection. |
| S12-2 | P2 | Repeated equivalent findings and out-of-range QOD could inflate or distort V. | Calculation deduplicates with existing stable key and bounds QOD. Historical scanner records are retained. |
| S12-3 | P2 | Formula descriptions implied SPF checks and true cross-collector correlation that are not performed. | This report records the actual rules; UI labels the result an observed-data heuristic and warns that zero findings/low score does not establish security. |

Assessment state is derived from stored collection/Nmap/GVM jobs: no jobs = `NOT_ASSESSED`; any recognized active state = `IN_PROGRESS`; otherwise any `COMPLETED` or `PARTIAL` job = `PARTIAL`; recorded jobs with no successful job = `FAILED`. `PARTIAL` is deliberate: the application has no configured, persisted coverage model proving all relevant collection/scanning was completed. A completed GVM job with zero findings remains a calculated zero V component, not a zero-risk conclusion.

## Limitations and verification

There is no score history table, user-triggered score recalculation API, resolved finding state, finding status filter, score trend, calibration against incidents, confidence interval, severity count panel, or validated coverage denominator. The UI computes on page load and reports last calculation time only within the returned score object; the report generator also invokes the same scorer. Public footprint/domain components count rows rather than distinct normalized assets; repeated entities can contribute repeatedly. D’s metadata substring test and C’s source-name heuristic are coarse. These limitations should be addressed before using the number as a compliance measure or an independently calibrated risk metric.

Regression coverage validates unassessed/partial states, score bounds behavior by existing component caps, and duplicate vulnerability calculation behavior through the stable key; PDF scoring integration remains covered by existing tests. External scanner availability is not implied by fixture-based tests.
