# Module 14 — Workflow Orchestration Audit

**Verified:** 2026-11-02.

## Implementation baseline

No workflow database model/table, workflow schema, workflow CRUD or execution API, workflow service, dependency/state machine, persistent workflow history, or workflow UI exists. Search of application source and migrations found no such implementation. “Workflow” in informational pages describes the user journey; it is not an executable workflow. Passive reconnaissance is the sole multi-collector orchestrator: it runs selected collectors concurrently, writes per-collector jobs/evidence/entities, and returns a non-persisted orchestration ID. It does not dispatch Nmap, Greenbone, scoring, or reports as dependent stages.

Actual supported modules remain separately callable: passive collection; explicitly authorized Nmap; explicitly authorized GVM; on-demand scoring during investigation/report rendering; and on-demand PDF/GraphML exports. There is no dependency scheduler, prerequisite blocking, partial workflow state, retry, cancellation, or result aggregator spanning these modules.

## Findings and disposition

| ID | Priority | Finding | Disposition / verification |
|---|---|---|---|
| W14-1 | P1 / feature gap | No executable end-to-end workflow or durable workflow history exists; the passive orchestrator does not represent a Group 5 pipeline. | Documented as not implemented. No workflow system was fabricated or added; creating one would require schema/API/state semantics and architecture beyond a safe defect patch. |
| W14-2 | P2 | Passive orchestrator returns a generated `orchestrator_job_id` without persisting a workflow row. | Identified as response correlation only, not workflow history. Existing collector/job/evidence behavior remains covered by passive orchestration tests. |

## Authorization, failures, and tests

There is no workflow submission surface to secure or test. Each supported active job independently checks RBAC, investigation access, exact target, enabled scope, authorization operation, expiration/revocation, and repeats authorization in the worker before execution. These checks do not create a guarantee that a future dependent workflow would revalidate all stages.

No application changes were made to claim cross-module ordering/recovery. Existing passive, Nmap, GVM, and report tests are separate; their mocks are controlled unit/API fixtures, not a successful end-to-end workflow. Live GVM is not configured, and passive external providers were not queried in this audit.

**Readiness:** NOT READY — executable workflow orchestration is absent. Existing standalone module jobs remain usable under their own access/authorization controls.
