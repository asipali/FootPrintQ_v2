# Module 15 — Reporting and Export Audit

**Verified:** 2026-11-02.

## Supported formats and architecture

- **PDF:** `InvestigationReportGenerator` uses ReportLab Platypus and returns a PDF byte stream on demand. `GET /investigations/{investigation_id}/report/pdf` enforces `report.export` and investigation ownership, sets attachment/no-store headers, and audits the export. No report table, saved artifact store, report version/history, or asynchronous report job exists.
- **GraphML:** `GraphMLExporter` exports the investigation node, entity nodes, Nmap host/port nodes, and Greenbone vulnerability nodes/edges as XML. Web and API download routes enforce access and export permission. XML text is escaped. It is a knowledge graph export, not a full report or workflow trace.
- **Raw scanner XML:** Nmap/GVM XML download routes return evidence payloads with digest checking. These are evidence retrievals, not additional report formats.

No CSV, JSON dossier, DOCX, or persisted report format is implemented. PDF includes investigation identity/scope, authorization records, observed entity/port/vulnerability data, score heuristic, job status/timestamps, evidence IDs/source/target/collection time and recorded digest prefixes, remediation text, and limitations. Finding status/lifecycle is absent in the source model. PDF descriptions are capped at 1,200 characters per finding with an explicit truncation marker; all finding rows are included. Evidence bytes are not re-read during report generation, so PDF digest prefixes are recorded metadata, not a report-time integrity verification.

## Defects fixed

| ID | Priority | Root cause and impact | Fix / verification |
|---|---|---|---|
| R15-1 | P1 | Empty or failed assessment displayed a numeric zero/Minimal score and the summary implied a scan had been conducted. | PDF now derives passive/Nmap/GVM status from persisted jobs; labels not performed, pending/running, completed, failed, cancelled, and partial outcomes; suppresses composite score for unassessed/failed states; completed-empty GVM explicitly says zero findings is not proof of safety. Controlled PDF text extraction verifies empty-state content. |
| R15-2 | P1 | Dynamic database strings were passed to ReportLab `Paragraph` as markup, so `&`, `<`, or malicious tags could break or alter a report. | Escape dynamic text before markup parsing across PDF identity/scope, findings, jobs, evidence, and recommendations. Empty-report fixture includes ampersand/angle-bracket values and still generates a valid PDF. |
| R15-3 | P2 | PDF labels and copy overstated a “17-section” report, graph correlation, SPF checking, and evidence verification; sections did not match that claim. | Removed unsupported 17-section claim; describes observed-data heuristic and actual DMARC substring rule, and distinguishes recorded hashes from retrieval-time verification. UI copy follows the implemented dossier. |
| R15-4 | P2 | Export error responses included raw exception strings, potentially exposing implementation details. | Web PDF/GraphML and API GraphML failures now log server-side details and return generic errors. Export authorization checks remain intact. |

## Content and document QA

PDF uses US Letter pages, fixed margins, repeated header/footer, and a two-pass page counter. Jobs display persisted start/completion times; evidence displays collected time; finding descriptions/evidence IDs/first-seen are included where available. Long finding descriptions use word wrapping and explicit truncation. ReportLab base fonts may not render arbitrary CJK/emoji glyphs; standard Latin/Unicode punctuation works in the generated test. Large records are streamed in memory and are not retained for history.

Controlled empty-investigation PDF was opened and text-extracted with local `pdfinfo`/`pdftotext`: valid two-page PDF, “NOT ASSESSED” and “NOT PERFORMED” present, no “Minimal” score. Existing fixture PDF tests cover populated data, empty investigations, download headers, and valid `%PDF`/EOF structure; GraphML tests cover XML structure/escaping/empty graph and route access. No report was downloaded from or persisted into the user database during QA.

**Readiness:** READY WITH LIMITATIONS for on-demand PDF and GraphML generation; report history, arbitrary Unicode font coverage, finding lifecycle, and archived artifact management are absent.
