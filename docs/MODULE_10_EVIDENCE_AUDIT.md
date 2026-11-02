# Module 10 — Evidence Management Audit

**Verified:** 2026-11-02. Scope: evidence model, ingestion/storage, retrieval, UI, and direct cross-module evidence links. No production evidence or database records were changed.

## Implemented flow

- `EvidenceModel` (`app/models/recon.py`, table `evidence`) stores investigation ID, optional collection job ID, source type/name, target, collection status, optional relative raw path, SHA-256, byte length, source metadata, and collection timestamp.
- `EvidenceStore` (`app/services/evidence_store.py`) stores UTF-8 text, bytes, or JSON-serialized dict/list values under `<EVIDENCE_STORAGE_PATH>/<sanitized-investigation-id>/`; the database stores a relative POSIX path. SHA-256 is calculated over the exact stored bytes. Reads reject paths outside the storage root and return bytes plus a calculated digest.
- Passive collectors store raw provider payloads through the passive orchestrator. Nmap stores original XML and links the evidence row through `active_scan_jobs.evidence_id`. Greenbone stores report XML and links via `vuln_scan_jobs.evidence_id`. Greenbone evidence job provenance also appears in source metadata because `evidence.job_id` has a foreign key only to `collection_jobs`.
- Raw retrieval routes: `/api/v1/investigations/{investigation_id}/evidence/{evidence_id}/raw`, `/api/v1/nmap-scans/{job_id}/xml` (route prefix as registered), and `/api/v1/vulnerability-assessments/{job_id}/report`. They enforce investigation access and compare calculated bytes to the database digest before responding.
- The browser ledger is `/evidence`; it now requires login and limits entries to accessible investigations. It accurately describes hashes as retrieval-time integrity checks, not immutable storage.

## Audit findings and fixes

| ID | Priority | Finding and root cause | Fix / verification |
|---|---|---|---|
| E10-1 | P1 | `/evidence` showed cross-investigation records and accepted unauthenticated requests. | Login gate and owner/admin investigation subquery. Regression verifies redirects and that an unowned record is absent from an analyst’s ledger. |
| E10-2 | P2 | Evidence IDs mapped to deterministic filenames, and `write_bytes` silently replaced existing bytes on accidental ID reuse. | Storage now opens with exclusive-create semantics and raises `FileExistsError`; regression confirms original content and digest remain intact. |
| E10-3 | P2 | Ledger copy called records “cryptographically sealed, immutable”; files and database rows are not WORM or independently protected from a privileged actor. | Copy now states the hash is checked when retrieved. PDF caveat likewise distinguishes digest checking from immutability. |
| E10-4 | P2 | Evidence job relationship is only a nullable FK to `collection_jobs`; active and GVM evidence cannot use it as a generic job reference. | Documented as a schema limitation; their job association is maintained on scanner jobs and/or source metadata. No migration was necessary for this audit. |

## Integrity and data baseline

At read-only baseline: 7 evidence rows; 3 non-null raw paths, all three files existed and matched stored SHA-256 and byte length; zero unsafe paths. Four rows have null raw path, which is supported by the nullable schema; these are metadata-only records and raw retrieval returns 404. The baseline database had no foreign-key violations. No evidence deletion or repair was performed.

Hashes detect content changes only when checked against a trusted stored digest. They do not prevent coordinated changes to both file and database hash. The store has no configured payload-size cap, retention/deletion workflow, atomic multi-file/database transaction, or independent immutable archive. It serializes arbitrary Python dict/list input as JSON; semantic schema validation is source-specific rather than centralized. These are open P2/P3 hardening items, not claims of implemented behavior.

## Verification

- `tests/test_evidence_storage.py`: path traversal, missing file, byte/hash round trip, and reused-key no-overwrite behavior.
- `tests/test_module10_12_regressions.py`: authenticated/owner-scoped page behavior and unauthenticated redirects.
- Existing passive, Nmap, Greenbone, and raw evidence endpoint tests exercise fixture/mock ingestion and digest checks. No external passive provider or live GVM service was contacted for this audit.

## Remaining limits

Evidence rows do not have generic foreign-key relationships to vulnerability findings; `VulnerabilityFindingModel.evidence_id` is a nullable string. Entity provenance uses a JSON list of evidence IDs. Deleting an evidence row can therefore leave dangling provenance references (no deletion UI is currently provided). Raw-file cleanup on database cascade is not implemented. Evidence is locally persisted on the configured filesystem; backup, permissions, retention, and disk-capacity policy belong to deployment operations.
