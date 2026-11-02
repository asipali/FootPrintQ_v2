# Module 05 — Investigation Management Audit

**Date:** 2026-11-02  
**Result:** PASS WITH DATA MIGRATION / LEGACY LIMITATION

## Scope and evidence

Reviewed the investigation model/schema, REST and dashboard routes, access control, report/export handlers, migration history, and tests. The feature supports create, list, detail, update, completion/archive, scoped dashboard views, and exports. It has no destructive delete operation; archive is the close action.

## Findings fixed

- Investigations had no owner; all records could be read by users with view permission. Added nullable `owner_user_id`, owner/admin access enforcement, owner-filtered lists/dashboard metrics, and ownership checks on detail/PDF/GraphML paths.
- Added PATCH update with validated status transitions, audit logging, and administrator-only reassignment to active approved accounts. Archived records are immutable.
- Creation now assigns the authenticated account as owner and identity as lead, avoiding client-supplied lead spoofing. Scope values are normalized and type-checked. Duplicate identifiers produce conflict responses.
- REST writes use CSRF protection. Dashboard writes and report exports enforce ownership/permissions.
- Database migration `0007_investigation_ownership` adds nullable FK/index and backfills only a unique username/full-name match. No investigation or authorization rows were deleted or rewritten beyond owner attribution.

## Migration and data preservation

A SQLite backup was made before migration at `.data/backups/footprintiq-pre-module05-06-20261102-115349.db`. Before migration: 17 users, 15 investigations, 14 target authorization records. After migration: counts unchanged; 6 investigations have resolved owners and 9 remain unowned because identity matches were ambiguous or absent. Unowned historical records are admin-only until an administrator assigns an owner. `PRAGMA foreign_key_check` returned no violations.

## Verification

Full suite: **217 passed, 0 failed, 20 warnings** (`DEBUG=false`; test evidence isolated under the OS temp directory). Coverage includes owner isolation, API update/archive, access denial, exports, dashboard behavior, scope validation, and migrations. Local app health/API checks are recorded in the integration report.

## Remaining limitation

Some legacy records are intentionally unowned; ordinary investigators cannot access them until an administrator reassigns them. Downstream scan/evidence read-by-job endpoints outside Modules 05/06 need a separate owner-boundary audit.
