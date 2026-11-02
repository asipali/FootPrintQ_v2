# Module 06 — Target Authorization Management Audit

**Date:** 2026-11-02  
**Result:** PASS WITH OPERATIONAL LIMITATIONS

## Scope and findings fixed

Reviewed authorization model, schemas, REST/web routes, validation service and recon/scan execution call sites. Authorization writes now validate target syntax/type, investigation scope, canonical operation identifiers, reference text and future validity window. REST mutations require CSRF protection; actor identity is taken from the authenticated account. Listing, update and revoke are investigation-owner/admin scoped and audited.

The validation endpoint request/response mismatch was corrected. Authorization checks now require: an active owned/admin-accessible investigation; an explicit exact target (or target contained by an explicit CIDR); matching permitted operation; valid non-revoked time window; and actor role permission. Campaign-level authorization references are descriptive only. Domain authorization does not imply permission on subdomains. Expiration is invalid at `now >= valid_to`.

## Verification

Full suite: **217 passed, 0 failed, 20 warnings**, including Module 06 create/update/revoke, target type/scope/operation/date validation, expiry/revocation behavior, cross-investigation denial and API validation shape. No active scanner or external provider was run.

## Limitations

Active Nmap and Greenbone availability remains deployment-dependent. Existing downstream job/evidence retrieval routes require a separate ownership review. No live target was scanned. Campaign-wide legacy authorization references no longer grant an operation; explicit target authorization records are required.
