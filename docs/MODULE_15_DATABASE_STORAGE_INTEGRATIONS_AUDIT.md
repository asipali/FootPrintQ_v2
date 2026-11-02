# Module 15 — Database, Storage and Integrations Audit

**Date:** 2026-11-02  
**Scope:** Database, migrations, evidence/report storage, recovery, and configured external integrations. The pre-change baseline is in [Group 6 Baseline Report](GROUP_6_BASELINE_REPORT.md).

## Executive result

The running application uses SQLite through SQLAlchemy. The live database is at Alembic head `0007_investigation_ownership`; SQLite integrity and FK checks pass. Fresh isolated migration upgrade, downgrade to base, and upgrade to head pass. Five evidence rows reference files and all five files match their stored SHA-256 and byte length; four other rows have no raw content path. Storage is local filesystem only. There is no SeaweedFS adapter and no supported combined backup/restore procedure for the database and evidence.

## Database architecture and integrity

- Configuration comes from typed `Settings.DATABASE_URL`; default development URL is SQLite. `build_engine` uses SQLAlchemy `create_engine`, `pool_pre_ping=True`, SQLite `check_same_thread=False`, WAL, `synchronous=NORMAL`, and `PRAGMA foreign_keys=ON`. Sessions are request-scoped, closed in `finally`, and rolled back on exceptions. Pool sizing/timeouts are not tuned.
- Runtime engine verified: SQLite. The project manifest does not declare a PostgreSQL driver, so PostgreSQL is not verified or currently supported by the packaged installation. SQL Server is not supported.
- Models cover users/sessions, investigations, authorizations, collection jobs, evidence, entities, Nmap jobs/results, vulnerability jobs/findings, and audit logs. Constraints and indexes are maintained in Alembic revisions `0001`–`0007`. Unique user constraints are now explicit in model metadata to match the migration schema.
- Live read-only snapshot: 15 investigations, 9 evidence records, 17 entities, 7 active scan jobs, 15 target authorizations; `PRAGMA integrity_check=ok`; `PRAGMA foreign_key_check` returned zero violations. No row mutation was used for audit verification.
- Fresh temporary SQLite database: migration upgrade to head, downgrade to base, and re-upgrade to head all succeeded; final integrity check was `ok`. `alembic check` still reports only the two self-referential user FKs as remove/add differences even though fresh SQLite `PRAGMA foreign_key_list(users)` confirms both use `ON DELETE SET NULL`. This is a SQLite/Alembic comparison limitation, not a missing runtime FK action.
- The backup file `footprintiq.db.backup` is readable and passes SQLite integrity, but it is at older revision `0007_add_reporting_and_scoring` and contains one investigation and no evidence rows. It is not a current full-system recovery point. No restore was performed over live data.

## Storage and consistency

- Runtime evidence backend is `EvidenceStore` on local filesystem under `EVIDENCE_STORAGE_PATH`. It creates safe investigation/file names, prevents path escape and overwrite, records SHA-256/size, and verifies hash on reads. Owner-scoped download handlers authorize investigation access.
- Of 9 current evidence records, 5 reference raw files; all referenced files were present and matched recorded hash and size. Four rows have no raw-content path and therefore have no raw file to verify. No path escaped the storage root.
- No SeaweedFS configuration, dependency, adapter, or live service verification exists. No generic upload endpoint was found. There is no transaction spanning evidence-file writes and DB commit, so a later database failure can leave an orphan file. No configured upload-size policy was found.
- Reports are generated on demand (PDF/GraphML) and streamed; report artifacts and report history are not persisted. Tests cover generation/download paths, not a stored report retrieval lifecycle.
- No supported backup utility or documented restore procedure was found. The old database-only backup omits file storage and is stale. Database and evidence backups, retention, encryption, offsite copies, and isolated restore drills remain required before production use.

## Integrations

| Integration | Verification | Result |
| --- | --- | --- |
| Nmap | Previous Module 08 controlled run against authorized `127.0.0.1`; current regression tests cover runner/parser/API behavior. | Local integration verified previously; no new scan launched in this audit. |
| Greenbone/OpenVAS | Configuration inspection and existing client tests. No configured endpoint/account or reachable service. | `NOT_CONFIGURED`; no live task or report verification. |
| Passive DNS/RDAP/certificate-transparency providers | Existing collector tests use controlled mocks; no external target was queried for this audit. | Mocked behavior only, no live-provider claim. |
| theHarvester | Executable/provider unavailable; missing-binary behavior is tested. | Blocked. |
| SeaweedFS | No integration implementation/configuration found. | Not implemented/configured. |

Timeout/error handling is implemented for collector and scan paths, but no durable worker queue exists; jobs use in-process background tasks and do not recover across restart.

## Defects and fixes

| ID | Severity | Finding and change | Verification |
| --- | --- | --- | --- |
| G6-15-01 | P2 | User model metadata omitted the named unique constraints present in migration `0002`; added explicit metadata constraints without changing the database. | Fresh migration cycle and model/schema inspection; `alembic check` no longer reports uniqueness drift. |
| G6-15-02 | P1 operational | No current combined backup/restore workflow; existing database-only backup is stale and has no evidence. No restore implementation was invented during audit. | Read-only integrity/revision/count check; limitation recorded. |
| G6-15-03 | P2 | Filesystem evidence and DB records are not committed atomically; orphan files remain possible on a later DB failure. | Source review; no destructive failure simulation against user data. |
| G6-15-04 | P2 | SeaweedFS and persisted report artifacts are absent. | Source/configuration review. |

## Tests and remaining limitations

Full suite results are in the Module 16 report. Migration lifecycle was verified only against a temporary SQLite file. Live PostgreSQL, SeaweedFS, Greenbone, passive external providers, full backup recovery, database restart failover, and durable job recovery remain unverified or unavailable.
