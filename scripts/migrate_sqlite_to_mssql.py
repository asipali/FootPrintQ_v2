"""Safe, non-destructive, transactionally verified SQLite to SQL Server 2022 Express migration pipeline.

Features:
- Source SQLite opened in strictly read-only mode. Zero mutations to source files.
- Pre-flight validation ensuring target database is empty.
- Topological insertion respecting all foreign key dependencies.
- Automatic type casting (ISO-8601 strings to datetime, ints to booleans, JSON strings).
- Row-level and table-level SHA-256 deterministic checksum verification.
- Comprehensive referential integrity & business logic verification.
- Zero sensitive data exposure in logs.
"""

import sys
import json
import struct
import hashlib
import sqlite3
from datetime import datetime, timezone, timedelta
import pyodbc
from typing import Dict, Any, List, Tuple


SQLITE_PATH = "footprintiq.db"
MSSQL_CONN_STR = (
    r"DRIVER={ODBC Driver 17 for SQL Server};"
    r"SERVER=localhost\SQLEXPRESS;"
    r"DATABASE=footprintiq;"
    r"Trusted_Connection=yes;"
)

# Ordered topological table sequence
TABLES_IN_ORDER = [
    "users",
    "user_sessions",
    "audit_logs",
    "investigations",
    "target_authorizations",
    "collection_jobs",
    "evidence",
    "entities",
    "active_scan_jobs",
    "scan_hosts",
    "scan_ports",
    "vuln_scan_jobs",
    "vuln_findings",
    "jobs",
]


def canonical_repr(val: Any) -> Any:
    """Normalizes scalar value for deterministic hashing."""
    if val is None:
        return None
    if isinstance(val, (datetime,)):
        # Normalize to UTC ISO string
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        else:
            val = val.astimezone(timezone.utc)
        return val.isoformat()
    if isinstance(val, (int, float, bool)):
        if isinstance(val, float):
            return round(val, 4)
        return val
    # If string is valid JSON object or array, parse and re-dump canonical sorted JSON
    if isinstance(val, str):
        val_str = val.strip()
        if (val_str.startswith("{") and val_str.endswith("}")) or (val_str.startswith("[") and val_str.endswith("]")):
            try:
                parsed = json.loads(val_str)
                return json.dumps(parsed, sort_keys=True)
            except Exception:
                pass
        # Check if ISO datetime string
        if len(val_str) >= 10 and val_str[4] == "-":
            try:
                # normalize space to T
                normalized_dt = val_str.replace(" ", "T")
                dt = datetime.fromisoformat(normalized_dt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                return dt.isoformat()
            except Exception:
                pass
        return val
    return str(val)


BOOLEAN_COLS = {
    "is_active",
    "is_revoked",
    "active_scanning_enabled",
    "cancellation_requested",
}


def compute_table_checksum(rows: List[Dict[str, Any]], columns: List[str] = None, primary_key: str = "id") -> Tuple[str, List[str]]:
    """Computes row-level and aggregated SHA-256 table checksum over target schema columns."""
    sorted_rows = sorted(rows, key=lambda r: str(r.get(primary_key, "")))
    row_checksums = []
    hasher = hashlib.sha256()

    for r in sorted_rows:
        canonical_row = {}
        keys = sorted(columns) if columns else sorted(r.keys())
        for k in keys:
            if k not in r:
                continue
            v = r[k]
            if k in BOOLEAN_COLS and v is not None:
                v = bool(v)
            canonical_row[k] = canonical_repr(v)
        canonical_bytes = json.dumps(canonical_row, sort_keys=True, default=str).encode("utf-8")
        row_hash = hashlib.sha256(canonical_bytes).hexdigest()
        row_checksums.append(row_hash)
        hasher.update(row_hash.encode("utf-8"))

    return hasher.hexdigest(), row_checksums


def main():
    print("=" * 70)
    print("FOOTPRINTIQ: SQLite to SQL Server 2022 Express Migration Pipeline")
    print("=" * 70)

    # 1. Open SQLite strictly read-only
    print(f"\n[1/6] Opening source SQLite database: {SQLITE_PATH} (uri=file:...mode=ro)")
    sqlite_uri = f"file:{SQLITE_PATH}?mode=ro"
    try:
        sqlite_conn = sqlite3.connect(sqlite_uri, uri=True)
        sqlite_conn.row_factory = sqlite3.Row
    except Exception as exc:
        print(f"FATAL: Unable to open SQLite in read-only mode: {exc}")
        sys.exit(1)

    # 2. Connect to SQL Server
    print("[2/6] Connecting to target Microsoft SQL Server 2022 Express...")
    try:
        mssql_conn = pyodbc.connect(MSSQL_CONN_STR, autocommit=False)
        # Register converter for SQL_SS_TIMESTAMPOFFSET (-155)
        def _handle_datetimeoffset(dto_value):
            if isinstance(dto_value, bytes):
                tup = struct.unpack("<6hI2h", dto_value)
                return datetime(
                    tup[0], tup[1], tup[2], tup[3], tup[4], tup[5], tup[6] // 1000,
                    timezone(timedelta(hours=tup[7], minutes=tup[8]))
                )
            return dto_value
        mssql_conn.add_output_converter(-155, _handle_datetimeoffset)
    except Exception as exc:
        print(f"FATAL: Unable to connect to SQL Server: {exc}")
        sqlite_conn.close()
        sys.exit(1)

    mssql_cursor = mssql_conn.cursor()

    # Pre-flight check: Target tables must have 0 rows
    print("\n[3/6] Pre-flight Check: Verifying target database is empty...")
    if "--clean-target" in sys.argv:
        print("  -> Flag --clean-target detected. Purging target tables in reverse topological order...")
        for table in reversed(TABLES_IN_ORDER):
            mssql_cursor.execute(f"ALTER TABLE [{table}] NOCHECK CONSTRAINT ALL")
        for table in reversed(TABLES_IN_ORDER):
            mssql_cursor.execute(f"DELETE FROM [{table}]")
        for table in reversed(TABLES_IN_ORDER):
            mssql_cursor.execute(f"ALTER TABLE [{table}] WITH CHECK CHECK CONSTRAINT ALL")
        mssql_conn.commit()
        print("  -> Target tables purged cleanly.")

    for table in TABLES_IN_ORDER:
        mssql_cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
        count = mssql_cursor.fetchone()[0]
        if count > 0:
            print(f"FATAL: Target table [{table}] already contains {count} rows! Pass --clean-target if re-running migration.")
            mssql_conn.close()
            sqlite_conn.close()
            sys.exit(1)
    print("Pre-flight check PASSED: Target tables are 100% empty.")

    # 3. Read and migrate each table in topological order
    print("\n[4/6] Executing Topological Bulk Migration...")
    migration_summary = {}

    try:
        # Disable foreign key checking during bulk loading to prevent order-dependency issues on self-referential rows
        for table in TABLES_IN_ORDER:
            mssql_cursor.execute(f"ALTER TABLE [{table}] NOCHECK CONSTRAINT ALL")

        for table in TABLES_IN_ORDER:
            # Read from SQLite
            sqlite_cursor = sqlite_conn.cursor()
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table,))
            if not sqlite_cursor.fetchone():
                print(f"  -> Table [{table}]: Not present in source SQLite schema (0 rows migrated).")
                migration_summary[table] = {
                    "source_count": 0,
                    "target_count": 0,
                    "checksum_match": True,
                    "source_checksum": "NOT_IN_SOURCE",
                    "target_checksum": "EMPTY",
                }
                continue

            sqlite_cursor.execute(f"SELECT * FROM [{table}]")
            sqlite_rows = [dict(row) for row in sqlite_cursor.fetchall()]
            row_count = len(sqlite_rows)

            if row_count == 0:
                print(f"  -> Table [{table}]: 0 rows (skipped)")
                migration_summary[table] = {
                    "source_count": 0,
                    "target_count": 0,
                    "checksum_match": True,
                    "source_checksum": "EMPTY",
                    "target_checksum": "EMPTY",
                }
                continue

            # Get target column names
            mssql_cursor.execute(f"SELECT TOP 0 * FROM [{table}]")
            target_cols = [desc[0] for desc in mssql_cursor.description]
            common_cols = [col for col in sqlite_rows[0].keys() if col in target_cols]

            # Prepare insert statement
            col_names = ", ".join(f"[{c}]" for c in common_cols)
            placeholders = ", ".join("?" for _ in common_cols)
            insert_sql = f"INSERT INTO [{table}] ({col_names}) VALUES ({placeholders})"

            # Transform row values
            batch_data = []
            for r in sqlite_rows:
                row_vals = []
                for c in common_cols:
                    val = r[c]
                    # Parse ISO dates if column contains dates to native datetime
                    if isinstance(val, str) and ("_at" in c or c in ("valid_from", "valid_to", "timestamp", "first_seen", "last_seen", "lease_expires_at", "heartbeat_at", "expires_at", "last_accessed_at", "password_changed_at", "approved_at", "rejected_at", "locked_until", "last_login_at", "authorization_expiry")):
                        try:
                            norm_val = val.replace(" ", "T")
                            dt = datetime.fromisoformat(norm_val)
                            val = dt.replace(tzinfo=None)
                        except Exception:
                            pass
                    row_vals.append(val)
                batch_data.append(tuple(row_vals))

            # Execute batch insert
            mssql_cursor.fast_executemany = True
            mssql_cursor.executemany(insert_sql, batch_data)

            # Normalize all datetimeoffset columns to UTC (+00:00) using TODATETIMEOFFSET
            mssql_cursor.execute("""
                SELECT c.name FROM sys.columns c
                JOIN sys.types t ON c.user_type_id = t.user_type_id
                WHERE c.object_id = OBJECT_ID(?) AND t.name = 'datetimeoffset'
            """, (table,))
            dto_cols = [r[0] for r in mssql_cursor.fetchall()]
            for dto_c in dto_cols:
                mssql_cursor.execute(f"UPDATE [{table}] SET [{dto_c}] = TODATETIMEOFFSET([{dto_c}], '+00:00') WHERE [{dto_c}] IS NOT NULL")

            print(f"  -> Table [{table}]: Migrated {row_count} rows successfully.")

        # Re-enable foreign key checking and validate constraints
        for table in TABLES_IN_ORDER:
            mssql_cursor.execute(f"ALTER TABLE [{table}] WITH CHECK CHECK CONSTRAINT ALL")

        # Commit target transaction
        mssql_conn.commit()
        print("\nAll tables committed to SQL Server successfully.")

    except Exception as exc:
        mssql_conn.rollback()
        print(f"\nFATAL: Migration transaction failed: {exc}. Target database rolled back.")
        mssql_conn.close()
        sqlite_conn.close()
        sys.exit(1)

    # 4. Data Reconciliation & SHA-256 Checksum Verification
    print("\n[5/6] Verifying Record Counts and SHA-256 Deterministic Checksums...")
    all_checksums_match = True

    for table in TABLES_IN_ORDER:
        # MSSQL rows and schema columns
        mssql_cursor.execute(f"SELECT * FROM [{table}]")
        cols = [d[0] for d in mssql_cursor.description]
        m_rows = [dict(zip(cols, row)) for row in mssql_cursor.fetchall()]

        # SQLite rows
        sqlite_cursor = sqlite_conn.cursor()
        sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table,))
        if not sqlite_cursor.fetchone():
            s_rows = []
            s_chk = "NOT_IN_SOURCE"
        else:
            sqlite_cursor.execute(f"SELECT * FROM [{table}]")
            s_rows = [dict(r) for r in sqlite_cursor.fetchall()]
            s_chk, _ = compute_table_checksum(s_rows, columns=cols)

        m_chk, _ = compute_table_checksum(m_rows, columns=cols)

        if s_chk == "NOT_IN_SOURCE":
            matched = (len(m_rows) == 0)
        else:
            matched = (len(s_rows) == len(m_rows)) and (s_chk == m_chk)

        if not matched:
            all_checksums_match = False

        status_icon = "MATCH" if matched else "MISMATCH"
        print(f"  [{status_icon}] {table:<25} SQLite: {len(s_rows):<4} MSSQL: {len(m_rows):<4} Checksum: {s_chk[:12]}... == {m_chk[:12]}...")

        migration_summary[table] = {
            "source_count": len(s_rows),
            "target_count": len(m_rows),
            "source_checksum": s_chk,
            "target_checksum": m_chk,
            "checksum_match": matched,
        }

    # 5. Referential Integrity & Business Logic Checks
    print("\n[6/6] Executing Deep Business Logic & Referential Integrity Verification...")
    integrity_checks = []

    # Check 1: User authentication integrity
    mssql_cursor.execute("SELECT count(*), count(distinct username), count(distinct email) FROM users")
    u_count, u_usernames, u_emails = mssql_cursor.fetchone()
    u_ok = (u_count == u_usernames == u_emails) and u_count > 0
    integrity_checks.append(("User Uniqueness & Identity Count", u_ok, f"Count={u_count}, Unique Usernames={u_usernames}, Unique Emails={u_emails}"))

    # Check 2: User sessions valid user_id
    mssql_cursor.execute("""
        SELECT count(*) FROM user_sessions s
        LEFT JOIN users u ON s.user_id = u.id
        WHERE u.id IS NULL
    """)
    orphaned_sessions = mssql_cursor.fetchone()[0]
    integrity_checks.append(("User Session Foreign Key Integrity", orphaned_sessions == 0, f"Orphaned sessions={orphaned_sessions}"))

    # Check 3: Investigation ownership foreign key
    mssql_cursor.execute("""
        SELECT count(*) FROM investigations i
        LEFT JOIN users u ON i.owner_user_id = u.id
        WHERE i.owner_user_id IS NOT NULL AND u.id IS NULL
    """)
    orphaned_inv_owners = mssql_cursor.fetchone()[0]
    integrity_checks.append(("Investigation Owner Foreign Key Integrity", orphaned_inv_owners == 0, f"Orphaned investigation owners={orphaned_inv_owners}"))

    # Check 4: Target authorizations foreign key
    mssql_cursor.execute("""
        SELECT count(*) FROM target_authorizations ta
        LEFT JOIN investigations i ON ta.investigation_id = i.id
        WHERE i.id IS NULL
    """)
    orphaned_auths = mssql_cursor.fetchone()[0]
    integrity_checks.append(("Target Authorization Foreign Key Integrity", orphaned_auths == 0, f"Orphaned authorizations={orphaned_auths}"))

    # Check 5: Evidence foreign key
    mssql_cursor.execute("""
        SELECT count(*) FROM evidence e
        LEFT JOIN investigations i ON e.investigation_id = i.id
        WHERE i.id IS NULL
    """)
    orphaned_evidence = mssql_cursor.fetchone()[0]
    integrity_checks.append(("Evidence Foreign Key Integrity", orphaned_evidence == 0, f"Orphaned evidence records={orphaned_evidence}"))

    # Check 6: Active scan jobs & scan hosts/ports integrity
    mssql_cursor.execute("""
        SELECT count(*) FROM scan_hosts sh
        LEFT JOIN active_scan_jobs aj ON sh.job_id = aj.id
        WHERE aj.id IS NULL
    """)
    orphaned_hosts = mssql_cursor.fetchone()[0]
    integrity_checks.append(("Scan Hosts Foreign Key Integrity", orphaned_hosts == 0, f"Orphaned scan hosts={orphaned_hosts}"))

    # Check 7: Vuln scan jobs & findings integrity
    mssql_cursor.execute("""
        SELECT count(*) FROM vuln_findings vf
        LEFT JOIN vuln_scan_jobs vj ON vf.job_id = vj.id
        WHERE vj.id IS NULL
    """)
    orphaned_vulns = mssql_cursor.fetchone()[0]
    integrity_checks.append(("Vuln Findings Foreign Key Integrity", orphaned_vulns == 0, f"Orphaned vuln findings={orphaned_vulns}"))

    # Check 8: Audit log records
    mssql_cursor.execute("SELECT count(*) FROM audit_logs WHERE event_type IS NOT NULL")
    audit_count = mssql_cursor.fetchone()[0]
    integrity_checks.append(("Audit Log Population", audit_count > 0, f"Total audit events={audit_count}"))

    for name, status, details in integrity_checks:
        status_text = "PASS" if status else "FAIL"
        print(f"  [{status_text}] {name}: {details}")

    all_integrity_passed = all(status for _, status, _ in integrity_checks)

    # Save migration results to temporary json for report generation
    results_payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "all_checksums_match": all_checksums_match,
        "all_integrity_passed": all_integrity_passed,
        "tables": migration_summary,
        "integrity_checks": [
            {"check": name, "passed": status, "details": details}
            for name, status, details in integrity_checks
        ],
    }

    with open(".data/migration_results.json", "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2)

    sqlite_conn.close()
    mssql_conn.close()

    print("\n" + "=" * 70)
    if all_checksums_match and all_integrity_passed:
        print("MIGRATION COMPLETED SUCCESSFULLY WITH 100% PARITY AND INTEGRITY.")
    else:
        print("MIGRATION FINISHED WITH WARNINGS OR DISCREPANCIES.")
    print("=" * 70)


if __name__ == "__main__":
    main()
