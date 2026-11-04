"""Provision Microsoft SQL Server 2022 Express database for FootprintIQ with READ_COMMITTED_SNAPSHOT."""

import sys
import pyodbc

SERVER = r"localhost\SQLEXPRESS"
DB_NAME = "footprintiq"
DRIVER = "{ODBC Driver 17 for SQL Server}"


def provision_database():
    print(f"Connecting to {SERVER} (master) using Windows Authentication...")
    conn_str = f"DRIVER={DRIVER};SERVER={SERVER};DATABASE=master;Trusted_Connection=yes;"
    
    try:
        conn = pyodbc.connect(conn_str, autocommit=True)
    except Exception as exc:
        print(f"ERROR: Failed to connect to SQL Server master: {exc}")
        sys.exit(1)

    cursor = conn.cursor()
    cursor.execute("SELECT name, is_read_committed_snapshot_on FROM sys.databases WHERE name = ?", (DB_NAME,))
    existing = cursor.fetchone()

    if existing:
        rcsi_on = bool(existing[1])
        print(f"Database '{DB_NAME}' already exists (READ_COMMITTED_SNAPSHOT: {rcsi_on}).")
        # Check if it contains any user tables
        cursor.execute(f"USE [{DB_NAME}]")
        cursor.execute("SELECT count(*) FROM sys.tables WHERE is_ms_shipped = 0")
        table_count = cursor.fetchone()[0]
        if table_count > 0:
            print(f"WARNING: Database '{DB_NAME}' already contains {table_count} user tables!")
        else:
            print(f"Database '{DB_NAME}' is empty (0 user tables). Ready for migration.")
    else:
        print(f"Database '{DB_NAME}' does not exist. Creating database...")
        cursor.execute(f"CREATE DATABASE [{DB_NAME}]")
        print(f"Database '{DB_NAME}' created successfully.")
        
        print("Enabling READ_COMMITTED_SNAPSHOT for high-concurrency non-blocking reads...")
        cursor.execute(f"ALTER DATABASE [{DB_NAME}] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE")
        print("READ_COMMITTED_SNAPSHOT enabled.")

    # Verify final state
    cursor.execute("SELECT name, is_read_committed_snapshot_on, state_desc FROM sys.databases WHERE name = ?", (DB_NAME,))
    row = cursor.fetchone()
    print(f"Verification: DB={row[0]}, RCS_ENABLED={bool(row[1])}, STATE={row[2]}")
    conn.close()


if __name__ == "__main__":
    provision_database()

