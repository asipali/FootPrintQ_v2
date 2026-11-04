import pathlib
from sqlalchemy import create_engine

def test_backup():
    p = pathlib.Path(".data/backups/sqlserver_test").resolve()
    p.mkdir(parents=True, exist_ok=True)
    bak_file = p / "test.bak"

    MSSQL_URL = "mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes&autocommit=True"
    engine = create_engine(MSSQL_URL)

    with engine.connect() as conn:
        raw_conn = conn.connection
        cursor = raw_conn.cursor()
        sql_str = f"BACKUP DATABASE [footprintiq] TO DISK = '{bak_file}' WITH INIT, CHECKSUM, STATS = 10"
        print("Executing SQL:", sql_str)
        cursor.execute(sql_str)
        while cursor.nextset():
            pass
        print("Backup command executed successfully!")

        # Verify
        verify_str = f"RESTORE VERIFYONLY FROM DISK = '{bak_file}' WITH CHECKSUM"
        cursor.execute(verify_str)
        while cursor.nextset():
            pass
        print("Restore verifyonly executed successfully!")

    print("Checking file on disk:", bak_file.exists(), "Size:", bak_file.stat().st_size if bak_file.exists() else 0)
    if bak_file.exists():
        bak_file.unlink()
        print("Cleaned up probe test file.")

if __name__ == "__main__":
    test_backup()

