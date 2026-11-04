import os
from sqlalchemy import create_engine, text

db_url = os.getenv('DATABASE_URL', 'mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes')
engine = create_engine(db_url)
with engine.connect() as conn:
    print('COLUMNS IN investigations:')
    for r in conn.execute(text("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='investigations'")):
        print(' ', r[0])
    print('\nCOLUMNS IN target_authorizations:')
    for r in conn.execute(text("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='target_authorizations'")):
        print(' ', r[0])

    print('\n=== INVESTIGATION RECORD ===')
    r = conn.execute(text("SELECT * FROM investigations WHERE id = 'inv-0fabf5f0690244e089b55661a273ee8a'")).fetchone()
    if r:
        print(dict(r._mapping))
    else:
        print('Investigation inv-0fabf5f0690244e089b55661a273ee8a not found!')

    print('\n=== TARGET AUTHORIZATIONS RECORDS ===')
    rows = conn.execute(text("SELECT * FROM target_authorizations WHERE investigation_id = 'inv-0fabf5f0690244e089b55661a273ee8a'")).fetchall()
    for row in rows:
        print(dict(row._mapping))

