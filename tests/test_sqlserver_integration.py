"""Dedicated integration tests for Microsoft SQL Server 2022 Express and dual-dialect support."""

import os
import pytest
from datetime import datetime, timezone
from sqlalchemy import text
from app.database import build_engine, check_database_connection
from app.models.user import UserModel
from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.models.job import JobModel
from app.core.security import verify_password
from sqlalchemy.orm import Session

MSSQL_URL = (
    r"mssql+pyodbc://@localhost\SQLEXPRESS/footprintiq"
    r"?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
)


@pytest.fixture(scope="module")
def mssql_engine():
    """Provides an active engine bound to SQL Server 2022 Express."""
    engine = build_engine(MSSQL_URL)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    yield engine
    engine.dispose()


def test_sqlserver_connectivity_and_version(mssql_engine):
    """Verifies that SQL Server 2022 Express accepts connections and returns valid version."""
    with mssql_engine.connect() as conn:
        version = conn.execute(text("SELECT @@VERSION")).scalar()
        assert "Microsoft SQL Server 2022" in version
        assert "Express Edition" in version


def test_sqlserver_read_committed_snapshot_enabled(mssql_engine):
    """Verifies that READ_COMMITTED_SNAPSHOT is active on footprintiq database."""
    with mssql_engine.connect() as conn:
        rcsi = conn.execute(
            text("SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = 'footprintiq'")
        ).scalar()
        assert rcsi == 1


def test_sqlserver_migrated_users_and_authentication(mssql_engine):
    """Verifies that migrated user records can be retrieved and authenticated."""
    with Session(mssql_engine) as session:
        users = session.query(UserModel).all()
        assert len(users) >= 17
        admin_user = session.query(UserModel).filter(UserModel.username == "admin").first()
        if not admin_user:
            admin_user = users[0]
        assert admin_user is not None
        assert admin_user.id is not None
        assert admin_user.password_hash.startswith("$argon2")


def test_sqlserver_migrated_investigations_and_relations(mssql_engine):
    """Verifies investigations and relations in SQL Server."""
    with Session(mssql_engine) as session:
        invs = session.query(InvestigationModel).all()
        assert len(invs) >= 15
        for inv in invs:
            assert inv.id is not None
            assert inv.name is not None
            assert isinstance(inv.team_members, list)
            assert isinstance(inv.owned_domains, list)


def test_sqlserver_migrated_evidence_records(mssql_engine):
    """Verifies evidence records, storage_backend, and SHA-256 hashes in SQL Server."""
    with Session(mssql_engine) as session:
        evidence_items = session.query(EvidenceModel).all()
        assert len(evidence_items) >= 11
        seaweedfs_count = 0
        filesystem_count = 0
        for item in evidence_items:
            assert len(item.content_hash) == 64
            assert item.investigation_id is not None
            if item.storage_backend == "seaweedfs":
                seaweedfs_count += 1
                assert item.raw_content_path is not None
            elif item.storage_backend == "filesystem":
                filesystem_count += 1
            else:
                pytest.fail(f"Unexpected storage_backend '{item.storage_backend}' for item {item.id}")
        assert seaweedfs_count >= 7
        assert filesystem_count >= 4


def test_sqlserver_durable_jobs_lifecycle(mssql_engine):
    """Verifies creating, updating, and querying durable jobs in SQL Server."""
    with Session(mssql_engine) as session:
        inv = session.query(InvestigationModel).first()
        test_job = JobModel(
            id="test-mssql-job-001",
            investigation_id=inv.id,
            job_type="NMAP_SCAN",
            operation="SCAN_ACTIVE",
            target="127.0.0.1",
            parameters={"profile": "fast"},
            status="QUEUED",
            progress=0,
            requested_by="admin",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(test_job)
        session.commit()

        # Retrieve and verify
        retrieved = session.get(JobModel, "test-mssql-job-001")
        assert retrieved is not None
        assert retrieved.status == "QUEUED"
        assert retrieved.target == "127.0.0.1"

        # Clean up
        session.delete(retrieved)
        session.commit()


def test_dual_dialect_check_database_connection():
    """Verifies that check_database_connection operates across both SQLite and MSSQL."""
    sqlite_engine = build_engine("sqlite:///./footprintiq.db")
    ok, msg = check_database_connection(engine_override=sqlite_engine)
    assert ok is True

    mssql_engine = build_engine(MSSQL_URL)
    ok_ms, msg_ms = check_database_connection(engine_override=mssql_engine)
    assert ok_ms is True
