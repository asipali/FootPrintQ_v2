"""Pytest fixtures providing isolated test databases, clients, and configuration."""

import os
import sys
from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

# Ensure repository root is in sys.path
test_dir = Path(__file__).resolve().parent
app_dir = test_dir.parent
if str(app_dir) not in sys.path:
    sys.path.insert(0, str(app_dir))

from app.config import Settings
from app.database import Base, get_db, check_database_connection
from app.main import create_app
import app.main as main_module


@pytest.fixture(scope="session")
def test_settings(tmp_path_factory) -> Settings:
    """Provides isolated test configuration using temporary SQLite file database."""
    temp_dir = tmp_path_factory.mktemp("footprintiq_test_db")
    db_path = temp_dir / "test_footprintiq.db"
    
    return Settings(
        APP_NAME="FootprintIQ Test Suite",
        APP_VERSION="2.0.0-test",
        APP_ENV="test",
        DEBUG=True,
        DATABASE_URL=f"sqlite:///{db_path}",
        STORAGE_BACKEND="filesystem",
        EVIDENCE_STORAGE_PATH=str(temp_dir / "evidence_storage"),
        SECRET_KEY="test-secret-key-for-unit-testing-only-12345",
        LOG_LEVEL="WARNING",
        LOG_FORMAT="standard",
        DEMO_ACCOUNTS_ENABLED=False,
        GVM_HOST="",
    )


@pytest.fixture
def isolated_test_settings(test_settings: Settings, tmp_path: Path) -> Settings:
    """Settings for one test with a private evidence root below pytest's temp directory."""
    return test_settings.model_copy(
        update={"EVIDENCE_STORAGE_PATH": str(tmp_path / "evidence_storage")}
    )


@pytest.fixture(autouse=True)
def isolated_evidence_storage(
    isolated_test_settings: Settings, test_engine, monkeypatch
):
    """Route every implicit EvidenceStore construction to per-test temporary storage."""
    import app.services.evidence_store as evidence_store_module

    monkeypatch.setattr(
        evidence_store_module,
        "get_settings",
        lambda: isolated_test_settings,
    )
    monkeypatch.setattr(evidence_store_module, "_default_store", None)
    from app.config import settings as global_settings
    monkeypatch.setattr(global_settings, "GVM_HOST", None)
    # The app lifespan otherwise probes the module-global engine, which points
    # at the user's configured database. Keep even startup probes on test DB.
    monkeypatch.setattr(
        main_module,
        "check_database_connection",
        lambda target=None, engine_override=None: check_database_connection(
            target=target,
            engine_override=engine_override
            or (test_engine if target is None else None),
        ),
    )
    return Path(isolated_test_settings.EVIDENCE_STORAGE_PATH)


@pytest.fixture(scope="session")
def test_engine(test_settings: Settings):
    """Initializes isolated SQLAlchemy engine for tests."""
    engine = create_engine(
        test_settings.DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Create tables
    Base.metadata.create_all(bind=engine)
    yield engine
    # Cleanup
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine) -> Generator[Session, None, None]:
    """Provides an isolated database session rolled back after each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    SessionTest = sessionmaker(bind=connection, autocommit=False, autoflush=False)
    session = SessionTest()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(isolated_test_settings: Settings, db_session: Session) -> Generator[TestClient, None, None]:
    """TestClient configured with test settings and isolated database session override."""
    app = create_app(settings=isolated_test_settings)

    # Override get_db dependency
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    from app.core.rate_limit import auth_rate_limiter
    auth_rate_limiter.reset()

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def authenticated_client(client: TestClient, analyst_user):
    """Browser client carrying a real analyst session for protected workflows."""
    from app.core.auth import create_user_session
    from app.database import get_db
    db = next(client.app.dependency_overrides[get_db]())
    token, _ = create_user_session(db=db, user=analyst_user)
    client.cookies.set("footprintiq_session", token)
    return client


@pytest.fixture
def admin_client(client: TestClient, admin_user):
    """Browser client carrying a real administrator session."""
    from app.core.auth import create_user_session
    from app.database import get_db
    db = next(client.app.dependency_overrides[get_db]())
    token, _ = create_user_session(db=db, user=admin_user)
    client.cookies.set("footprintiq_session", token)
    return client


@pytest.fixture
def admin_user(db_session: Session):
    """Provisions a test administrator user."""
    from app.models.user import UserModel
    from app.core.security import hash_password, ROLE_ADMINISTRATOR

    user = UserModel(
        id="usr-test-admin-01",
        username="admin_test",
        email="admin@lab.example",
        password_hash=hash_password("AdminSecure123!#"),
        role=ROLE_ADMINISTRATOR,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def analyst_user(db_session: Session):
    """Provisions a test security analyst user."""
    from app.models.user import UserModel
    from app.core.security import hash_password, ROLE_ANALYST

    user = UserModel(
        id="usr-test-analyst-01",
        username="analyst_test",
        email="analyst@lab.example",
        password_hash=hash_password("AnalystSecure123!#"),
        role=ROLE_ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def viewer_user(db_session: Session):
    """Provisions a test read-only viewer user."""
    from app.models.user import UserModel
    from app.core.security import hash_password, ROLE_VIEWER

    user = UserModel(
        id="usr-test-viewer-01",
        username="viewer_test",
        email="viewer@lab.example",
        password_hash=hash_password("ViewerSecure123!#"),
        role=ROLE_VIEWER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_token(db_session: Session, admin_user) -> str:
    """Creates an active session and returns raw token for admin."""
    from app.core.auth import create_user_session
    raw_token, _ = create_user_session(db_session, admin_user)
    return raw_token


@pytest.fixture
def analyst_token(db_session: Session, analyst_user) -> str:
    """Creates an active session and returns raw token for analyst."""
    from app.core.auth import create_user_session
    raw_token, _ = create_user_session(db_session, analyst_user)
    return raw_token


@pytest.fixture
def viewer_token(db_session: Session, viewer_user) -> str:
    """Creates an active session and returns raw token for viewer."""
    from app.core.auth import create_user_session
    raw_token, _ = create_user_session(db_session, viewer_user)
    return raw_token


@pytest.fixture
def admin_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token: str) -> dict:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_headers(viewer_token: str) -> dict:
    return {"Authorization": f"Bearer {viewer_token}"}
