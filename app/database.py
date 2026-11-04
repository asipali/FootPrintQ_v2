"""SQLAlchemy 2.x database connectivity, session factory, and SQLite tuning."""

from typing import Generator
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from app.config import get_settings
from app.logging_config import get_logger

logger = get_logger("footprintiq.database")


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""
    pass


def build_engine(database_url: str):
    """Builds an engine configured specifically for the target database dialect."""
    connect_args = {}
    is_sqlite = database_url.startswith("sqlite")
    is_mssql = database_url.startswith("mssql")

    if is_sqlite:
        # SQLite needs check_same_thread=False for async FastAPI request thread pools
        connect_args["check_same_thread"] = False
        engine = create_engine(
            database_url,
            connect_args=connect_args,
            pool_pre_ping=True,  # Proactively test dead connections
            echo=False
        )

        # Enforce foreign key constraints and Write-Ahead Logging (WAL) in SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        return engine

    elif is_mssql:
        # Microsoft SQL Server 2022 Express engine with fast_executemany and pool pre-ping
        engine = create_engine(
            database_url,
            fast_executemany=True,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=1800,
            echo=False
        )
        return engine

    return create_engine(database_url, pool_pre_ping=True, echo=False)


# Centralized engine and sessionmaker
from app.core.db_retry import is_deadlock_error, retry_on_deadlock, run_with_deadlock_retry

settings = get_settings()


def init_engine(target_settings=None) -> Engine:
    """Initializes and returns configured database engine with strict production guards."""
    cfg = target_settings or get_settings()
    is_production_or_staging = cfg.APP_ENV in {"staging", "production"}

    try:
        eng = build_engine(cfg.DATABASE_URL)
        # In staging/production or when non-sqlite, proactively probe database
        if is_production_or_staging or not cfg.is_sqlite:
            with eng.connect() as probe_conn:
                probe_conn.execute(text("SELECT 1"))
        return eng
    except Exception as exc:
        # Strictly forbid fallback in staging and production to prevent split-brain state
        if is_production_or_staging or not getattr(cfg, "DB_FALLBACK_TO_SQLITE", False):
            logger.critical(
                "Primary database connection to %s failed in %s environment: %s. SQLite fallback is locked out.",
                cfg.DATABASE_URL.split("@")[-1] if "@" in cfg.DATABASE_URL else "relational",
                cfg.APP_ENV,
                exc,
            )
            raise RuntimeError(
                f"Database connection failed in {cfg.APP_ENV} environment: {exc}. "
                "SQLite fallback is strictly forbidden in staging/production."
            ) from exc

        logger.warning(
            "Primary database connection failed: %s. Falling back to local SQLite in %s environment.",
            exc,
            cfg.APP_ENV,
        )
        return build_engine("sqlite:///./footprintiq.db")


try:
    engine = init_engine(settings)
except Exception:
    # If during import in staging/production, keep engine as None or re-raise if not in test
    if settings.APP_ENV in {"staging", "production"}:
        raise
    engine = build_engine("sqlite:///./footprintiq.db")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


from contextlib import contextmanager


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency providing a transactional database session per request."""
    session = SessionLocal()
    try:
        yield session
    except Exception as exc:
        session.rollback()
        logger.error("Database session rolled back due to %s", type(exc).__name__)
        raise
    finally:
        session.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Context manager providing a transactional database session for background tasks and services."""
    session = SessionLocal()
    try:
        yield session
    except Exception as exc:
        session.rollback()
        logger.error("Database session rolled back due to %s", type(exc).__name__)
        raise
    finally:
        session.close()



def check_database_connection(target = None, engine_override = None) -> tuple[bool, str]:
    """Validates the live database connection by executing a lightweight probe query."""
    target = target or engine_override
    try:
        if target is None:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        elif isinstance(target, Session):
            target.execute(text("SELECT 1"))
        elif hasattr(target, "connect"):
            with target.connect() as conn:
                conn.execute(text("SELECT 1"))
        else:
            target.execute(text("SELECT 1"))
        return True, "Database connection operational."
    except Exception as exc:
        err_msg = f"Database probe failed: {exc.__class__.__name__}"
        logger.warning(err_msg)
        return False, err_msg

