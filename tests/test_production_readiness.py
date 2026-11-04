"""Automated regression tests for Task 03B Production Readiness conditions.

Covers:
1. Production SQLite fallback lockout and fail-fast startup.
2. Development/test SQLite fallback preservation.
3. SQL Server Error 1205 deadlock detection, rollback, and bounded retry with jitter.
"""

import sys
import pytest
from unittest.mock import MagicMock
from sqlalchemy.exc import DBAPIError, OperationalError
from app.config import Settings
from app.database import init_engine
from app.core.db_retry import (
    is_deadlock_error,
    retry_on_deadlock,
    run_with_deadlock_retry,
    run_with_deadlock_retry_async,
    calculate_backoff,
)


# ============================================================================
# CONDITION 1: Production SQLite Fallback Lockout Tests
# ============================================================================

def test_production_and_staging_force_fallback_false():
    """Confirms DB_FALLBACK_TO_SQLITE is forced to False in staging and production."""
    prod_settings = Settings(
        APP_ENV="production",
        DATABASE_URL="mssql+pyodbc://@localhost/footprintiq?driver=ODBC+Driver+17+for+SQL+Server",
        DB_FALLBACK_TO_SQLITE=True,  # Attempting to enable fallback
        SESSION_COOKIE_SECURE=True,
        ALLOWED_HOSTS=["footprintiq.internal"],
        DEMO_ACCOUNTS_ENABLED=False,
        SECRET_KEY="production-secret-key-that-is-at-least-32-characters-long-12345",
    )
    assert prod_settings.DB_FALLBACK_TO_SQLITE is False, "Production must lock out SQLite fallback"

    staging_settings = Settings(
        APP_ENV="staging",
        DATABASE_URL="mssql+pyodbc://@localhost/footprintiq?driver=ODBC+Driver+17+for+SQL+Server",
        DB_FALLBACK_TO_SQLITE=True,  # Attempting to enable fallback
        SESSION_COOKIE_SECURE=True,
        ALLOWED_HOSTS=["staging.footprintiq.internal"],
        DEMO_ACCOUNTS_ENABLED=False,
        SECRET_KEY="staging-secret-key-that-is-at-least-32-characters-long-12345",
    )
    assert staging_settings.DB_FALLBACK_TO_SQLITE is False, "Staging must lock out SQLite fallback"


def test_development_and_test_preserve_fallback():
    """Confirms development and test environments permit DB_FALLBACK_TO_SQLITE."""
    dev_settings = Settings(
        APP_ENV="development",
        DATABASE_URL="mssql+pyodbc://@localhost/footprintiq?driver=ODBC+Driver+17+for+SQL+Server",
        DB_FALLBACK_TO_SQLITE=True,
    )
    assert dev_settings.DB_FALLBACK_TO_SQLITE is True

    test_settings = Settings(
        APP_ENV="test",
        DATABASE_URL="sqlite:///./test.db",
        DB_FALLBACK_TO_SQLITE=False,
    )
    assert test_settings.DB_FALLBACK_TO_SQLITE is False


def test_init_engine_fails_fast_in_production_when_unreachable():
    """Confirms init_engine raises RuntimeError and never switches to SQLite in production."""
    prod_bad_db = Settings(
        APP_ENV="production",
        DATABASE_URL="mssql+pyodbc://@invalid-unreachable-host:9999/dummy?driver=ODBC+Driver+17+for+SQL+Server",
        SESSION_COOKIE_SECURE=True,
        ALLOWED_HOSTS=["footprintiq.internal"],
        DEMO_ACCOUNTS_ENABLED=False,
        SECRET_KEY="production-secret-key-that-is-at-least-32-characters-long-12345",
    )
    
    with pytest.raises(RuntimeError) as exc_info:
        init_engine(prod_bad_db)
    
    assert "Database connection failed in production environment" in str(exc_info.value)
    assert "SQLite fallback is strictly forbidden" in str(exc_info.value)


def test_init_engine_allows_fallback_in_development():
    """Confirms init_engine safely falls back to local SQLite when configured in development."""
    dev_bad_db = Settings(
        APP_ENV="development",
        DATABASE_URL="mssql+pyodbc://@invalid-unreachable-host:9999/dummy?driver=ODBC+Driver+17+for+SQL+Server",
        DB_FALLBACK_TO_SQLITE=True,
    )
    fallback_engine = init_engine(dev_bad_db)
    assert fallback_engine.url.drivername == "sqlite"


# ============================================================================
# CONDITION 3: SQL Server Error 1205 Deadlock Retry Tests
# ============================================================================

def make_deadlock_exception():
    """Helper creating a realistic simulated PyODBC/SQLAlchemy deadlock error."""
    class MockPyODBCError(Exception):
        pass

    pyodbc_err = MockPyODBCError(
        "('40001', '[40001] [Microsoft][ODBC Driver 17 for SQL Server][SQL Server]"
        "Transaction (Process ID 62) was deadlocked on lock resources with another process "
        "and has been chosen as the deadlock victim. Rerun the transaction. (1205) (SQLExecute)')"
    )
    sa_err = OperationalError("SELECT * FROM jobs", {}, pyodbc_err)
    return sa_err


def test_is_deadlock_error_recognition():
    """Verifies that is_deadlock_error accurately identifies Error 1205 and rejects other errors."""
    dl_exc = make_deadlock_exception()
    assert is_deadlock_error(dl_exc) is True

    # Test raw message variation
    raw_dl = Exception("Error 1205: chosen as the deadlock victim.")
    assert is_deadlock_error(raw_dl) is True

    # Rejection of non-deadlock exceptions
    assert is_deadlock_error(None) is False
    assert is_deadlock_error(ValueError("Invalid argument")) is False
    assert is_deadlock_error(KeyError("missing_col")) is False
    assert is_deadlock_error(OperationalError("syntax error (102)", {}, Exception())) is False
    assert is_deadlock_error(DBAPIError("UNIQUE KEY violation (2627)", {}, Exception())) is False


def test_calculate_backoff_with_jitter():
    """Verifies backoff formula and bounded ceiling."""
    # Without jitter
    d1 = calculate_backoff(attempt=1, base_delay=0.1, max_delay=1.0, jitter=False)
    assert d1 == 0.1
    d2 = calculate_backoff(attempt=2, base_delay=0.1, max_delay=1.0, jitter=False)
    assert d2 == 0.2
    d5 = calculate_backoff(attempt=5, base_delay=0.1, max_delay=1.0, jitter=False)
    assert d5 == 1.0  # Capped at max_delay

    # With jitter: must be within [0.5 * raw, 1.0 * raw]
    d_jit = calculate_backoff(attempt=2, base_delay=0.1, max_delay=1.0, jitter=True)
    assert 0.1 <= d_jit <= 0.2


def test_retry_on_deadlock_succeeds_after_transient_failure():
    """Verifies retry succeeds when an operation deadlocks on attempt 1 and succeeds on attempt 2."""
    attempts = 0
    mock_session = MagicMock()

    @retry_on_deadlock(max_attempts=3, base_delay=0.01, max_delay=0.05, jitter=False)
    def resilient_unit_of_work(session=None):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise make_deadlock_exception()
        return "SUCCESS_DATA"

    result = resilient_unit_of_work(session=mock_session)
    assert result == "SUCCESS_DATA"
    assert attempts == 2
    mock_session.rollback.assert_called_once()


def test_retry_on_deadlock_exhausted_attempts():
    """Verifies retry terminates and raises deadlock when attempts are exhausted."""
    attempts = 0
    mock_session = MagicMock()

    @retry_on_deadlock(max_attempts=3, base_delay=0.01, max_delay=0.05, jitter=False)
    def perpetually_deadlocking_work(session=None):
        nonlocal attempts
        attempts += 1
        raise make_deadlock_exception()

    with pytest.raises(OperationalError) as exc_info:
        perpetually_deadlocking_work(session=mock_session)

    assert "1205" in str(exc_info.value)
    assert attempts == 3
    assert mock_session.rollback.call_count == 3


def test_retry_on_deadlock_non_retryable_failure_raises_immediately():
    """Verifies permanent/non-deadlock exceptions are NOT retried."""
    attempts = 0
    mock_session = MagicMock()

    @retry_on_deadlock(max_attempts=3, base_delay=0.01, max_delay=0.05, jitter=False)
    def broken_sql_syntax(session=None):
        nonlocal attempts
        attempts += 1
        raise ValueError("Invalid syntax in query")

    with pytest.raises(ValueError) as exc_info:
        broken_sql_syntax(session=mock_session)

    assert "Invalid syntax" in str(exc_info.value)
    assert attempts == 1  # Raised immediately on first attempt without retrying
    mock_session.rollback.assert_not_called()


@pytest.mark.asyncio
async def test_retry_on_deadlock_async():
    """Verifies async decorator handles transient deadlocks properly."""
    attempts = 0

    @retry_on_deadlock(max_attempts=3, base_delay=0.01, max_delay=0.05, jitter=False)
    async def async_scan_worker():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise make_deadlock_exception()
        return "ASYNC_SUCCESS"

    result = await async_scan_worker()
    assert result == "ASYNC_SUCCESS"
    assert attempts == 3
