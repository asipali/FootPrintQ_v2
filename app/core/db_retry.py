"""SQL Server Error 1205 (deadlock victim) bounded retry handler.

Provides transaction rollback and exponential backoff with jitter for
transient SQL Server lock resource contention.
"""

import time
import random
import inspect
import asyncio
import functools
from typing import Callable, TypeVar, Optional, Any
from sqlalchemy.orm import Session
from app.logging_config import get_logger

logger = get_logger("footprintiq.db_retry")

T = TypeVar("T")

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 0.05
DEFAULT_MAX_DELAY = 0.5


def is_deadlock_error(exc: Optional[BaseException]) -> bool:
    """Determines whether an exception represents a SQL Server Error 1205 deadlock victim.
    
    Rejects permanent errors (syntax, foreign key, duplicate key, timeouts, etc.).
    """
    if exc is None:
        return False

    visited = set()
    queue = [exc]

    while queue:
        current = queue.pop(0)
        if id(current) in visited:
            continue
        visited.add(id(current))

        # Check exception string representation and args
        msg = str(current).lower()
        if "1205" in msg and ("deadlock" in msg or "deadlocked" in msg or "victim" in msg):
            return True
        if "chosen as the deadlock victim" in msg:
            return True

        if hasattr(current, "args") and current.args:
            for arg in current.args:
                if isinstance(arg, str):
                    arg_l = arg.lower()
                    if "1205" in arg_l and ("deadlock" in arg_l or "victim" in arg_l):
                        return True
                    if "chosen as the deadlock victim" in arg_l:
                        return True

        # Inspect underlying DBAPI error attributes
        if hasattr(current, "orig") and current.orig is not None:
            queue.append(current.orig)
        if hasattr(current, "__cause__") and current.__cause__ is not None:
            queue.append(current.__cause__)
        if hasattr(current, "__context__") and current.__context__ is not None:
            queue.append(current.__context__)

    return False


def calculate_backoff(attempt: int, base_delay: float, max_delay: float, jitter: bool) -> float:
    """Calculates exponential backoff delay with randomized jitter."""
    factor = 2 ** max(0, attempt - 1)
    raw_delay = min(max_delay, base_delay * factor)
    if jitter:
        # Full/equal jitter between 50% and 100% of calculated backoff
        return raw_delay * (0.5 + random.random() * 0.5)
    return raw_delay


def run_with_deadlock_retry(
    operation: Callable[..., T],
    *args,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: bool = True,
    session: Optional[Session] = None,
    **kwargs,
) -> T:
    """Executes a synchronous operation, retrying exclusively on SQL Server Error 1205 deadlock.
    
    If a session is provided, rolls back the transaction before retrying to preserve atomicity.
    """
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return operation(*args, **kwargs)
        except Exception as exc:
            if not is_deadlock_error(exc):
                # Permanent error or non-deadlock: raise immediately without retrying
                raise

            last_exc = exc
            if session is not None:
                try:
                    session.rollback()
                except Exception as rb_err:
                    logger.warning("Rollback during deadlock recovery encountered: %s", rb_err)

            if attempt >= max_attempts:
                logger.error(
                    "SQL Server Error 1205 deadlock: exhausted all %d retry attempts. Re-raising exception.",
                    max_attempts,
                )
                raise

            delay = calculate_backoff(attempt, base_delay, max_delay, jitter)
            logger.warning(
                "SQL Server Error 1205 deadlock victim on attempt %d/%d. Rolled back; backing off for %.3fs...",
                attempt,
                max_attempts,
                delay,
            )
            time.sleep(delay)

    assert last_exc is not None
    raise last_exc


async def run_with_deadlock_retry_async(
    operation: Callable[..., Any],
    *args,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: bool = True,
    session: Optional[Session] = None,
    **kwargs,
) -> Any:
    """Executes an asynchronous operation, retrying exclusively on SQL Server Error 1205 deadlock."""
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return await operation(*args, **kwargs)
        except Exception as exc:
            if not is_deadlock_error(exc):
                raise

            last_exc = exc
            if session is not None:
                try:
                    session.rollback()
                except Exception as rb_err:
                    logger.warning("Rollback during deadlock recovery encountered: %s", rb_err)

            if attempt >= max_attempts:
                logger.error(
                    "SQL Server Error 1205 deadlock: exhausted all %d retry attempts. Re-raising exception.",
                    max_attempts,
                )
                raise

            delay = calculate_backoff(attempt, base_delay, max_delay, jitter)
            logger.warning(
                "SQL Server Error 1205 deadlock victim on attempt %d/%d. Rolled back; backing off for %.3fs...",
                attempt,
                max_attempts,
                delay,
            )
            await asyncio.sleep(delay)

    assert last_exc is not None
    raise last_exc


def retry_on_deadlock(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: bool = True,
    session_arg_name: Optional[str] = "session",
):
    """Decorator for functions that perform database operations subject to SQL Server lock contention."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                kwargs_copy = dict(kwargs)
                sess = kwargs_copy.pop(session_arg_name, None) if session_arg_name else None
                return await run_with_deadlock_retry_async(
                    func,
                    *args,
                    max_attempts=max_attempts,
                    base_delay=base_delay,
                    max_delay=max_delay,
                    jitter=jitter,
                    session=sess,
                    **kwargs_copy,
                )
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                kwargs_copy = dict(kwargs)
                sess = kwargs_copy.pop(session_arg_name, None) if session_arg_name else None
                return run_with_deadlock_retry(
                    func,
                    *args,
                    max_attempts=max_attempts,
                    base_delay=base_delay,
                    max_delay=max_delay,
                    jitter=jitter,
                    session=sess,
                    **kwargs_copy,
                )
            return sync_wrapper
    return decorator
