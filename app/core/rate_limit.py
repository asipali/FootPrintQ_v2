"""In-memory sliding-window rate limiter for sensitive authentication endpoints."""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from fastapi import HTTPException, status


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(
        self,
        key: str,
        max_requests: int = 10,
        window_seconds: int = 60,
    ) -> Tuple[bool, int]:
        """Checks whether the given key is within the rate limit.

        Returns:
            Tuple of (is_allowed, retry_after_seconds).
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            # Purge timestamps older than window
            timestamps = self._records[key]
            self._records[key] = [t for t in timestamps if t > cutoff]

            if len(self._records[key]) >= max_requests:
                oldest_in_window = self._records[key][0]
                retry_after = max(1, int(window_seconds - (now - oldest_in_window)))
                return False, retry_after

            self._records[key].append(now)
            return True, 0

    def enforce_rate_limit(
        self,
        key: str,
        max_requests: int = 10,
        window_seconds: int = 60,
        detail: str = "Too many requests. Please slow down.",
    ):
        """Raises HTTP 429 Too Many Requests if rate limit is exceeded."""
        is_allowed, retry_after = self.check_rate_limit(key, max_requests, window_seconds)
        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=detail,
                headers={"Retry-After": str(retry_after)},
            )

    def is_allowed(self, key: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        allowed, _ = self.check_rate_limit(key, max_requests, window_seconds)
        return allowed

    def get_retry_after(self, key: str, window_seconds: int = 60) -> int:
        """Returns remaining retry-after seconds for key."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            timestamps = [t for t in self._records.get(key, []) if t > cutoff]
            if not timestamps:
                return 0
            return max(1, int(window_seconds - (now - timestamps[0])))

    def clear(self):
        """Clears all rate limit records."""
        self.reset()

    def reset(self, key: Optional[str] = None):
        """Clears records for a key or all keys (useful in test teardown)."""
        with self._lock:
            if key is not None:
                self._records.pop(key, None)
            else:
                self._records.clear()


# Global singleton instance for authentication endpoints
auth_rate_limiter = SlidingWindowRateLimiter()
