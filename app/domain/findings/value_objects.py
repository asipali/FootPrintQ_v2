"""Domain value objects for findings."""

from enum import Enum


class FindingSeverity(str, Enum):
    """Severity classification for security findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

