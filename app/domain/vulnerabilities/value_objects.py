"""Domain value objects for vulnerability assessment."""

from enum import Enum
from dataclasses import dataclass
from app.domain.common.value_objects import ValueObject
from app.domain.common.exceptions import InvariantViolationException


class VulnerabilitySeverity(str, Enum):
    """Severity classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class CVSSScore(ValueObject):
    """Common Vulnerability Scoring System metric."""
    score: float
    version: str = "3.1"

    def __post_init__(self):
        if self.score < 0.0 or self.score > 10.0:
            raise InvariantViolationException("CVSS score must be between 0.0 and 10.0.")

    @property
    def severity(self) -> VulnerabilitySeverity:
        """Map score to severity."""
        if self.score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        if self.score >= 7.0:
            return VulnerabilitySeverity.HIGH
        if self.score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        if self.score > 0.0:
            return VulnerabilitySeverity.LOW
        return VulnerabilitySeverity.INFO

