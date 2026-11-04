"""Vulnerabilities domain package."""

from app.domain.vulnerabilities.value_objects import VulnerabilitySeverity, CVSSScore
from app.domain.vulnerabilities.entities import VulnerabilityFinding, VulnerabilityScanJob

__all__ = [
    "VulnerabilitySeverity",
    "CVSSScore",
    "VulnerabilityFinding",
    "VulnerabilityScanJob",
]

