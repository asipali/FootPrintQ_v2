"""Domain value objects for reporting and dossiers."""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


class ReportFormat(str, Enum):
    """Formats supported for reports."""
    PDF = "pdf"
    JSON = "json"
    GRAPHML = "graphml"


@dataclass(frozen=True)
class ReportMetadata:
    """Metadata regarding a generated report."""
    title: str
    classification: str
    author: str
    organization: str
    disclaimer: Optional[str] = None

