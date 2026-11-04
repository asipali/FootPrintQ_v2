"""Domain entities for reports and dossiers."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List
from app.domain.common.entities import Entity, utc_now
from app.domain.reporting.value_objects import ReportFormat, ReportMetadata


@dataclass
class InvestigationDossier(Entity):
    """Generated dossier summarizing investigation results and evidence."""
    id: str
    investigation_id: str
    metadata: ReportMetadata
    format: ReportFormat
    content_bytes: bytes = field(repr=False, default=b"")
    content_hash_sha256: str = ""
    evidence_count: int = 0
    findings_count: int = 0
    generated_at: datetime = field(default_factory=utc_now)

