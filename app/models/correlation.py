"""Correlation models representing cross-source asset, observation, and vulnerability relationships."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CorrelationRecordModel(Base):
    """Persisted relationship between multi-source observations, assets, and evidence."""

    __tablename__ = "correlation_records"

    id = Column(String(64), primary_key=True, default=lambda: f"corr-{uuid.uuid4().hex[:12]}")
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Correlation Rule provenance
    correlation_rule_id = Column(String(64), nullable=False, index=True)
    rule_version = Column(String(32), nullable=False, default="1.0.0")

    # Relationship classification & confidence
    # CONFIRMED_MATCH | STRONG_MATCH | POSSIBLE_MATCH | UNMATCHED
    relationship_type = Column(String(32), nullable=False, index=True)
    confidence_score = Column(Float, nullable=False, default=0.0)

    # Asset context
    asset_identifier = Column(String(255), nullable=False, index=True)
    asset_type = Column(String(32), nullable=False, index=True)  # IP_ADDRESS | DOMAIN | SUBDOMAIN | HOST | PORT | SERVICE | URL

    # Observation provenance
    source_modules = Column(JSON, nullable=False, default=list)  # e.g. ["active_scanner", "vuln_scanner"]
    source_scanners = Column(JSON, nullable=False, default=list)  # e.g. ["nmap", "openvas"]
    source_observation_ids = Column(JSON, nullable=False, default=list)  # e.g. ["host-1", "port-2", "vf-3"]
    matching_attributes = Column(JSON, nullable=False, default=list)  # e.g. ["ip", "port", "protocol"]

    # Optional vulnerability link
    related_vulnerability_id = Column(String(64), nullable=True, index=True)

    # Forensic evidence traceability
    evidence_references = Column(JSON, nullable=False, default=list)  # e.g. ["evi-123"]
    evidence_verification_status = Column(String(32), nullable=False, default="NOT_APPLICABLE", index=True)  # VERIFIED | HASH_MISMATCH | UNAVAILABLE | NOT_APPLICABLE

    # Lifecycle & status
    lifecycle_status = Column(String(32), nullable=False, default="NEW", index=True)  # NEW | REOBSERVED | CHANGED | RESOLVED | UNCONFIRMED
    correlation_status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE | HISTORICAL | SUPERSEDED

    # Descriptions & metadata
    summary = Column(String(1024), nullable=True)
    details_json = Column(JSON, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    # Composite indices for common query patterns
    __table_args__ = (
        Index("ix_corr_inv_asset", "investigation_id", "asset_identifier"),
        Index("ix_corr_inv_rule", "investigation_id", "correlation_rule_id"),
        Index("ix_corr_inv_rel", "investigation_id", "relationship_type"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Converts model to dictionary for API serialization."""
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "correlation_rule_id": self.correlation_rule_id,
            "rule_version": self.rule_version,
            "relationship_type": self.relationship_type,
            "confidence_score": self.confidence_score,
            "asset_identifier": self.asset_identifier,
            "asset_type": self.asset_type,
            "source_modules": self.source_modules or [],
            "source_scanners": self.source_scanners or [],
            "source_observation_ids": self.source_observation_ids or [],
            "matching_attributes": self.matching_attributes or [],
            "related_vulnerability_id": self.related_vulnerability_id,
            "evidence_references": self.evidence_references or [],
            "evidence_verification_status": self.evidence_verification_status,
            "lifecycle_status": self.lifecycle_status,
            "correlation_status": self.correlation_status,
            "summary": self.summary,
            "details": self.details_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

