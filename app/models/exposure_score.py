"""SQLAlchemy model for persisting exposure scores and historical calculations."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExposureScoreModel(Base):
    """Persisted exposure assessment calculation with complete factor breakdown and coverage provenance."""

    __tablename__ = "exposure_scores"

    id = Column(String(64), primary_key=True, default=lambda: f"exp-{uuid.uuid4().hex[:12]}")
    investigation_id = Column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Formula provenance
    formula_version = Column(String(32), nullable=False, index=True)  # e.g. "v3.0-5factor", "v1.0-legacy"
    formula_weights = Column(JSON, nullable=False)  # {"P": 0.20, "D": 0.15, "S": 0.25, "V": 0.35, "C": 0.05}

    # Factor scores and contributions
    raw_factor_inputs = Column(JSON, nullable=False)  # raw counts, port lists, finding summaries
    normalized_factor_scores = Column(JSON, nullable=False)  # {"P": 66, "D": 65, "S": 34, "V": 70, "C": 50}
    weighted_contributions = Column(JSON, nullable=False)  # {"P": 13.2, "D": 9.75, "S": 8.5, "V": 24.5, "C": 2.5}

    # Scores and tiers
    total_score = Column(Integer, nullable=False)  # composite 0-100
    renormalized_score = Column(Float, nullable=True)  # score over assessed factors only
    risk_tier = Column(String(32), nullable=False)  # Minimal, Low, Moderate, High, Critical, Incomplete

    # Assessment coverage
    assessment_status = Column(String(32), nullable=False)  # FULL_ASSESSMENT, PARTIAL, NOT_ASSESSED, FAILED, SCANNER_UNAVAILABLE
    coverage_percentage = Column(Integer, nullable=False)  # 0 - 100
    is_fully_assessed = Column(Boolean, nullable=False, default=False)
    coverage_metadata = Column(JSON, nullable=False)  # dimension_status for PASSIVE, DNS, NMAP, GREENBONE, CORRELATION
    scanner_availability = Column(JSON, nullable=False)  # nmap, greenbone status

    # Provenance tracking
    source_observation_ids = Column(JSON, nullable=False, default=list)
    reviewer_notes = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)

    # Historical versioning state
    is_active = Column(Boolean, nullable=False, default=True, index=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "formula_version": self.formula_version,
            "formula_weights": self.formula_weights or {},
            "raw_factor_inputs": self.raw_factor_inputs or {},
            "normalized_factor_scores": self.normalized_factor_scores or {},
            "weighted_contributions": self.weighted_contributions or {},
            "total_score": self.total_score,
            "renormalized_score": self.renormalized_score,
            "risk_tier": self.risk_tier,
            "assessment_status": self.assessment_status,
            "coverage_percentage": self.coverage_percentage,
            "is_fully_assessed": self.is_fully_assessed,
            "coverage_metadata": self.coverage_metadata or {},
            "scanner_availability": self.scanner_availability or {},
            "source_observation_ids": self.source_observation_ids or [],
            "reviewer_notes": self.reviewer_notes,
            "explanation": self.explanation,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

