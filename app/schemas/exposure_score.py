"""Pydantic schemas for Exposure Scoring API requests and responses."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExposureScoreCalculateRequest(BaseModel):
    """Request payload to calculate an exposure score."""

    model_version: str = Field(
        default="v3.0-5factor",
        description="Formula version to apply ('v3.0-5factor' or 'v1.0-legacy')",
    )
    reviewer_notes: Optional[str] = Field(
        default=None,
        description="Optional reviewer notes or risk observation rationale",
    )


class ExposureScoreResponse(BaseModel):
    """Detailed exposure score response with factor breakdown and coverage provenance."""

    id: Optional[str] = None
    investigation_id: str
    formula_version: str
    formula_weights: Dict[str, float]
    normalized_factor_scores: Dict[str, int]
    weighted_contributions: Dict[str, float]
    total_score: int
    renormalized_score: Optional[float] = None
    risk_tier: str
    assessment_status: str
    coverage_percentage: int
    is_fully_assessed: bool
    coverage_metadata: Dict[str, Any]
    scanner_availability: Dict[str, Any]
    raw_factor_inputs: Optional[Dict[str, Any]] = None
    reviewer_notes: Optional[str] = None
    explanation: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None


class ExposureScoreHistoryResponse(BaseModel):
    """List of historical exposure calculations for an investigation."""

    investigation_id: str
    total_records: int
    scores: List[ExposureScoreResponse]


class ExposureScoreComparisonResponse(BaseModel):
    """Comparison result between two exposure score records."""

    same_formula_version: bool
    version_a: str
    version_b: str
    delta_total_score: int
    factor_deltas: Dict[str, int]
    comparison_notes: List[str]

