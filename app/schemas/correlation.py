"""Pydantic schemas for findings and evidence correlation."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CorrelationRecordResponse(BaseModel):
    """Detailed correlation record representing an evaluated relationship."""
    id: str
    investigation_id: str
    correlation_rule_id: str
    rule_version: str
    relationship_type: str
    confidence_score: float
    asset_identifier: str
    asset_type: str
    source_modules: List[str] = Field(default_factory=list)
    source_scanners: List[str] = Field(default_factory=list)
    source_observation_ids: List[str] = Field(default_factory=list)
    matching_attributes: List[str] = Field(default_factory=list)
    related_vulnerability_id: Optional[str] = None
    evidence_references: List[str] = Field(default_factory=list)
    evidence_verification_status: str
    lifecycle_status: str
    correlation_status: str
    summary: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CorrelationSummaryResponse(BaseModel):
    """Aggregate metrics of investigation correlation."""
    total_assets: int = 0
    total_correlations: int = 0
    total_entities: int = 0
    total_discovered_hosts: int = 0
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    total_unmatched: int = 0
    total_evidence_verified: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    relationship_types: Dict[str, int] = Field(default_factory=dict)
    evidence_verification_breakdown: Dict[str, int] = Field(default_factory=dict)


class InvestigationCorrelationResponse(BaseModel):
    """Complete correlation payload with summary, assets, correlations, and knowledge graph."""
    investigation_id: str
    correlation_timestamp: str
    summary: CorrelationSummaryResponse
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    unmatched_observations: List[Dict[str, Any]] = Field(default_factory=list)
    graph: Dict[str, Any] = Field(default_factory=dict)

