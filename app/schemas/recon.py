"""Pydantic schemas for passive reconnaissance, target authorizations, evidence, and entities."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


class TargetValidationRequest(BaseModel):
    """Payload to validate target syntax, scope and operation-specific authorization."""
    target: str = Field(..., min_length=1, max_length=255, description="Domain, IP, or CIDR to validate")
    operation: Literal[
        "RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN",
        "PASSIVE_RECON", "SCAN_PORTS", "SCAN_VULNERABILITY",
    ] = "RECON_PASSIVE"


class TargetValidationResponse(BaseModel):
    """Validation response distinguishes syntax, investigation scope and authorization."""
    target: str
    target_type: str  # DOMAIN, IP, CIDR, UNKNOWN
    is_valid_syntax: bool
    is_in_investigation_scope: bool
    is_authorized: bool
    message: str


class TargetAuthorizationCreate(BaseModel):
    """Payload for provisioning a formal administrative target authorization record."""
    target: str = Field(..., min_length=1, max_length=255)
    target_type: Literal["DOMAIN", "IP", "CIDR"]
    allowed_operations: List[str] = Field(
        default=["PASSIVE_RECON"],
        description="Permitted operations, e.g. ['PASSIVE_RECON']"
    )
    authorization_reference: str = Field(
        ..., min_length=3, max_length=128,
        description="Formal approval document or consent tracking reference"
    )
    valid_from: Optional[datetime] = Field(default=None, description="Start timestamp of authorization in UTC")
    valid_to: datetime = Field(..., description="Expiration timestamp in UTC")
    approved_by: Optional[str] = Field(default=None, description="Authorizing administrator or officer name")
    notes: Optional[str] = None

    @field_validator("target")
    @classmethod
    def trim_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Target cannot be blank")
        return value

    @field_validator("authorization_reference")
    @classmethod
    def trim_reference(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Authorization reference cannot be blank")
        return value

    @field_validator("allowed_operations")
    @classmethod
    def validate_operations(cls, operations: List[str]) -> List[str]:
        aliases = {
            "PASSIVE_RECON": "RECON_PASSIVE",
            "SCAN_PORTS": "SCAN_ACTIVE",
            "SCAN_VULNERABILITY": "SCAN_VULN",
        }
        canonical = [aliases.get(value.strip().upper(), value.strip().upper()) for value in operations]
        supported = {"RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"}
        if not canonical or any(value not in supported for value in canonical):
            raise ValueError("At least one supported operation is required: RECON_PASSIVE, SCAN_ACTIVE, SCAN_VULN")
        if len(set(canonical)) != len(canonical):
            raise ValueError("Duplicate operations are not allowed")
        return canonical

    @model_validator(mode="after")
    def validate_target_and_dates(self):
        from app.services.target_authorization import classify_target, normalize_target

        actual_type = classify_target(self.target)
        if actual_type == "UNKNOWN" or actual_type != self.target_type:
            raise ValueError(f"Target syntax must be valid and match target_type {self.target_type}")
        self.target = normalize_target(self.target)
        valid_to = self.valid_to.replace(tzinfo=timezone.utc) if self.valid_to.tzinfo is None else self.valid_to
        valid_from = self.valid_from
        if valid_from and valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        if valid_from and valid_from >= valid_to:
            raise ValueError("Authorization valid_from must be earlier than valid_to")
        if valid_to <= datetime.now(timezone.utc):
            raise ValueError("Authorization expiration must be in the future")
        if self.approved_by is not None:
            self.approved_by = self.approved_by.strip() or None
        return self


class TargetAuthorizationResponse(BaseModel):
    """Representation of an administrative target authorization record."""
    id: str
    investigation_id: str
    target: str
    target_type: str
    allowed_operations: List[str]
    authorization_reference: str
    approved_by: str
    valid_from: datetime
    valid_to: datetime
    is_revoked: bool
    notes: Optional[str] = None
    created_at: datetime


class TargetAuthorizationUpdate(BaseModel):
    """Fields that can be amended on an authorization record; approver is immutable."""

    target: Optional[str] = Field(default=None, min_length=1, max_length=255)
    target_type: Optional[Literal["DOMAIN", "IP", "CIDR"]] = None
    allowed_operations: Optional[List[str]] = None
    authorization_reference: Optional[str] = Field(default=None, min_length=3, max_length=128)
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    notes: Optional[str] = None

    @field_validator("allowed_operations")
    @classmethod
    def validate_update_operations(cls, operations: Optional[List[str]]) -> Optional[List[str]]:
        if operations is None:
            return operations
        return TargetAuthorizationCreate.validate_operations(operations)

    @field_validator("target")
    @classmethod
    def validate_update_target(cls, target: Optional[str]) -> Optional[str]:
        if target is None:
            return target
        target = target.strip()
        if not target:
            raise ValueError("Target cannot be blank")
        return target

    @field_validator("authorization_reference")
    @classmethod
    def validate_update_reference(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Authorization reference cannot be blank")
        return value


class PassiveReconRequest(BaseModel):
    """Payload to trigger passive reconnaissance for an authorized target."""
    target: str = Field(..., min_length=1, max_length=255, description="Approved domain target")
    collectors: Optional[List[str]] = Field(
        default=None,
        description="Optional list of collectors to run: 'rdap', 'dns', 'crtsh', 'theharvester'. Defaults to all."
    )


class CollectionJobSummary(BaseModel):
    """Summary of individual collector execution status."""
    id: str
    collector_name: str
    status: str
    result_summary: Dict[str, Any] = Field(default_factory=dict)
    error_category: Optional[str] = None
    error_message: Optional[str] = None


class PassiveReconResponse(BaseModel):
    """Aggregated execution summary returned by passive reconnaissance orchestrator."""
    investigation_id: str
    target: str
    orchestrator_job_id: str
    status: str  # COMPLETED, PARTIAL, FAILED
    collectors: List[CollectionJobSummary]
    evidence_collected: int
    new_entities_discovered: int
    total_entities_count: int


class EvidenceResponse(BaseModel):
    """Forensic evidence metadata representation."""
    id: str
    investigation_id: str
    job_id: Optional[str] = None
    source_type: str
    source_name: str
    target: str
    collection_status: str
    storage_backend: Optional[str] = "filesystem"
    content_hash: str
    content_size_bytes: int
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime


class EntityResponse(BaseModel):
    """Normalized OSINT entity record with provenance."""
    id: str
    investigation_id: str
    entity_type: str
    canonical_value: str
    original_value: str
    first_seen: datetime
    last_seen: datetime
    evidence_ids: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
