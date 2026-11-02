"""Pydantic schemas for investigation validation and responses."""

from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


class ScopeSchema(BaseModel):
    """Scope target lists defining investigation boundaries."""
    owned_domains: List[str] = Field(default_factory=list, description="Apex domains owned by target organization")
    approved_ips: List[str] = Field(default_factory=list, description="Approved static IP addresses")
    approved_cidrs: List[str] = Field(default_factory=list, description="Approved network CIDR blocks")
    active_targets: List[str] = Field(default_factory=list, description="Explicitly allowlisted active scan IPs")

    @field_validator("owned_domains", "approved_ips", "approved_cidrs", "active_targets")
    @classmethod
    def validate_scope_targets(cls, values: List[str], info) -> List[str]:
        from app.services.target_authorization import classify_target, normalize_target

        field_types = {
            "owned_domains": {"DOMAIN"},
            "approved_ips": {"IP"},
            "approved_cidrs": {"CIDR"},
            "active_targets": {"DOMAIN", "IP", "CIDR"},
        }
        normalized = []
        for value in values:
            kind = classify_target(value)
            if kind not in field_types[info.field_name]:
                raise ValueError(f"Invalid {info.field_name} target: {value}")
            normalized.append(normalize_target(value))
        if len(set(normalized)) != len(normalized):
            raise ValueError(f"Duplicate values are not allowed in {info.field_name}")
        return normalized


class InvestigationBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=128, description="Investigation title")
    organization_name: str = Field(..., min_length=2, max_length=128, description="Target company or entity")
    description: str = Field(..., min_length=5, max_length=1024, description="Scope and purpose description")
    lead_investigator: str = Field(..., min_length=2, max_length=128, description="Primary analyst name")
    team_members: List[str] = Field(default_factory=list, description="Secondary analysts")
    status: Literal["active", "completed", "archived"] = Field(default="active", description="Campaign status")
    scope: ScopeSchema = Field(default_factory=ScopeSchema)
    active_scanning_enabled: bool = Field(default=False)
    authorization_reference: Optional[str] = Field(default=None, max_length=128)
    authorization_expiry: Optional[datetime] = None

    @field_validator("name", "organization_name", "description", "lead_investigator")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value


class InvestigationCreate(InvestigationBase):
    id: Optional[str] = Field(default=None, description="Optional custom identifier (e.g., inv-northstar-01)")

    @model_validator(mode="after")
    def new_investigations_start_active(self):
        if self.status != "active":
            raise ValueError("New investigations must start in active status")
        return self


class InvestigationResponse(InvestigationBase):
    id: str
    owner_user_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class InvestigationUpdate(BaseModel):
    """Partial update schema; ownership and identifiers are intentionally immutable."""

    name: Optional[str] = Field(default=None, min_length=3, max_length=128)
    organization_name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, min_length=5, max_length=1024)
    team_members: Optional[List[str]] = None
    status: Optional[Literal["active", "completed", "archived"]] = None
    scope: Optional[ScopeSchema] = None
    active_scanning_enabled: Optional[bool] = None
    authorization_reference: Optional[str] = Field(default=None, max_length=128)
    authorization_expiry: Optional[datetime] = None
    owner_user_id: Optional[str] = None

    @field_validator("name", "organization_name", "description")
    @classmethod
    def strip_nonblank_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value
