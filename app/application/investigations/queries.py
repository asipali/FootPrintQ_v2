"""Investigation queries and DTOs."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class GetInvestigationQuery:
    """Query to fetch a single investigation."""
    investigation_id: str
    user_id: str
    is_admin: bool = False


@dataclass
class ListInvestigationsQuery:
    """Query to list investigations."""
    user_id: str
    is_admin: bool = False
    limit: int = 100
    offset: int = 0


@dataclass
class InvestigationDTO:
    """Data Transfer Object representing an investigation."""
    id: str
    name: str
    organization_name: str
    description: str
    lead_investigator: str
    status: str
    owner_user_id: Optional[str] = None
    team_members: List[str] = field(default_factory=list)
    owned_domains: List[str] = field(default_factory=list)
    approved_ips: List[str] = field(default_factory=list)
    approved_cidrs: List[str] = field(default_factory=list)
    active_targets: List[str] = field(default_factory=list)
    active_scanning_enabled: bool = False
    authorization_reference: Optional[str] = None
    authorization_expiry: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

