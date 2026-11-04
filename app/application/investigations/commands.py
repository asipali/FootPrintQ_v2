"""Investigation commands for application layer."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class CreateInvestigationCommand:
    """Command to initialize a new investigation."""
    name: str
    organization_name: str
    description: str
    lead_investigator: str
    owner_user_id: Optional[str] = None
    custom_id: Optional[str] = None
    team_members: List[str] = field(default_factory=list)
    owned_domains: List[str] = field(default_factory=list)
    approved_ips: List[str] = field(default_factory=list)
    approved_cidrs: List[str] = field(default_factory=list)
    active_targets: List[str] = field(default_factory=list)
    active_scanning_enabled: bool = False
    authorization_reference: Optional[str] = None
    authorization_expiry: Optional[datetime] = None


@dataclass
class TransitionInvestigationStatusCommand:
    """Command to advance an investigation's lifecycle state."""
    investigation_id: str
    new_status: str
    user_id: str
    is_admin: bool = False
    reason: Optional[str] = None

