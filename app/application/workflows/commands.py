"""Workflow commands."""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class DispatchWorkflowCommand:
    """Command to enqueue an automated investigation workflow."""
    investigation_id: str
    target: str
    requested_by: str
    enable_active: bool = False
    enable_vuln: bool = False
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CancelWorkflowCommand:
    """Command to cancel an ongoing workflow."""
    job_id: str
    requested_by: str
    is_admin: bool = False
    reason: Optional[str] = None


@dataclass
class RecoverOrphanedJobsCommand:
    """Command to recover expired job leases."""
    max_lease_seconds: int = 300

