"""Domain entities for workflows and durable jobs."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional
from app.domain.common.entities import AggregateRoot, utc_now
from app.domain.workflows.value_objects import JobStatus, WorkflowStage


@dataclass
class WorkflowJob(AggregateRoot):
    """Durable asynchronous workflow job."""
    id: str
    job_type: str
    investigation_id: str
    requested_by: str
    target: str
    status: JobStatus = JobStatus.QUEUED
    progress: int = 0
    worker_id: Optional[str] = None
    lease_expires_at: Optional[datetime] = None
    attempt_count: int = 0
    max_retries: int = 3
    retry_delay_seconds: int = 30
    next_run_at: Optional[datetime] = None
    params: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def is_terminal(self) -> bool:
        """Check if job has finished in a terminal state."""
        return self.status in (
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
            JobStatus.TIMED_OUT,
        )

    def is_active(self) -> bool:
        """Check if job is active."""
        return not self.is_terminal()

