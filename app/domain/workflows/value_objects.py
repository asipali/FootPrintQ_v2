"""Domain value objects for workflow orchestration and job queues."""

from enum import Enum


class JobStatus(str, Enum):
    """Job status lifecycle."""
    QUEUED = "QUEUED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY_WAIT = "RETRY_WAIT"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class WorkflowStage(str, Enum):
    """Investigation workflow orchestration stages."""
    PASSIVE_RECONNAISSANCE = "PASSIVE_RECONNAISSANCE"
    ACTIVE_NMAP = "ACTIVE_NMAP"
    VULNERABILITY_ASSESSMENT = "VULNERABILITY_ASSESSMENT"
    FINDING_CORRELATION = "FINDING_CORRELATION"
    EXPOSURE_SCORING = "EXPOSURE_SCORING"

