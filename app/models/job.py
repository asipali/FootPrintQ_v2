"""SQLAlchemy data model for durable, database-backed background jobs and execution recovery."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


def utc_now() -> datetime:
    """Returns current datetime in UTC timezone."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime object is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# Valid Job Lifecycle Statuses
JOB_STATUS_QUEUED = "QUEUED"
JOB_STATUS_CLAIMED = "CLAIMED"
JOB_STATUS_RUNNING = "RUNNING"
JOB_STATUS_COMPLETED = "COMPLETED"
JOB_STATUS_FAILED = "FAILED"
JOB_STATUS_RETRY_WAIT = "RETRY_WAIT"
JOB_STATUS_CANCEL_REQUESTED = "CANCEL_REQUESTED"
JOB_STATUS_CANCELLED = "CANCELLED"
JOB_STATUS_TIMED_OUT = "TIMED_OUT"

VALID_JOB_STATUSES = {
    JOB_STATUS_QUEUED,
    JOB_STATUS_CLAIMED,
    JOB_STATUS_RUNNING,
    JOB_STATUS_COMPLETED,
    JOB_STATUS_FAILED,
    JOB_STATUS_RETRY_WAIT,
    JOB_STATUS_CANCEL_REQUESTED,
    JOB_STATUS_CANCELLED,
    JOB_STATUS_TIMED_OUT,
}

TERMINAL_STATUSES = {
    JOB_STATUS_COMPLETED,
    JOB_STATUS_FAILED,
    JOB_STATUS_CANCELLED,
    JOB_STATUS_TIMED_OUT,
}

ACTIVE_STATUSES = {
    JOB_STATUS_QUEUED,
    JOB_STATUS_CLAIMED,
    JOB_STATUS_RUNNING,
    JOB_STATUS_RETRY_WAIT,
    JOB_STATUS_CANCEL_REQUESTED,
}


class JobModel(Base):
    """Tracks persistent asynchronous reconnaissance, scanning, and analytical jobs."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # NMAP_SCAN, VULN_SCAN, PASSIVE_RECON
    operation: Mapped[str] = mapped_column(String(64), nullable=False)            # SCAN_ACTIVE, SCAN_VULN, RECON_PASSIVE
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=JOB_STATUS_QUEUED, nullable=False, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Ownership & Concurrency Leasing
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    worker_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    process_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Retry & Error Handling
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Cancellation
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cancellation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Evidence & Timing
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True
    )
    duration_seconds: Mapped[Optional[float]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def is_active(self) -> bool:
        return self.status in ACTIVE_STATUSES

    def is_lease_expired(self) -> bool:
        if not self.lease_expires_at:
            return True
        return utc_now() >= ensure_utc(self.lease_expires_at)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "job_type": self.job_type,
            "operation": self.operation,
            "target": self.target,
            "parameters": self.parameters or {},
            "status": self.status,
            "progress": self.progress,
            "requested_by": self.requested_by,
            "worker_id": self.worker_id,
            "process_pid": self.process_pid,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "error_category": self.error_category,
            "error_message": self.error_message,
            "cancellation_requested": self.cancellation_requested,
            "cancellation_reason": self.cancellation_reason,
            "evidence_id": self.evidence_id,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

