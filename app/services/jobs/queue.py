"""Durable database-backed job queue service with atomic claiming and lease management."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import Session

from app.core.auth import log_audit_event
from app.models.job import (
    JobModel,
    JOB_STATUS_QUEUED,
    JOB_STATUS_CLAIMED,
    JOB_STATUS_RUNNING,
    JOB_STATUS_COMPLETED,
    JOB_STATUS_FAILED,
    JOB_STATUS_RETRY_WAIT,
    JOB_STATUS_CANCEL_REQUESTED,
    JOB_STATUS_CANCELLED,
    JOB_STATUS_TIMED_OUT,
    ACTIVE_STATUSES,
    TERMINAL_STATUSES,
    utc_now,
    ensure_utc,
)

logger = logging.getLogger("footprintiq.services.jobs.queue")


class DuplicateJobError(Exception):
    """Raised when an active identical job is already queued or running."""
    pass


class JobQueueService:
    """Manages job persistence, duplicate prevention, atomic worker claims, and lifecycle transitions."""

    @staticmethod
    def _sanitize_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
        """Strips credentials, private tokens, or sensitive secrets from stored parameters."""
        sanitized = {}
        sensitive_keys = {"password", "secret", "token", "key", "auth", "credential", "api_key", "gvm_password"}
        for k, v in (params or {}).items():
            if any(s in k.lower() for s in sensitive_keys):
                sanitized[k] = "[REDACTED]"
            elif isinstance(v, dict):
                sanitized[k] = JobQueueService._sanitize_parameters(v)
            else:
                sanitized[k] = v
        return sanitized

    def enqueue_job(
        self,
        db: Session,
        investigation_id: str,
        job_type: str,
        operation: str,
        target: str,
        requested_by: str,
        parameters: Optional[Dict[str, Any]] = None,
        max_retries: int = 0,
        job_id: Optional[str] = None,
        prevent_duplicates: bool = True,
    ) -> JobModel:
        """Enqueues a new persistent job. Rejects duplicate active jobs on same investigation+target+operation."""
        target_clean = target.strip()

        if prevent_duplicates:
            existing = db.scalars(
                select(JobModel).where(
                    JobModel.investigation_id == investigation_id,
                    JobModel.operation == operation,
                    JobModel.target == target_clean,
                    JobModel.status.in_(ACTIVE_STATUSES),
                )
            ).first()
            if existing:
                raise DuplicateJobError(
                    f"An active {operation} job ({existing.id}) for target '{target_clean}' "
                    f"is already {existing.status}."
                )

        jid = job_id or f"job-{job_type.lower()[:6]}-{uuid.uuid4().hex[:12]}"
        now = utc_now()
        sanitized_params = self._sanitize_parameters(parameters or {})

        job = JobModel(
            id=jid,
            investigation_id=investigation_id,
            job_type=job_type,
            operation=operation,
            target=target_clean,
            parameters=sanitized_params,
            status=JOB_STATUS_QUEUED,
            progress=0,
            requested_by=requested_by,
            max_retries=max_retries,
            retry_count=0,
            cancellation_requested=False,
            created_at=now,
            updated_at=now,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        logger.info(
            "Enqueued durable job %s (type=%s, op=%s, target=%s, inv=%s)",
            job.id, job.job_type, job.operation, job.target, job.investigation_id
        )
        return job

    def claim_next_job(
        self,
        db: Session,
        worker_id: str,
        supported_types: Optional[List[str]] = None,
        lease_duration_seconds: int = 60,
    ) -> Optional[JobModel]:
        """Atomically claims the next eligible QUEUED job. Dialect-agnostic via optimistic concurrency update."""
        now = utc_now()
        lease_until = now + timedelta(seconds=lease_duration_seconds)

        stmt = select(JobModel.id).where(
            JobModel.status.in_([JOB_STATUS_QUEUED, JOB_STATUS_RETRY_WAIT]),
            JobModel.cancellation_requested == False,
        )
        if supported_types:
            stmt = stmt.where(JobModel.job_type.in_(supported_types))
        stmt = stmt.order_by(JobModel.created_at.asc()).limit(1)

        candidate_id = db.scalars(stmt).first()
        if not candidate_id:
            return None

        # Atomic claim: only succeeds if status hasn't changed since candidate query
        result = db.execute(
            update(JobModel)
            .where(
                JobModel.id == candidate_id,
                JobModel.status.in_([JOB_STATUS_QUEUED, JOB_STATUS_RETRY_WAIT]),
                JobModel.cancellation_requested == False,
            )
            .values(
                status=JOB_STATUS_CLAIMED,
                worker_id=worker_id,
                lease_expires_at=lease_until,
                heartbeat_at=now,
                updated_at=now,
            )
        )
        if result.rowcount == 1:
            db.commit()
            claimed = db.get(JobModel, candidate_id)
            logger.debug("Worker %s claimed job %s", worker_id, candidate_id)
            return claimed

        db.rollback()
        return None

    def start_job(
        self,
        db: Session,
        job_id: str,
        worker_id: str,
        process_pid: Optional[int] = None,
    ) -> JobModel:
        """Transitions claimed job to RUNNING and records optional OS process PID."""
        job = db.get(JobModel, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found.")

        now = utc_now()
        job.status = JOB_STATUS_RUNNING
        job.started_at = now
        job.updated_at = now
        job.worker_id = worker_id
        job.process_pid = process_pid
        db.commit()
        db.refresh(job)
        return job

    def heartbeat(
        self,
        db: Session,
        job_id: str,
        worker_id: str,
        progress: Optional[int] = None,
        lease_duration_seconds: int = 60,
    ) -> bool:
        """Puts a heartbeat on the job and extends lease. Returns False if job was cancelled or unassigned."""
        now = utc_now()
        lease_until = now + timedelta(seconds=lease_duration_seconds)
        values: Dict[str, Any] = {
            "heartbeat_at": now,
            "lease_expires_at": lease_until,
            "updated_at": now,
        }
        if progress is not None:
            values["progress"] = min(100, max(0, int(progress)))

        result = db.execute(
            update(JobModel)
            .where(
                JobModel.id == job_id,
                JobModel.worker_id == worker_id,
                JobModel.status == JOB_STATUS_RUNNING,
            )
            .values(**values)
        )
        if result.rowcount == 1:
            db.commit()
            return True
        db.rollback()
        return False

    def complete_job(
        self,
        db: Session,
        job_id: str,
        evidence_id: Optional[str] = None,
    ) -> JobModel:
        """Marks a job COMPLETED with 100% progress and duration calculation."""
        job = db.get(JobModel, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found.")

        now = utc_now()
        job.status = JOB_STATUS_COMPLETED
        job.progress = 100
        job.completed_at = now
        job.updated_at = now
        job.evidence_id = evidence_id or job.evidence_id
        if job.started_at:
            job.duration_seconds = max(0.0, (ensure_utc(now) - ensure_utc(job.started_at)).total_seconds())

        db.commit()
        db.refresh(job)
        logger.info("Job %s completed successfully in %.2fs", job.id, job.duration_seconds or 0.0)
        return job

    def fail_job(
        self,
        db: Session,
        job_id: str,
        error_category: str,
        error_message: str,
        allow_retry: bool = True,
    ) -> JobModel:
        """Fails a job or moves it to RETRY_WAIT if retries remain."""
        job = db.get(JobModel, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found.")

        now = utc_now()
        job.error_category = error_category
        job.error_message = error_message
        job.updated_at = now

        if allow_retry and job.retry_count < job.max_retries and not job.cancellation_requested:
            job.retry_count += 1
            job.status = JOB_STATUS_RETRY_WAIT
            logger.warning(
                "Job %s failed (%s: %s). Retrying (attempt %d of %d).",
                job.id, error_category, error_message, job.retry_count, job.max_retries
            )
        else:
            job.status = JOB_STATUS_FAILED
            job.completed_at = now
            if job.started_at:
                job.duration_seconds = max(0.0, (ensure_utc(now) - ensure_utc(job.started_at)).total_seconds())
            logger.error("Job %s failed permanently: %s - %s", job.id, error_category, error_message)

        db.commit()
        db.refresh(job)
        return job

    def request_cancellation(
        self,
        db: Session,
        job_id: str,
        reason: str = "User requested cancellation",
        actor_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Signals durable cancellation request. Immediately cancels QUEUED jobs."""
        job = db.get(JobModel, job_id)
        if not job:
            return False, f"Job '{job_id}' not found."

        if job.is_terminal():
            return False, f"Job '{job_id}' is already in terminal state '{job.status}'."

        now = utc_now()
        job.cancellation_requested = True
        job.cancellation_reason = reason
        job.updated_at = now

        if job.status in (JOB_STATUS_QUEUED, JOB_STATUS_RETRY_WAIT):
            job.status = JOB_STATUS_CANCELLED
            job.completed_at = now
            db.commit()
            logger.info("Job %s was cancelled before execution.", job_id)
            return True, "Job cancelled prior to worker execution."

        # If RUNNING or CLAIMED, flag for worker termination
        job.status = JOB_STATUS_CANCEL_REQUESTED
        db.commit()
        logger.info("Cancellation requested for running job %s.", job_id)
        return True, "Cancellation requested. Worker will terminate the active task."

    def get_job(self, db: Session, job_id: str) -> Optional[JobModel]:
        return db.get(JobModel, job_id)

    def list_investigation_jobs(
        self,
        db: Session,
        investigation_id: str,
        limit: int = 50,
    ) -> List[JobModel]:
        return list(
            db.scalars(
                select(JobModel)
                .where(JobModel.investigation_id == investigation_id)
                .order_by(JobModel.created_at.desc())
                .limit(limit)
            ).all()
        )


_queue_service_instance: Optional[JobQueueService] = None


def get_job_queue() -> JobQueueService:
    global _queue_service_instance
    if _queue_service_instance is None:
        _queue_service_instance = JobQueueService()
    return _queue_service_instance

