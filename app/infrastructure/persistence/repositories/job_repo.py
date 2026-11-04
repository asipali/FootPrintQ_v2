"""SQLAlchemy implementation of IJobRepository."""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.application.common.interfaces.repositories import IJobRepository
from app.domain.workflows.entities import WorkflowJob
from app.domain.workflows.value_objects import JobStatus
from app.models.job import JobModel, JOB_STATUS_QUEUED


class SqlAlchemyJobRepository(IJobRepository):
    """Concrete repository mapping between WorkflowJob domain aggregate and SQLAlchemy model."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, job_id: str) -> Optional[WorkflowJob]:
        model = self.session.get(JobModel, job_id)
        return self._to_domain(model) if model else None

    def list_pending(self, limit: int = 10) -> List[WorkflowJob]:
        models = self.session.query(JobModel).filter(
            JobModel.status == JOB_STATUS_QUEUED
        ).order_by(JobModel.created_at.asc()).limit(limit).all()
        return [self._to_domain(m) for m in models]

    def save(self, job: WorkflowJob) -> WorkflowJob:
        model = self.session.get(JobModel, job.id)
        if not model:
            model = JobModel(id=job.id)
            self.session.add(model)

        model.job_type = job.job_type
        model.investigation_id = job.investigation_id
        model.requested_by = job.requested_by
        model.target = job.target
        model.status = job.status.value
        model.progress = job.progress
        model.worker_id = job.worker_id
        model.lease_expires_at = job.lease_expires_at
        model.attempt_count = job.attempt_count
        model.max_retries = job.max_retries
        model.retry_delay_seconds = job.retry_delay_seconds
        model.next_run_at = job.next_run_at
        model.params = dict(job.params or {})
        model.results = dict(job.results or {})
        model.error_message = job.error_message

        self.session.flush()
        return self._to_domain(model)

    @staticmethod
    def _to_domain(model: JobModel) -> WorkflowJob:
        try:
            status_enum = JobStatus(model.status)
        except (ValueError, AttributeError):
            status_enum = JobStatus.QUEUED

        return WorkflowJob(
            id=model.id,
            job_type=model.job_type,
            investigation_id=model.investigation_id,
            requested_by=model.requested_by,
            target=model.target,
            status=status_enum,
            progress=model.progress,
            worker_id=model.worker_id,
            lease_expires_at=model.lease_expires_at,
            attempt_count=model.attempt_count,
            max_retries=model.max_retries,
            retry_delay_seconds=model.retry_delay_seconds,
            next_run_at=model.next_run_at,
            params=dict(model.params or {}),
            results=dict(model.results or {}),
            error_message=model.error_message,
            created_at=model.created_at,
            updated_at=model.updated_at,
            started_at=model.started_at,
            completed_at=model.completed_at,
        )

