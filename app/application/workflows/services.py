"""Workflow application service coordinating asynchronous investigation jobs."""

import uuid
from typing import Optional, List
from app.application.common.interfaces.uow import IUnitOfWork
from app.application.workflows.commands import DispatchWorkflowCommand, CancelWorkflowCommand, RecoverOrphanedJobsCommand
from app.domain.workflows.entities import WorkflowJob
from app.domain.workflows.value_objects import JobStatus
from app.domain.investigations.value_objects import InvestigationState
from app.domain.common.exceptions import (
    EntityNotFoundException,
    UnauthorizedOperationException,
    InvariantViolationException,
)
from app.domain.audit.entities import SecurityAuditEvent
from app.domain.audit.value_objects import AuditAction


class WorkflowApplicationService:
    """Manages dispatch, cancellation, and execution lifecycle of workflow jobs."""

    def __init__(self, uow: IUnitOfWork):
        self.uow = uow

    def dispatch_workflow(self, cmd: DispatchWorkflowCommand) -> WorkflowJob:
        """Enqueue workflow job after validating authorization and investigation state."""
        with self.uow:
            inv = self.uow.investigations.get_by_id(cmd.investigation_id)
            if not inv:
                raise EntityNotFoundException(f"Investigation '{cmd.investigation_id}' not found.")
            if not inv.can_execute_workflows():
                raise InvariantViolationException(
                    f"Investigation state '{inv.status.value}' does not permit workflow dispatch."
                )

            # Check target authorization if active or vuln scanning requested
            if cmd.enable_active or cmd.enable_vuln:
                auth = self.uow.authorizations.find_active(cmd.investigation_id, cmd.target)
                if not auth:
                    raise InvariantViolationException(
                        f"Active scanning requires an active target authorization for '{cmd.target}'."
                    )

            job_id = f"job-wf-{uuid.uuid4().hex[:12]}"
            job = WorkflowJob(
                id=job_id,
                job_type="investigation_workflow",
                investigation_id=cmd.investigation_id,
                requested_by=cmd.requested_by,
                target=cmd.target,
                status=JobStatus.QUEUED,
                params={
                    "enable_active": cmd.enable_active,
                    "enable_vuln": cmd.enable_vuln,
                    **cmd.params,
                },
            )

            # Transition investigation state to QUEUED
            if inv.status in (InvestigationState.READY, InvestigationState.ACTIVE):
                inv.transition_to(InvestigationState.QUEUED)
                self.uow.investigations.save(inv)

            saved_job = self.uow.jobs.save(job)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.WORKFLOW_DISPATCH.value,
                    actor_id=cmd.requested_by,
                    details={"job_id": job_id, "investigation_id": cmd.investigation_id, "target": cmd.target},
                )
            )
            self.uow.commit()

        return saved_job

    def cancel_workflow(self, cmd: CancelWorkflowCommand) -> WorkflowJob:
        """Request cooperative cancellation of a running workflow job."""
        with self.uow:
            job = self.uow.jobs.get_by_id(cmd.job_id)
            if not job:
                raise EntityNotFoundException(f"Job '{cmd.job_id}' not found.")
            if job.is_terminal():
                return job

            inv = self.uow.investigations.get_by_id(job.investigation_id)
            if inv and not inv.is_user_authorized(cmd.requested_by, cmd.is_admin):
                raise UnauthorizedOperationException("Unauthorized to cancel this workflow.")

            job.status = JobStatus.CANCEL_REQUESTED
            saved = self.uow.jobs.save(job)
            self.uow.audit_logs.log_event(
                SecurityAuditEvent(
                    id=f"audit-{uuid.uuid4().hex[:8]}",
                    event_type=AuditAction.WORKFLOW_CANCEL.value,
                    actor_id=cmd.requested_by,
                    details={"job_id": cmd.job_id, "reason": cmd.reason},
                )
            )
            self.uow.commit()
            return saved

