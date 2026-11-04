"""FastAPI v1 workflow endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from app.application.workflows.services import WorkflowApplicationService
from app.application.workflows.commands import DispatchWorkflowCommand, CancelWorkflowCommand
from app.presentation.api.dependencies import get_workflow_service
from app.api.deps import get_current_user
from app.models.user import UserModel
from app.domain.common.exceptions import (
    EntityNotFoundException,
    UnauthorizedOperationException,
    InvariantViolationException,
)

router = APIRouter(prefix="/workflows", tags=["Workflows"])


@router.post("/dispatch", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
def dispatch_workflow(
    payload: dict,
    current_user: UserModel = Depends(get_current_user),
    service: WorkflowApplicationService = Depends(get_workflow_service),
):
    """Dispatch an investigation workflow into durable queue."""
    cmd = DispatchWorkflowCommand(
        investigation_id=payload["investigation_id"],
        target=payload["target"],
        requested_by=current_user.id,
        enable_active=payload.get("enable_active", False),
        enable_vuln=payload.get("enable_vuln", False),
        params=payload.get("params", {}),
    )
    try:
        job = service.dispatch_workflow(cmd)
        return {
            "job_id": job.id,
            "status": job.status.value,
            "investigation_id": job.investigation_id,
            "target": job.target,
        }
    except EntityNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvariantViolationException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{job_id}/cancel", response_model=dict)
def cancel_workflow(
    job_id: str,
    payload: dict = None,
    current_user: UserModel = Depends(get_current_user),
    service: WorkflowApplicationService = Depends(get_workflow_service),
):
    """Cancel an active workflow job."""
    is_admin = current_user.role == "administrator"
    cmd = CancelWorkflowCommand(
        job_id=job_id,
        requested_by=current_user.id,
        is_admin=is_admin,
        reason=(payload or {}).get("reason"),
    )
    try:
        job = service.cancel_workflow(cmd)
        return {"job_id": job.id, "status": job.status.value}
    except EntityNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UnauthorizedOperationException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

