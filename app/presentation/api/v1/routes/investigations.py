"""FastAPI v1 investigation endpoints delegating to application use cases."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from app.application.investigations.services import InvestigationApplicationService
from app.application.investigations.commands import CreateInvestigationCommand, TransitionInvestigationStatusCommand
from app.application.investigations.queries import GetInvestigationQuery, ListInvestigationsQuery, InvestigationDTO
from app.presentation.api.dependencies import get_investigation_service
from app.api.deps import get_current_user
from app.models.user import UserModel
from app.domain.common.exceptions import (
    EntityNotFoundException,
    UnauthorizedOperationException,
    InvalidStateTransitionException,
)

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.get("", response_model=List[dict])
def list_investigations(
    limit: int = 100,
    offset: int = 0,
    current_user: UserModel = Depends(get_current_user),
    service: InvestigationApplicationService = Depends(get_investigation_service),
):
    """List investigations accessible to caller."""
    is_admin = current_user.role == "administrator"
    query = ListInvestigationsQuery(user_id=current_user.id, is_admin=is_admin, limit=limit, offset=offset)
    results = service.list_investigations(query)
    return [r.__dict__ for r in results]


@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
def create_investigation(
    payload: dict,
    current_user: UserModel = Depends(get_current_user),
    service: InvestigationApplicationService = Depends(get_investigation_service),
):
    """Create a new investigation."""
    scope = payload.get("scope", {})
    cmd = CreateInvestigationCommand(
        name=payload["name"],
        organization_name=payload["organization_name"],
        description=payload.get("description", ""),
        lead_investigator=payload.get("lead_investigator", current_user.username),
        owner_user_id=current_user.id,
        custom_id=payload.get("id"),
        team_members=payload.get("team_members", []),
        owned_domains=scope.get("owned_domains", []),
        approved_ips=scope.get("approved_ips", []),
        approved_cidrs=scope.get("approved_cidrs", []),
        active_targets=scope.get("active_targets", []),
        active_scanning_enabled=payload.get("active_scanning_enabled", False),
        authorization_reference=payload.get("authorization_reference"),
    )
    result = service.create_investigation(cmd)
    return result.__dict__


@router.get("/{investigation_id}", response_model=dict)
def get_investigation(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    service: InvestigationApplicationService = Depends(get_investigation_service),
):
    """Retrieve investigation by ID."""
    is_admin = current_user.role == "administrator"
    try:
        dto = service.get_investigation(
            GetInvestigationQuery(investigation_id=investigation_id, user_id=current_user.id, is_admin=is_admin)
        )
        return dto.__dict__
    except EntityNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UnauthorizedOperationException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post("/{investigation_id}/transition", response_model=dict)
def transition_investigation(
    investigation_id: str,
    payload: dict,
    current_user: UserModel = Depends(get_current_user),
    service: InvestigationApplicationService = Depends(get_investigation_service),
):
    """Transition investigation lifecycle status."""
    is_admin = current_user.role == "administrator"
    target_status = payload.get("status")
    if not target_status:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Field 'status' is required.")

    cmd = TransitionInvestigationStatusCommand(
        investigation_id=investigation_id,
        new_status=target_status,
        user_id=current_user.id,
        is_admin=is_admin,
        reason=payload.get("reason"),
    )
    try:
        dto = service.transition_status(cmd)
        return dto.__dict__
    except EntityNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UnauthorizedOperationException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

