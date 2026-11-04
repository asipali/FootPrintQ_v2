"""Investigation update rules and audit recording for REST and web workflows."""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import log_audit_event
from app.core.security import ROLE_ADMINISTRATOR
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.schemas.investigation import InvestigationUpdate
from app.services.workflow.state_machine import (
    validate_transition,
    STATUS_ARCHIVED,
    normalize_status,
)


def update_investigation_record(
    db: Session,
    investigation: InvestigationModel,
    payload: InvestigationUpdate,
    actor: UserModel,
    request_id: str | None = None,
    client_ip: str | None = None,
) -> InvestigationModel:
    """Validate and persist an update, preserving scope data unless explicitly supplied."""
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="At least one field must be provided.")
    if normalize_status(investigation.status) == STATUS_ARCHIVED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Archived investigations cannot be modified.")

    requested_owner = changes.pop("owner_user_id", ...)
    previous_owner = investigation.owner_user_id
    if requested_owner is not ...:
        if actor.role != ROLE_ADMINISTRATOR:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators may reassign investigations.")
        if requested_owner is not None:
            owner = db.get(UserModel, requested_owner)
            if not owner or not owner.is_active or owner.account_status != "active":
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Owner must be an active approved user.")
        investigation.owner_user_id = requested_owner

    new_status = changes.get("status")
    if new_status and normalize_status(new_status) != normalize_status(investigation.status):
        validate_transition(investigation.status, new_status)
        investigation.status = normalize_status(new_status)
        changes.pop("status", None)

    scope = changes.pop("scope", None)
    for field, value in changes.items():
        setattr(investigation, field, value)
    if scope is not None:
        investigation.owned_domains = scope.owned_domains
        investigation.approved_ips = scope.approved_ips
        investigation.approved_cidrs = scope.approved_cidrs
        investigation.active_targets = scope.active_targets

    db.commit()
    db.refresh(investigation)
    log_audit_event(
        db=db,
        event_type="INVESTIGATION_UPDATED",
        outcome="SUCCESS",
        actor_id=actor.id,
        request_id=request_id,
        ip_address=client_ip,
        details={
            "investigation_id": investigation.id,
            "changed_fields": sorted(payload.model_fields_set),
            "previous_owner_user_id": previous_owner,
            "owner_user_id": investigation.owner_user_id,
        },
    )
    return investigation
