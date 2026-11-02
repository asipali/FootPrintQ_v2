"""FastAPI router for administrative target authorization management."""

import uuid
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, ensure_utc
from app.models.user import UserModel
from app.schemas.recon import TargetAuthorizationCreate, TargetAuthorizationResponse, TargetAuthorizationUpdate
from app.api.deps import require_permission, verify_csrf_token
from app.core.auth import log_audit_event
from app.services.target_authorization import (
    classify_target,
    normalize_target,
    is_target_in_investigation_scope,
)
from app.services.investigation_access import require_investigation_access

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}/authorizations", tags=["Target Authorizations"])


@router.post(
    "",
    response_model=TargetAuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create administrative target authorization",
)
def create_target_authorization(
    investigation_id: str,
    payload: TargetAuthorizationCreate,
    request: Request,
    current_user: UserModel = Depends(require_permission("scope.manage")),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Issues an explicit administrative target authorization record permitting reconnaissance operations."""
    investigation = db.get(InvestigationModel, investigation_id)
    investigation = require_investigation_access(investigation, current_user)

    in_scope, reason = is_target_in_investigation_scope(investigation, payload.target)
    if not in_scope:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=reason)
    target_type = classify_target(payload.target)
    if target_type != payload.target_type:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Target type does not match target syntax")
    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)

    auth_record = TargetAuthorizationModel(
        id=f"auth-{uuid.uuid4().hex[:16]}",
        investigation_id=investigation_id,
        target=normalize_target(payload.target),
        target_type=target_type,
        allowed_operations=payload.allowed_operations,
        authorization_reference=payload.authorization_reference.strip(),
        approved_by=current_user.username,
        valid_from=ensure_utc(payload.valid_from) or ensure_utc(datetime.now(timezone.utc)),
        valid_to=ensure_utc(payload.valid_to),
        is_revoked=False,
        notes=payload.notes,
    )
    db.add(auth_record)
    db.commit()
    db.refresh(auth_record)

    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_CREATED",
        outcome="SUCCESS",
        actor_id=current_user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={
            "authorization_id": auth_record.id,
            "investigation_id": investigation_id,
            "target": auth_record.target,
            "allowed_operations": auth_record.allowed_operations,
            "reference": auth_record.authorization_reference,
        },
    )

    return auth_record.to_dict()


@router.get(
    "",
    response_model=List[TargetAuthorizationResponse],
    summary="List target authorizations for investigation",
)
def list_target_authorizations(
    investigation_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Returns all authorization records associated with an investigation."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    require_investigation_access(investigation, current_user)

    stmt = (
        select(TargetAuthorizationModel)
        .where(TargetAuthorizationModel.investigation_id == investigation_id)
        .order_by(TargetAuthorizationModel.created_at.desc())
    )
    records = db.scalars(stmt).all()
    return [r.to_dict() for r in records]


@router.delete(
    "/{authorization_id}",
    summary="Revoke target authorization",
)
def revoke_target_authorization(
    investigation_id: str,
    authorization_id: str,
    request: Request,
    current_user: UserModel = Depends(require_permission("scope.manage")),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Revokes a target authorization record, preventing further reconnaissance against that target."""
    investigation = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    record = db.get(TargetAuthorizationModel, authorization_id)
    if not record or record.investigation_id != investigation_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found")

    if record.is_revoked:
        return {"message": "Authorization record was already revoked", "authorization_id": authorization_id}
    record.is_revoked = True
    db.commit()

    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)
    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_REVOKED",
        outcome="SUCCESS",
        actor_id=current_user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={
            "authorization_id": authorization_id,
            "investigation_id": investigation_id,
            "target": record.target,
        },
    )

    return {"message": "Authorization record successfully revoked", "authorization_id": authorization_id}


@router.patch(
    "/{authorization_id}",
    response_model=TargetAuthorizationResponse,
    summary="Update an authorization record",
)
def update_target_authorization(
    investigation_id: str,
    authorization_id: str,
    payload: TargetAuthorizationUpdate,
    request: Request,
    current_user: UserModel = Depends(require_permission("scope.manage")),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Amends an unrevoked authorization and records the previous values in the audit trail."""
    investigation = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    record = db.get(TargetAuthorizationModel, authorization_id)
    if not record or record.investigation_id != investigation.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found")
    if record.is_revoked:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Revoked authorizations cannot be modified")

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="At least one field must be provided")
    required_values = {"target", "target_type", "allowed_operations", "authorization_reference", "valid_from", "valid_to"}
    if any(name in changes and changes[name] is None for name in required_values):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Required authorization fields cannot be cleared")
    target = changes.get("target", record.target)
    target_type = changes.get("target_type", record.target_type)
    operations = changes.get("allowed_operations", record.allowed_operations)
    valid_from = ensure_utc(changes.get("valid_from", record.valid_from))
    valid_to = ensure_utc(changes.get("valid_to", record.valid_to))
    actual_type = classify_target(target)
    if actual_type == "UNKNOWN" or actual_type != target_type:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Target syntax and target_type must match")
    in_scope, reason = is_target_in_investigation_scope(investigation, target)
    if not in_scope:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=reason)
    now = datetime.now(timezone.utc)
    if valid_from >= valid_to or valid_to <= now:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Authorization window must be valid and expire in the future")
    old_values = {
        "target": record.target,
        "target_type": record.target_type,
        "allowed_operations": record.allowed_operations,
        "authorization_reference": record.authorization_reference,
        "valid_from": ensure_utc(record.valid_from).isoformat(),
        "valid_to": ensure_utc(record.valid_to).isoformat(),
        "notes": record.notes,
    }
    for field, value in changes.items():
        setattr(record, field, value)
    record.target = normalize_target(target)
    record.target_type = actual_type
    record.allowed_operations = operations
    record.valid_from = valid_from
    record.valid_to = valid_to
    db.commit()
    db.refresh(record)
    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_UPDATED",
        outcome="SUCCESS",
        actor_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        details={
            "authorization_id": record.id,
            "investigation_id": investigation.id,
            "previous": old_values,
            "updated_fields": sorted(changes),
        },
    )
    return record.to_dict()
