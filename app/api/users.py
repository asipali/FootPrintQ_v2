"""User management API endpoints restricted to Administrators."""

import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models.user import UserModel, UserSessionModel
from app.schemas.auth import (
    UserResponse,
    UserCreate,
    UserUpdateRole,
    UserUpdateStatus,
)
from app.core.security import (
    hash_password,
    ROLE_ADMINISTRATOR,
    ROLE_INVESTIGATOR,
    VALID_ROLES,
)
from app.core.auth import log_audit_event, transition_investigator_account
from app.api.deps import require_role, verify_csrf_token

router = APIRouter(prefix="/api/v1/users", tags=["User Management"])


@router.get("", response_model=List[UserResponse])
def list_users(
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Lists all user accounts. Restricted to Administrator."""
    stmt = select(UserModel).order_by(UserModel.created_at.desc())
    users = db.scalars(stmt).all()
    return [user.to_dict() for user in users]


@router.get("/pending-investigators", response_model=List[UserResponse])
def list_pending_investigators(
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Lists investigator registrations awaiting an administrator decision."""
    users = db.scalars(
        select(UserModel)
        .where(
            UserModel.role == ROLE_INVESTIGATOR,
            UserModel.account_status == "pending",
        )
        .order_by(UserModel.created_at.asc())
    ).all()
    return [user.to_dict() for user in users]


@router.post("/{user_id}/approve", response_model=UserResponse)
def approve_investigator(
    user_id: str,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Approves a pending investigator. Only administrators may call this endpoint."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        transition_investigator_account(
            db, user, admin, "approve",
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return user.to_dict()


@router.post("/{user_id}/reject", response_model=UserResponse)
def reject_investigator(
    user_id: str,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Rejects a pending investigator. Only administrators may call this endpoint."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        transition_investigator_account(
            db, user, admin, "reject",
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return user.to_dict()


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Provisions a new user account. Restricted to Administrator."""
    # Check username collision
    existing_username = db.scalar(select(UserModel).where(UserModel.username == payload.username))
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already registered",
        )

    # Check email collision
    existing_email = db.scalar(select(UserModel).where(UserModel.email == payload.email))
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{payload.email}' is already registered",
        )

    user = UserModel(
        id=f"usr-{uuid.uuid4().hex[:12]}",
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        event_type="USER_CREATED",
        outcome="SUCCESS",
        actor_id=admin.id,
        target_user_id=user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={"username": user.username, "role": user.role},
    )

    return user.to_dict()


@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id(
    user_id: str,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Retrieves user profile by ID. Restricted to Administrator."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user.to_dict()


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: str,
    payload: UserUpdateRole,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Updates user role. Restricted to Administrator."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_role = user.role
    user.role = payload.role
    db.commit()
    db.refresh(user)

    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        event_type="ROLE_CHANGED",
        outcome="SUCCESS",
        actor_id=admin.id,
        target_user_id=user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={"old_role": old_role, "new_role": user.role},
    )

    return user.to_dict()


@router.patch("/{user_id}/status", response_model=UserResponse)
def update_user_status(
    user_id: str,
    payload: UserUpdateStatus,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Enables or disables user account and revokes active sessions if disabled."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not payload.is_active:
        user.is_active = False
        if user.account_status == "active":
            user.account_status = "disabled"
        # Revoke all active sessions for this user
        for s in user.sessions:
            s.is_revoked = True
    else:
        if user.account_status not in {"active", "disabled"}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Pending or rejected investigators must use the approval workflow.",
            )
        user.is_active = True
        user.account_status = "active"

    db.commit()
    db.refresh(user)

    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        event_type="ACCOUNT_STATUS_CHANGED",
        outcome="SUCCESS",
        actor_id=admin.id,
        target_user_id=user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={"is_active": user.is_active},
    )

    return user.to_dict()
