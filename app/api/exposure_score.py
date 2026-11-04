"""FastAPI router for Exposure Scoring engine endpoints."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_permission, verify_csrf_token
from app.database import get_db
from app.models.exposure_score import ExposureScoreModel
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.schemas.exposure_score import (
    ExposureScoreCalculateRequest,
    ExposureScoreComparisonResponse,
    ExposureScoreHistoryResponse,
    ExposureScoreResponse,
)
from app.services.investigation_access import require_investigation_access
from app.services.scoring.calculator import DEFAULT_SCORING_MODEL, SCORING_MODELS, ExposureScorer

logger = logging.getLogger("footprintiq.api.exposure_score")

router = APIRouter(tags=["Exposure Scoring Engine"])


@router.get(
    "/api/v1/investigations/{investigation_id}/exposure-score",
    response_model=ExposureScoreResponse,
    summary="Get active 5-factor exposure score for an investigation",
)
def get_active_exposure_score(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
) -> ExposureScoreResponse:
    """Returns the current active exposure score with complete factor contributions and coverage."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )
    inv = require_investigation_access(inv, current_user)

    # Check for persisted active score
    active_record = db.scalars(
        select(ExposureScoreModel).where(
            ExposureScoreModel.investigation_id == inv.id,
            ExposureScoreModel.is_active == True,
        ).order_by(ExposureScoreModel.created_at.desc())
    ).first()

    if not active_record:
        # Calculate and persist
        breakdown = ExposureScorer.calculate_for_investigation(
            investigation_id=inv.id,
            db=db,
            model_version=DEFAULT_SCORING_MODEL,
            persist=True,
        )
        db.commit()
        active_record = db.scalars(
            select(ExposureScoreModel).where(
                ExposureScoreModel.investigation_id == inv.id,
                ExposureScoreModel.is_active == True,
            ).order_by(ExposureScoreModel.created_at.desc())
        ).first()

    return ExposureScoreResponse(**active_record.to_dict())


@router.post(
    "/api/v1/investigations/{investigation_id}/exposure-score/calculate",
    response_model=ExposureScoreResponse,
    summary="Recalculate and persist exposure score under specified formula version",
)
def calculate_investigation_exposure_score(
    investigation_id: str,
    payload: ExposureScoreCalculateRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission("investigation.view")),
    _csrf: None = Depends(verify_csrf_token),
) -> ExposureScoreResponse:
    """Calculates, explains, and persists an exposure score under v3.0-5factor or v1.0-legacy."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )
    inv = require_investigation_access(inv, current_user)

    if payload.model_version not in SCORING_MODELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported formula model '{payload.model_version}'. Supported models: {list(SCORING_MODELS.keys())}",
        )

    breakdown = ExposureScorer.calculate_for_investigation(
        investigation_id=inv.id,
        db=db,
        model_version=payload.model_version,
        reviewer_notes=payload.reviewer_notes,
        persist=True,
    )
    db.commit()

    active_record = db.scalars(
        select(ExposureScoreModel).where(
            ExposureScoreModel.investigation_id == inv.id,
            ExposureScoreModel.is_active == True,
        ).order_by(ExposureScoreModel.created_at.desc())
    ).first()

    return ExposureScoreResponse(**active_record.to_dict())


@router.get(
    "/api/v1/investigations/{investigation_id}/exposure-score/history",
    response_model=ExposureScoreHistoryResponse,
    summary="Get exposure score calculation history for an investigation",
)
def get_exposure_score_history(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
) -> ExposureScoreHistoryResponse:
    """Returns chronological audit trail of all exposure score calculations."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )
    inv = require_investigation_access(inv, current_user)

    history = ExposureScorer.get_score_history(investigation_id=inv.id, db=db)
    score_objs = [ExposureScoreResponse(**item) for item in history]

    return ExposureScoreHistoryResponse(
        investigation_id=inv.id,
        total_records=len(score_objs),
        scores=score_objs,
    )


@router.get(
    "/api/v1/investigations/{investigation_id}/exposure-score/{score_id}",
    response_model=ExposureScoreResponse,
    summary="Get single historical exposure score record",
)
def get_single_exposure_score(
    investigation_id: str,
    score_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
) -> ExposureScoreResponse:
    """Returns specific historical score record by ID."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )
    inv = require_investigation_access(inv, current_user)

    record = db.get(ExposureScoreModel, score_id)
    if not record or record.investigation_id != inv.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Score record '{score_id}' not found for investigation '{investigation_id}'.",
        )

    return ExposureScoreResponse(**record.to_dict())

