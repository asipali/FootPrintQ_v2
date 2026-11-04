"""FastAPI router for findings and evidence correlation engine."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_permission, verify_csrf_token
from app.database import get_db
from app.models.correlation import CorrelationRecordModel
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.schemas.correlation import (
    CorrelationRecordResponse,
    InvestigationCorrelationResponse,
)
from app.services.correlation.engine import CorrelationEngine
from app.services.investigation_access import require_investigation_access

logger = logging.getLogger("footprintiq.api.correlations")

router = APIRouter(tags=["Finding & Evidence Correlation"])


@router.get(
    "/api/v1/investigations/{investigation_id}/correlations",
    response_model=InvestigationCorrelationResponse,
    summary="Get cross-stage correlated finding assets, relationships, and evidence graph",
)
def get_investigation_correlations(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
    relationship_type: Optional[str] = Query(None, description="Filter by CONFIRMED_MATCH, STRONG_MATCH, etc."),
    asset: Optional[str] = Query(None, description="Filter by asset identifier"),
    verification_status: Optional[str] = Query(None, description="Filter by VERIFIED, HASH_MISMATCH, etc."),
) -> InvestigationCorrelationResponse:
    """Returns cross-source correlated asset profiles, provenance, and graph representation."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")
    inv = require_investigation_access(inv, current_user)

    engine = CorrelationEngine(db)
    result = engine.run_correlation(investigation_id=inv.id)

    # Apply optional query filters on the correlations list
    corrs = result.get("correlations", [])
    if relationship_type:
        corrs = [c for c in corrs if c.get("relationship_type") == relationship_type.upper()]
    if asset:
        corrs = [c for c in corrs if asset.lower() in str(c.get("asset_identifier", "")).lower()]
    if verification_status:
        corrs = [c for c in corrs if c.get("evidence_verification_status") == verification_status.upper()]

    result["correlations"] = corrs
    return InvestigationCorrelationResponse(**result)


@router.post(
    "/api/v1/investigations/{investigation_id}/correlations/refresh",
    response_model=InvestigationCorrelationResponse,
    summary="Recompute and refresh deterministic correlation records",
)
def refresh_investigation_correlations(
    investigation_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission("investigation.view")),
    csrf_ok: None = Depends(verify_csrf_token),
) -> InvestigationCorrelationResponse:
    """Deterministically re-executes correlation engine and updates persisted records."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")
    inv = require_investigation_access(inv, current_user)

    engine = CorrelationEngine(db)
    result = engine.run_correlation(investigation_id=inv.id)
    return InvestigationCorrelationResponse(**result)


@router.get(
    "/api/v1/investigations/{investigation_id}/correlations/{correlation_id}",
    response_model=CorrelationRecordResponse,
    summary="Get single correlation record with full provenance and evidence integrity",
)
def get_correlation_record(
    investigation_id: str,
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
) -> CorrelationRecordResponse:
    """Returns a specific correlation record by ID ensuring tenant and investigation isolation."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")
    inv = require_investigation_access(inv, current_user)

    record = db.scalar(
        select(CorrelationRecordModel).where(
            CorrelationRecordModel.id == correlation_id,
            CorrelationRecordModel.investigation_id == inv.id,
        )
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation record '{correlation_id}' not found in investigation '{investigation_id}'.",
        )

    return CorrelationRecordResponse(**record.to_dict())

