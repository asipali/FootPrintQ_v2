"""FastAPI v1 evidence endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status, Response
from app.application.evidence.services import EvidenceApplicationService
from app.application.evidence.commands import GetEvidenceQuery, VerifyEvidenceIntegrityCommand
from app.presentation.api.dependencies import get_evidence_service
from app.api.deps import get_current_user
from app.models.user import UserModel
from app.domain.common.exceptions import EntityNotFoundException, UnauthorizedOperationException

router = APIRouter(prefix="/evidence", tags=["Evidence"])


@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    current_user: UserModel = Depends(get_current_user),
    service: EvidenceApplicationService = Depends(get_evidence_service),
):
    """Download forensic evidence content."""
    is_admin = current_user.role == "administrator"
    try:
        item, data = service.get_evidence_content(
            GetEvidenceQuery(evidence_id=evidence_id, user_id=current_user.id, is_admin=is_admin)
        )
        return Response(content=data, media_type="application/octet-stream")
    except EntityNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UnauthorizedOperationException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post("/{evidence_id}/verify", response_model=dict)
def verify_evidence(
    evidence_id: str,
    current_user: UserModel = Depends(get_current_user),
    service: EvidenceApplicationService = Depends(get_evidence_service),
):
    """Verify cryptographic integrity of evidence file."""
    try:
        valid, message = service.verify_integrity(VerifyEvidenceIntegrityCommand(evidence_id=evidence_id))
        return {"evidence_id": evidence_id, "valid": valid, "message": message}
    except EntityNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

