import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.database import get_db
from app.models.investigation import InvestigationModel
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationResponse,
    InvestigationUpdate,
    WorkflowStartRequest,
    WorkflowCancelRequest,
)
from app.services.workflow.orchestrator import InvestigationWorkflowOrchestrator
from app.services.workflow.correlation import InvestigationCorrelationService
from app.services.reporting.pdf_generator import InvestigationReportGenerator
from app.logging_config import get_logger

from app.api.deps import get_current_user_optional, verify_csrf_token
from app.core.security import has_permission
from app.core.auth import log_audit_event
from app.services.reporting.graphml_generator import GraphMLExporter
from app.models.user import UserModel
from app.services.investigation_access import require_investigation_access
from app.services.investigation_management import update_investigation_record
from sqlalchemy.exc import IntegrityError

logger = get_logger("footprintiq.api.investigations")

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


@router.get("", response_model=List[InvestigationResponse])
def list_investigations(
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Lists all registered investigations in the database."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.view",
        )

    stmt = select(InvestigationModel).order_by(InvestigationModel.created_at.desc())
    if current_user.role != "administrator":
        stmt = stmt.where(InvestigationModel.owner_user_id == current_user.id)
    results = db.scalars(stmt).all()

    # Map model attributes to response schema
    responses = []
    for inv in results:
        data = inv.to_dict()
        responses.append(InvestigationResponse(
            id=data["id"],
            name=data["name"],
            organization_name=data["organization_name"],
            description=data["description"],
            lead_investigator=data["lead_investigator"],
            owner_user_id=inv.owner_user_id,
            team_members=data["team_members"],
            status=data["status"],
            scope=data["scope"],
            active_scanning_enabled=data["active_scanning_enabled"],
            authorization_reference=data["authorization_reference"],
            authorization_expiry=inv.authorization_expiry,
            created_at=inv.created_at,
            updated_at=inv.updated_at
        ))
    return responses


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def create_investigation(
    payload: InvestigationCreate,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Registers a new investigation and persists target scopes."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.create",
        )
    """Registers a new investigation and persists target scopes."""
    inv_id = payload.id or f"inv-{uuid.uuid4().hex[:8]}"

    existing = db.get(InvestigationModel, inv_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation with identifier '{inv_id}' already exists."
        )

    model = InvestigationModel(
        id=inv_id,
        name=payload.name,
        organization_name=payload.organization_name,
        description=payload.description,
        lead_investigator=current_user.full_name or current_user.username,
        owner_user_id=current_user.id,
        team_members=payload.team_members,
        status=payload.status,
        owned_domains=payload.scope.owned_domains,
        approved_ips=payload.scope.approved_ips,
        approved_cidrs=payload.scope.approved_cidrs,
        active_targets=payload.scope.active_targets,
        active_scanning_enabled=payload.active_scanning_enabled,
        authorization_reference=payload.authorization_reference,
        authorization_expiry=payload.authorization_expiry
    )

    db.add(model)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Investigation identifier is already in use.",
        ) from exc
    db.refresh(model)

    logger.info(f"Created investigation '{model.name}' ({model.id}) for '{model.organization_name}' by user '{current_user.username}'")

    data = model.to_dict()
    return InvestigationResponse(
        id=data["id"],
        name=data["name"],
        organization_name=data["organization_name"],
        description=data["description"],
        lead_investigator=data["lead_investigator"],
        owner_user_id=model.owner_user_id,
        team_members=data["team_members"],
        status=data["status"],
        scope=data["scope"],
        active_scanning_enabled=data["active_scanning_enabled"],
        authorization_reference=data["authorization_reference"],
        authorization_expiry=model.authorization_expiry,
        created_at=model.created_at,
        updated_at=model.updated_at
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Retrieves an individual investigation by ID."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.view",
        )

    model = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)

    data = model.to_dict()
    return InvestigationResponse(
        id=data["id"],
        name=data["name"],
        organization_name=data["organization_name"],
        description=data["description"],
        lead_investigator=data["lead_investigator"],
        owner_user_id=model.owner_user_id,
        team_members=data["team_members"],
        status=data["status"],
        scope=data["scope"],
        active_scanning_enabled=data["active_scanning_enabled"],
        authorization_reference=data["authorization_reference"],
        authorization_expiry=model.authorization_expiry,
        created_at=model.created_at,
        updated_at=model.updated_at
    )


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
def update_investigation(
    investigation_id: str,
    payload: InvestigationUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Updates an owned investigation; archival is the non-destructive close operation."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "investigation.create"):
        raise HTTPException(status_code=403, detail="Operation requires permission: investigation.create")
    model = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    model = update_investigation_record(
        db=db,
        investigation=model,
        payload=payload,
        actor=current_user,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request.client.host if request.client else None,
    )
    data = model.to_dict()
    return InvestigationResponse(**data)


@router.get("/{investigation_id}/export/graphml")
def export_investigation_graphml(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Exports investigation entities, hosts, ports, and vulnerabilities as standard GraphML XML."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.view",
        )

    model = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    if not has_permission(current_user.role, "report.export"):
        raise HTTPException(status_code=403, detail="Operation requires permission: report.export")

    try:
        xml_content = GraphMLExporter.generate_graphml(investigation_id=investigation_id, db=db)
    except Exception:
        logger.exception("GraphML export failed for investigation %s", investigation_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate GraphML export.",
        )

    log_audit_event(
        db=db,
        event_type="REPORT_EXPORT",
        actor_id=current_user.id,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "GRAPHML"},
    )

    filename = f"knowledge_graph_{investigation_id}.graphml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


# -----------------------------------------------------------------------------
# End-to-End Investigation Workflow Endpoints
# -----------------------------------------------------------------------------

@router.post("/{investigation_id}/workflow/start")
async def start_investigation_workflow(
    investigation_id: str,
    payload: WorkflowStartRequest = WorkflowStartRequest(),
    request: Request = None,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Executes the full multi-stage forensic investigation workflow."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "investigation.create"):
        raise HTTPException(status_code=403, detail="Operation requires permission: investigation.create")

    inv = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    orchestrator = InvestigationWorkflowOrchestrator(db=db)

    try:
        summary = await orchestrator.execute_workflow(
            investigation_id=investigation_id,
            actor_user=current_user,
            target=payload.target,
            scan_profile_id=payload.scan_profile_id or "service_inventory",
            vuln_profile_id=payload.vuln_profile_id or "full_and_fast",
            client_ip=request.client.host if request and request.client else None,
            request_id=getattr(request.state, "request_id", None) if request and hasattr(request, "state") else None,
        )
        return summary
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))


@router.post("/{investigation_id}/workflow/dispatch")
def dispatch_investigation_workflow(
    investigation_id: str,
    payload: WorkflowStartRequest = WorkflowStartRequest(),
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Dispatches investigation workflow execution as a durable, asynchronous background job."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "investigation.create"):
        raise HTTPException(status_code=403, detail="Operation requires permission: investigation.create")

    require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    orchestrator = InvestigationWorkflowOrchestrator(db=db)

    try:
        job = orchestrator.dispatch_workflow(
            investigation_id=investigation_id,
            actor_user=current_user,
            target=payload.target,
            scan_profile_id=payload.scan_profile_id or "service_inventory",
            vuln_profile_id=payload.vuln_profile_id or "full_and_fast",
        )
        return job.to_dict()
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.get("/{investigation_id}/workflow/status")
def get_investigation_workflow_status(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Returns the current workflow status, progress, and stage execution summary."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(status_code=403, detail="Operation requires permission: investigation.view")

    inv = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)

    from app.models.job import JobModel
    jobs = db.scalars(
        select(JobModel).where(JobModel.investigation_id == investigation_id).order_by(JobModel.created_at.desc())
    ).all()

    return {
        "investigation_id": inv.id,
        "investigation_name": inv.name,
        "status": inv.status,
        "active_scanning_enabled": inv.active_scanning_enabled,
        "total_jobs_count": len(jobs),
        "jobs": [j.to_dict() for j in jobs[:20]],
    }


@router.post("/{investigation_id}/workflow/cancel")
def cancel_investigation_workflow(
    investigation_id: str,
    payload: WorkflowCancelRequest = WorkflowCancelRequest(),
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Cancels running workflow stages and aborts active queue items."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "investigation.create"):
        raise HTTPException(status_code=403, detail="Operation requires permission: investigation.create")

    require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    orchestrator = InvestigationWorkflowOrchestrator(db=db)
    return orchestrator.cancel_workflow(
        investigation_id=investigation_id,
        actor_user=current_user,
        reason=payload.reason,
    )


@router.get("/{investigation_id}/workflow/correlation")
def get_investigation_correlation(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Returns cross-stage correlated finding assets, evidence provenance, and entity graph."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(status_code=403, detail="Operation requires permission: investigation.view")

    require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    service = InvestigationCorrelationService(db=db)
    try:
        return service.correlate_investigation(investigation_id=investigation_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))


@router.get("/{investigation_id}/workflow/report/pdf")
def get_investigation_pdf_report(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Generates and downloads the consolidated investigation dossier PDF."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not has_permission(current_user.role, "report.export"):
        raise HTTPException(status_code=403, detail="Operation requires permission: report.export")

    require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)

    try:
        pdf_bytes = InvestigationReportGenerator.generate_pdf(
            investigation_id=investigation_id,
            db=db,
            generated_by=current_user.full_name or current_user.username,
        )
    except Exception as e:
        logger.exception("PDF report generation failed for %s", investigation_id)
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")

    log_audit_event(
        db=db,
        event_type="REPORT_EXPORT",
        actor_id=current_user.id,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "PDF"},
    )

    filename = f"investigation_report_{investigation_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )

