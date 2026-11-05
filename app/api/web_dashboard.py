"""Web dashboard routes for FootprintIQ serving Jinja2 templates and HTMX components."""

import os
import asyncio
import uuid
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Request, Depends, Form, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, func, or_, case
from urllib.parse import quote

from app.config import get_settings
from app.database import get_db, check_database_connection, SessionLocal
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.logging_config import get_logger
from app.services.investigation_access import require_investigation_access
from app.schemas.recon import TargetAuthorizationCreate
from app.schemas.investigation import InvestigationCreate, ScopeSchema
from app.services.target_authorization import is_target_in_investigation_scope, normalize_target
from pydantic import ValidationError
from app.models.recon import TargetAuthorizationModel, CollectionJobModel, EvidenceModel, EntityModel
from app.models.scan import ActiveScanJobModel, ScanFindingPortModel, ScanFindingHostModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.models.audit import AuditLogModel
from app.api.deps import get_current_user_optional, get_current_user, require_role
from app.core.security import generate_csrf_token, is_safe_redirect_url
from app.core.auth import (
    change_user_password,
    log_audit_event,
    transition_investigator_account,
    toggle_investigator_active_status,
)
from app.core.security import ROLE_ADMINISTRATOR, has_permission
from app.services.scoring.calculator import ExposureScorer
from app.services.reporting.pdf_generator import InvestigationReportGenerator
from app.services.reporting.graphml_generator import GraphMLExporter
from app.services.active.nmap_detector import NmapDetector
from app.integrations.greenbone_client import GreenboneClient
from app.services.passive.orchestrator import PassiveReconOrchestrator
from app.services.active.runner import get_nmap_runner, NmapExecutionError
from app.services.active.profiles import get_scan_profile
from app.services.vuln.orchestrator import get_vuln_orchestrator, VulnerabilityAssessmentError
from app.services.vuln.profiles import get_vuln_profile
from app.services.correlation.engine import CorrelationEngine

import fastapi

settings = get_settings()
logger = get_logger("footprintiq.api.web_dashboard")
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(include_in_schema=False)

FEATURE_CARDS = [
    {
        "mark": "01",
        "title": "Passive Reconnaissance",
        "body": "Collect and organize public domain intelligence through the platform's passive collection workflow, including DNS & Domain Intelligence, RDAP, and WHOIS sources.",
        "badge": "Available",
        "badge_class": "badge-passive",
        "url": "/scans#passive-recon",
        "action_text": "Open passive recon",
    },
    {
        "mark": "02",
        "title": "Investigation Management",
        "body": "Create investigation records, document scope and context, and review associated collection and assessment activity.",
        "badge": "Available",
        "badge_class": "badge-brand",
        "url": "/investigations",
        "action_text": "Open investigations",
    },
    {
        "mark": "03",
        "title": "Network Assessment (Nmap)",
        "body": "Run configured Nmap profiles only when the target is explicitly authorized within the investigation.",
        "badge": "AUTHORIZED TARGETS ONLY",
        "badge_class": "badge-active",
        "url": "/scans#nmap-scans",
        "action_text": "Open network scans",
    },
    {
        "mark": "04",
        "title": "Vulnerability Assessment",
        "body": "Manage Greenbone vulnerability assessment jobs and track correlated CVE findings across authorized targets.",
        "badge": "REQUIRES GVM DAEMON",
        "badge_class": "badge-info",
        "url": "/findings",
        "action_text": "Explore findings",
    },
    {
        "mark": "05",
        "title": "Evidence Management",
        "body": "Review stored evidence with timestamps, provenance details, and cryptographically verified SHA-256 integrity hashes.",
        "badge": "CRYPTOGRAPHICALLY VERIFIED",
        "badge_class": "badge-passive",
        "url": "/evidence",
        "action_text": "Open evidence ledger",
    },
    {
        "mark": "06",
        "title": "Investigation Reports",
        "body": "Export investigation reports and forensic dossiers in supported PDF and GraphML formats.",
        "badge": "PDF & GRAPHML SUPPORTED",
        "badge_class": "badge-brand",
        "url": "/investigations",
        "action_text": "View report exports",
    },
    {
        "mark": "07",
        "title": "Authentication and Access Control",
        "body": "Use server-managed sessions, role and permission checks, CSRF defenses, and administrator review of pending investigators.",
        "badge": "ROLE-BASED ACCESS",
        "badge_class": "badge-amber",
        "url": "/admin/investigators",
        "action_text": "Manage access control",
    },
]

PUBLIC_PAGES = {
    "features": {
        "title": "Platform capabilities",
        "heading": "A practical workspace for digital footprint investigations.",
        "description": "Use the capabilities implemented in FootprintIQ to organize passive intelligence, authorized assessments, evidence, and reports. Optional integrations depend on your deployment.",
        "eyebrow": "Platform",
        "layout": "cards",
        "items": FEATURE_CARDS,
        "notice": "Scanner availability depends on the local deployment. Active scanning is restricted to explicitly authorized targets.",
    },
    "how-it-works": {
        "title": "How it works",
        "heading": "A clear path from scope to report.",
        "description": "FootprintIQ organizes investigation tasks in a sequence that keeps engagement context, collection, assessment, and evidence together.",
        "eyebrow": "Investigation workflow",
        "layout": "steps",
        "items": [
            {"title": "Create an investigation", "body": "Record an investigation name, purpose, organization, lead investigator, and engagement context."},
            {"title": "Define authorized scope", "body": "Document domain and network scope. Explicit authorization records are required for active assessment targets."},
            {"title": "Collect passive intelligence", "body": "Run supported passive collectors and review their results as entities and evidence associated with the investigation."},
            {"title": "Perform permitted assessments", "body": "Use configured Nmap or Greenbone workflows only when their required tools are available and the target is authorized."},
            {"title": "Organize findings and evidence", "body": "Review collected evidence, vulnerability findings, scan results, and provenance in the investigation workspace."},
            {"title": "Generate reports", "body": "Export supported PDF reports and GraphML investigation data for review and documentation."},
        ],
        "notice": "All active scanning requires explicit target authorization records and is enforced by backend checks.",
    },
    "use-cases": {
        "title": "Use cases",
        "heading": "Built for careful, authorized investigation work.",
        "description": "FootprintIQ provides an organized workflow for teams that need to document scope, collect public intelligence, and preserve findings.",
        "eyebrow": "Who it is for",
        "layout": "cards",
        "items": [
            {"title": "Cybersecurity investigations", "body": "Keep investigation context, collection jobs, findings, and exports associated with a defined case."},
            {"title": "Digital footprint analysis", "body": "Review supported public domain and DNS information as part of a documented investigation."},
            {"title": "Domain exposure assessment", "body": "Organize passive domain intelligence and assess in-scope exposure with supported collection workflows."},
            {"title": "Authorized network assessments", "body": "Run Nmap or vulnerability assessment workflows only for targets covered by the engagement's authorization."},
            {"title": "Security research and documentation", "body": "Track evidence provenance and prepare PDF or GraphML outputs for research and review."},
            {"title": "Investigator collaboration", "body": "Use investigator accounts subject to administrator approval and role-based access controls."},
        ],
    },
    "security": {
        "title": "Security and responsible use",
        "heading": "Security controls are part of the workflow.",
        "description": "FootprintIQ includes application-level controls for account access, browser sessions, request protection, and authorized scanning. These controls do not replace deployment hardening or an organization's security program.",
        "eyebrow": "Security overview",
        "layout": "cards",
        "items": [
            {"title": "Authentication", "body": "Passwords are stored as hashes. Browser sessions are managed server-side and issued through HTTP-only cookies."},
            {"title": "Role-based access", "body": "Roles and permission checks protect API operations, administrative functions, and operational pages."},
            {"title": "Investigator approval", "body": "When public registration is enabled, new accounts are pending and cannot access the application until approved by an administrator."},
            {"title": "Session and request protections", "body": "Browser forms use CSRF validation. Session revocation and expiry are checked by the server; cookie transport settings depend on deployment configuration."},
            {"title": "Active scanning authorization", "body": "Nmap and vulnerability assessment targets are checked against explicit authorization records before active work is allowed."},
            {"title": "Evidence handling", "body": "Evidence records include provenance details and SHA-256 hashes. Administrators can review audit events for important actions."},
        ],
        "notice": "No certification, compliance attestation, or security guarantee is implied by these application controls.",
        "notice_id": "responsible-use",
    },
    "about": {
        "title": "About FootprintIQ",
        "heading": "A workspace for responsible digital footprint investigations.",
        "description": "FootprintIQ is an application for organizing authorized cybersecurity reconnaissance and investigation records.",
        "eyebrow": "About",
        "layout": "cards",
        "items": [
            {"title": "Purpose", "body": "Bring investigation context, supported passive collection, authorized assessments, evidence, and reporting into one workflow."},
            {"title": "Intended users", "body": "Security investigators, analysts, educators, and research teams working within authorized scopes."},
            {"title": "Responsible by design", "body": "Active assessments are restricted by target authorization checks, and new investigator access can require administrator approval."},
        ],
    },
    "faq": {
        "title": "Frequently asked questions",
        "heading": "Questions about using FootprintIQ.",
        "description": "A concise guide to access, investigations, integrations, and responsible use.",
        "eyebrow": "FAQ",
        "layout": "faq",
        "items": [
            {"title": "Who can access the application?", "body": "Users must sign in with an active account. Public investigator registration can be enabled or disabled by the application administrator; submitted accounts remain pending until approved."},
            {"title": "Does FootprintIQ scan arbitrary targets?", "body": "No. Active Nmap and vulnerability assessment workflows require explicit authorization records covering the target."},
            {"title": "Which integrations are required?", "body": "Passive collection uses the configured collectors. Nmap and Greenbone functions depend on their respective tools and services being available in the deployment."},
            {"title": "What can I export?", "body": "The implemented investigation reporting workflows support PDF and GraphML exports."},
            {"title": "How is evidence integrity represented?", "body": "Evidence records include a SHA-256 integrity hash alongside provenance metadata."},
            {"title": "Does FootprintIQ provide a compliance certification?", "body": "No. The application does not claim certifications or compliance attestations. Operators are responsible for deployment configuration, access management, and applicable policies."},
        ],
    },
}


def _validate_csrf(request: Request, submitted_csrf: str):
    """Verifies CSRF token from form matches cookie."""
    expected = request.cookies.get(settings.CSRF_COOKIE_NAME)
    if not expected or not submitted_csrf or not hmac.compare_digest(submitted_csrf.strip(), expected.strip()):
        raise StarletteHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security validation failed (CSRF token mismatch or expired). Please reload the page."
        )


def _base_context(request: Request, db: Session, active_nav: str = "") -> Dict[str, Any]:
    """Returns standard template context parameters."""
    current_user = get_current_user_optional(request, db=db)
    is_connected, _ = check_database_connection(db)
    csrf_token = request.cookies.get(settings.CSRF_COOKIE_NAME) or generate_csrf_token()

    return {
        "request": request,
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "app_env": settings.APP_ENV,
        "db_dialect": "SQLite" if settings.is_sqlite else "PostgreSQL",
        "fastapi_version": fastapi.__version__,
        "is_db_connected": is_connected,
        "current_user": current_user,
        "csrf_token": csrf_token,
        "active_nav": active_nav,
        "current_year": datetime.now(timezone.utc).year,
        "allow_public_signup": settings.ALLOW_PUBLIC_SIGNUP,
    }


# =============================================================================
# Public Landing Page & Executive Dashboard
# =============================================================================
@router.get("/", response_class=HTMLResponse)
def render_landing(
    request: Request,
    logged_out: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Renders the public landing page for visitors without requiring authentication."""
    ctx = _base_context(request, db=db, active_nav="home")
    ctx.update({
        "allow_public_signup": settings.ALLOW_PUBLIC_SIGNUP,
        "logged_out": logged_out,
        "product_screenshots": [],
        "feature_cards": FEATURE_CARDS,
    })
    res = templates.TemplateResponse(request=request, name="landing.html", context=ctx)
    if not request.cookies.get(settings.CSRF_COOKIE_NAME):
        res.set_cookie(
            key=settings.CSRF_COOKIE_NAME,
            value=ctx["csrf_token"],
            max_age=settings.SESSION_MAX_AGE_SECONDS,
            secure=settings.cookie_secure,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
    return res


@router.get("/features", response_class=HTMLResponse)
@router.get("/how-it-works", response_class=HTMLResponse)
@router.get("/use-cases", response_class=HTMLResponse)
@router.get("/security", response_class=HTMLResponse)
@router.get("/about", response_class=HTMLResponse)
@router.get("/faq", response_class=HTMLResponse)
def render_public_page(request: Request, db: Session = Depends(get_db)):
    """Render one of the static, unauthenticated product information pages."""
    slug = request.url.path.strip("/")
    page = PUBLIC_PAGES.get(slug)
    if page is None:
        raise StarletteHTTPException(status_code=404, detail="Page not found")
    ctx = _base_context(request, db=db, active_nav=slug)
    ctx["page"] = page
    return templates.TemplateResponse(request=request, name="public_page.html", context=ctx)


@router.get("/dashboard", response_class=HTMLResponse)
def render_dashboard(request: Request, db: Session = Depends(get_db)):
    """Renders the primary executive dashboard with genuine metrics. Requires authentication."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        return RedirectResponse(url="/login?next=/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    ctx = _base_context(request, db=db, active_nav="dashboard")

    # Genuine counts from database
    inv_filter = [] if current_user.role == ROLE_ADMINISTRATOR else [InvestigationModel.owner_user_id == current_user.id]
    total_invs = db.scalar(select(func.count(InvestigationModel.id)).where(*inv_filter)) or 0
    active_invs = db.scalar(select(func.count(InvestigationModel.id)).where(*inv_filter, InvestigationModel.status == "active")) or 0
    completed_invs = db.scalar(select(func.count(InvestigationModel.id)).where(*inv_filter, InvestigationModel.status == "completed")) or 0

    inv_scope = select(InvestigationModel.id).where(*inv_filter)
    total_entities = db.scalar(select(func.count(EntityModel.id)).where(EntityModel.investigation_id.in_(inv_scope))) or 0
    total_evidence = db.scalar(select(func.count(EvidenceModel.id)).where(EvidenceModel.investigation_id.in_(inv_scope))) or 0
    total_scans = db.scalar(select(func.count(ActiveScanJobModel.id)).where(ActiveScanJobModel.investigation_id.in_(inv_scope))) or 0
    total_open_ports = db.scalar(
        select(func.count(ScanFindingPortModel.id))
        .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
        .where(ScanFindingHostModel.investigation_id.in_(inv_scope))
    ) or 0
    total_vuln_scans = db.scalar(select(func.count(VulnerabilityScanJobModel.id)).where(VulnerabilityScanJobModel.investigation_id.in_(inv_scope))) or 0
    total_vulns = db.scalar(select(func.count(VulnerabilityFindingModel.id)).where(VulnerabilityFindingModel.investigation_id.in_(inv_scope))) or 0

    # Recent investigations
    recent_invs = db.scalars(
        select(InvestigationModel).where(*inv_filter).order_by(InvestigationModel.created_at.desc()).limit(10)
    ).all()

    # Tool readiness diagnostics
    nmap_diag = NmapDetector().check_availability()
    gvm_diag = GreenboneClient().check_status()

    ctx.update({
        "total_investigations": total_invs,
        "active_investigations": active_invs,
        "completed_investigations": completed_invs,
        "total_entities": total_entities,
        "total_evidence": total_evidence,
        "total_scans": total_scans,
        "total_open_ports": total_open_ports,
        "total_vuln_scans": total_vuln_scans,
        "total_vulns": total_vulns,
        "investigations": recent_invs,
        "nmap_status": "READY" if nmap_diag.get("is_available") else "UNAVAILABLE",
        "greenbone_status": gvm_diag.get("status", "NOT_CONFIGURED"),
    })

    res = templates.TemplateResponse(request=request, name="dashboard.html", context=ctx)
    if not request.cookies.get(settings.CSRF_COOKIE_NAME):
        res.set_cookie(
            key=settings.CSRF_COOKIE_NAME,
            value=ctx["csrf_token"],
            max_age=settings.SESSION_MAX_AGE_SECONDS,
            secure=settings.cookie_secure,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
    return res


@router.get("/admin/dashboard", response_class=HTMLResponse)
def render_admin_dashboard(request: Request, db: Session = Depends(get_db)):
    """Render the existing operational dashboard at the administrator landing URL."""
    return render_dashboard(request, db)


# =============================================================================
# Investigations Listing & Creation
# =============================================================================
@router.get("/investigations", response_class=HTMLResponse)
def render_investigations(
    request: Request,
    q: Optional[str] = None,
    status: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists investigations with optional search query and status filter."""
    ctx = _base_context(request, db=db, active_nav="investigations")

    current_user = ctx["current_user"]
    query = select(InvestigationModel)
    if current_user.role != ROLE_ADMINISTRATOR:
        query = query.where(InvestigationModel.owner_user_id == current_user.id)
    if q and q.strip():
        search_term = f"%{q.strip()}%"
        query = query.where(
            or_(
                InvestigationModel.id.ilike(search_term),
                InvestigationModel.name.ilike(search_term),
                InvestigationModel.organization_name.ilike(search_term),
                InvestigationModel.lead_investigator.ilike(search_term),
            )
        )
    if status and status.strip():
        query = query.where(InvestigationModel.status == status.strip().lower())

    investigations = db.scalars(query.order_by(InvestigationModel.created_at.desc())).all()

    ctx.update({
        "investigations": investigations,
        "search_query": q,
        "status_filter": status,
        "error": error,
    })
    return templates.TemplateResponse(request=request, name="investigations.html", context=ctx)


@router.post("/investigations")
def handle_create_investigation(
    request: Request,
    name: str = Form(...),
    organization_name: str = Form(...),
    description: str = Form(...),
    lead_investigator: str = Form(...),
    authorization_reference: Optional[str] = Form(None),
    owned_domains: Optional[str] = Form(None),
    approved_ips: Optional[str] = Form(None),
    approved_cidrs: Optional[str] = Form(None),
    active_targets: Optional[str] = Form(None),
    active_scanning_enabled: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Registers a new investigation campaign from the web UI."""
    _validate_csrf(request, csrf_token)
    current_user = get_current_user_optional(request, db=db)
    if not current_user or not has_permission(current_user.role, "investigation.create"):
        raise StarletteHTTPException(status_code=403, detail="Investigation creation permission required")
    actor_id = current_user.id

    # Parse comma-separated fields
    domains_list = [d.strip() for d in (owned_domains or "").split(",") if d.strip()]
    ips_list = [ip.strip() for ip in (approved_ips or "").split(",") if ip.strip()]
    cidrs_list = [c.strip() for c in (approved_cidrs or "").split(",") if c.strip()]
    active_list = [t.strip() for t in (active_targets or "").split(",") if t.strip()]
    active_bool = bool(active_scanning_enabled and active_scanning_enabled.lower() in ("true", "1", "yes", "on"))

    try:
        payload = InvestigationCreate(
            name=name,
            organization_name=organization_name,
            description=description,
            lead_investigator=current_user.full_name or current_user.username,
            scope=ScopeSchema(
                owned_domains=domains_list,
                approved_ips=ips_list,
                approved_cidrs=cidrs_list,
                active_targets=active_list,
            ),
            authorization_reference=authorization_reference.strip() if authorization_reference else None,
            active_scanning_enabled=active_bool,
        )
    except ValidationError as exc:
        err_msg = "; ".join([f"{err['loc'][-1]}: {err['msg']}" for err in exc.errors()])
        accept = request.headers.get("accept", "")
        content_type = request.headers.get("content-type", "")
        if "text/html" in accept or "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import quote_plus
            return RedirectResponse(f"/investigations?error={quote_plus(err_msg)}", status_code=303)
        raise StarletteHTTPException(status_code=422, detail=f"Invalid investigation details or target scope: {err_msg}") from exc

    inv_id = f"inv-{uuid.uuid4().hex}"
    inv = InvestigationModel(
        id=inv_id,
        name=payload.name,
        organization_name=payload.organization_name,
        description=payload.description,
        lead_investigator=payload.lead_investigator,
        owner_user_id=current_user.id,
        team_members=[],
        status="active",
        owned_domains=payload.scope.owned_domains,
        approved_ips=payload.scope.approved_ips,
        approved_cidrs=payload.scope.approved_cidrs,
        active_targets=payload.scope.active_targets,
        active_scanning_enabled=payload.active_scanning_enabled,
        authorization_reference=payload.authorization_reference,
    )
    db.add(inv)
    db.commit()

    log_audit_event(
        db=db,
        event_type="INVESTIGATION_CREATED",
        actor_id=actor_id,
        outcome="SUCCESS",
        details={"investigation_id": inv_id, "name": name, "organization": organization_name},
    )

    return RedirectResponse(url=f"/investigations/{inv_id}", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Investigation Detail Workspace
# =============================================================================
@router.get("/investigations/{investigation_id}", response_class=HTMLResponse)
def render_investigation_detail(
    investigation_id: str,
    request: Request,
    error: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Renders the comprehensive 8-tab investigation workspace."""
    ctx = _base_context(request, db=db, active_nav="investigations")

    inv = db.get(InvestigationModel, investigation_id)
    current_user = ctx["current_user"]
    if not current_user or not has_permission(current_user.role, "investigation.view"):
        raise StarletteHTTPException(status_code=403, detail="Investigation view permission required")
    inv = require_investigation_access(inv, current_user)

    authorizations = db.scalars(
        select(TargetAuthorizationModel).where(TargetAuthorizationModel.investigation_id == investigation_id)
    ).all()

    entities = db.scalars(
        select(EntityModel).where(EntityModel.investigation_id == investigation_id).order_by(EntityModel.first_seen.desc())
    ).all()

    evidence_list = db.scalars(
        select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id).order_by(EvidenceModel.collected_at.desc())
    ).all()

    scan_hosts = db.scalars(
        select(ScanFindingHostModel)
        .where(ScanFindingHostModel.investigation_id == investigation_id)
        .order_by(ScanFindingHostModel.created_at.desc())
    ).all()

    scan_ports = db.scalars(
        select(ScanFindingPortModel)
        .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
        .where(ScanFindingHostModel.investigation_id == investigation_id)
    ).all()

    vuln_findings = db.scalars(
        select(VulnerabilityFindingModel)
        .where(VulnerabilityFindingModel.investigation_id == investigation_id)
        .order_by(
            case((VulnerabilityFindingModel.cvss_score.is_(None), 1), else_=0),
            VulnerabilityFindingModel.cvss_score.desc(),
        )
    ).all()

    collection_jobs = db.scalars(
        select(CollectionJobModel).where(CollectionJobModel.investigation_id == investigation_id).order_by(CollectionJobModel.started_at.desc())
    ).all()

    nmap_jobs = db.scalars(
        select(ActiveScanJobModel).where(ActiveScanJobModel.investigation_id == investigation_id).order_by(ActiveScanJobModel.started_at.desc())
    ).all()

    vuln_jobs = db.scalars(
        select(VulnerabilityScanJobModel).where(VulnerabilityScanJobModel.investigation_id == investigation_id).order_by(VulnerabilityScanJobModel.started_at.desc())
    ).all()

    # Calculate genuine 5-factor Exposure Score
    score = ExposureScorer.calculate_for_investigation(investigation_id, db=db)
    score_history = ExposureScorer.get_score_history(investigation_id, db=db)
    greenbone_diag = GreenboneClient().check_status()

    # Load multi-source correlated asset & findings intelligence
    try:
        correlation_engine = CorrelationEngine(db)
        correlation_data = correlation_engine.run_correlation(investigation_id)
    except Exception as corr_exc:
        logger.warning("Error running correlation engine for %s: %s", investigation_id, corr_exc)
        correlation_data = {"summary": {}, "assets": [], "correlations": [], "unmatched_observations": [], "graph": {}}

    ctx.update({
        "inv": inv,
        "authorizations": authorizations,
        "entities": entities,
        "evidence_list": evidence_list,
        "scan_hosts": scan_hosts,
        "scan_ports": scan_ports,
        "vuln_findings": vuln_findings,
        "collection_jobs": collection_jobs,
        "nmap_jobs": nmap_jobs,
        "vuln_jobs": vuln_jobs,
        "greenbone_diag": greenbone_diag,
        "score": score,
        "score_history": score_history,
        "correlation_data": correlation_data,
        "correlation_records": correlation_data.get("correlations", []),
        "correlated_assets": correlation_data.get("assets", []),
        "unmatched_observations": correlation_data.get("unmatched_observations", []),
        "error": error,
    })
    return templates.TemplateResponse(request=request, name="investigation_detail.html", context=ctx)


# =============================================================================
# Target Authorization Creation from Web UI
# =============================================================================
@router.post("/investigations/{investigation_id}/authorizations")
def handle_create_authorization(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    target_type: str = Form("IP"),
    approved_by: str = Form(""),
    authorization_reference: str = Form(...),
    operations: List[str] = Form(["SCAN_ACTIVE", "SCAN_VULN"]),
    valid_days: int = Form(30, ge=1, le=3650),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Adds an explicit target authorization record for active reconnaissance."""
    _validate_csrf(request, csrf_token)
    current_user = get_current_user_optional(request, db=db)
    if not current_user or not has_permission(current_user.role, "scope.manage"):
        raise StarletteHTTPException(status_code=403, detail="Target authorization management permission required")
    inv = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)

    now = datetime.now(timezone.utc)
    valid_to = now + timedelta(days=valid_days)
    try:
        payload = TargetAuthorizationCreate(
            target=target,
            target_type=target_type.strip().upper(),
            allowed_operations=operations,
            authorization_reference=authorization_reference,
            valid_from=now,
            valid_to=valid_to,
            approved_by=current_user.username,
        )
    except ValidationError as exc:
        raise StarletteHTTPException(status_code=422, detail="Invalid target authorization details") from exc
    in_scope, reason = is_target_in_investigation_scope(inv, payload.target)
    if not in_scope:
        raise StarletteHTTPException(status_code=422, detail=reason)

    norm_target = normalize_target(payload.target)
    existing_active = db.scalars(
        select(TargetAuthorizationModel).where(
            TargetAuthorizationModel.investigation_id == investigation_id,
            TargetAuthorizationModel.target == norm_target,
            TargetAuthorizationModel.is_revoked == False,
            TargetAuthorizationModel.valid_to > now,
        )
    ).first()
    if existing_active:
        return RedirectResponse(
            url=f"/investigations/{investigation_id}?error=An+active+authorization+already+exists+for+target+{quote_plus(payload.target)}+%28Ticket%3A+{quote_plus(existing_active.authorization_reference)}%29#tab-authorizations",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:10]}",
        investigation_id=investigation_id,
        target=norm_target,
        target_type=payload.target_type,
        allowed_operations=payload.allowed_operations,
        authorization_reference=payload.authorization_reference,
        approved_by=current_user.username,
        valid_from=payload.valid_from or now,
        valid_to=payload.valid_to,
        is_revoked=False,
    )
    db.add(authz)
    db.commit()

    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_GRANTED",
        actor_id=current_user.id,
        outcome="SUCCESS",
        details={
            "investigation_id": investigation_id,
            "target": authz.target,
            "operations": authz.allowed_operations,
            "valid_to": valid_to.isoformat(),
        },
    )

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-authorizations",
        status_code=status.HTTP_303_SEE_OTHER
    )


# =============================================================================
# Tool Invocations from Web UI
# =============================================================================
@router.post("/investigations/{investigation_id}/recon/passive")
async def handle_trigger_passive_recon(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers passive reconnaissance collectors via form submission."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        raise StarletteHTTPException(status_code=401, detail="Authentication required")
    if not has_permission(current_user.role, "recon.passive"):
        raise StarletteHTTPException(status_code=403, detail="Passive reconnaissance permission required")
    inv = require_investigation_access(inv, current_user)
    actor_id = current_user.id
    orchestrator = PassiveReconOrchestrator(
        db=db,
        investigation_id=investigation_id,
        actor_user=current_user,
    )
    try:
        await orchestrator.run(target=target.strip())
    except Exception as e:
        log_audit_event(
            db=db,
            event_type="PASSIVE_RECON_LAUNCH_FAILED",
            actor_id=actor_id,
            outcome="FAILURE",
            details={"investigation_id": investigation_id, "target": target, "error": str(e)},
        )
        accept = request.headers.get("accept", "")
        content_type = request.headers.get("content-type", "")
        if "text/html" in accept or "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import quote_plus
            return RedirectResponse(
                url=f"/investigations/{investigation_id}?error={quote_plus(str(e))}#tab-passive",
                status_code=status.HTTP_303_SEE_OTHER
            )
        raise StarletteHTTPException(status_code=403 if isinstance(e, PermissionError) else 400,
                                     detail=str(e)) from e

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-passive",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/investigations/{investigation_id}/scans/nmap")
async def handle_trigger_nmap_scan(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    profile_id: str = Form("service_inventory"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers active Nmap scan via form submission."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        raise StarletteHTTPException(status_code=401, detail="Authentication required")
    if not has_permission(current_user.role, "recon.active"):
        raise StarletteHTTPException(status_code=403, detail="Active reconnaissance permission required")
    inv = require_investigation_access(inv, current_user)
    actor_id = current_user.id

    profile = get_scan_profile(profile_id)
    if not profile:
        raise StarletteHTTPException(status_code=400, detail=f"Invalid scan profile '{profile_id}'")

    runner = get_nmap_runner()
    try:
        job = await runner.create_scan_job(
            db=db, investigation=inv, target=target.strip(), profile_id=profile_id,
            actor_user=current_user, client_ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        )
        asyncio.create_task(runner.execute_scan(
            db_factory=SessionLocal, job_id=job.id,
            client_ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        ))
    except (NmapExecutionError, ValueError, PermissionError) as e:
        log_audit_event(
            db=db,
            event_type="ACTIVE_SCAN_LAUNCH_FAILED",
            actor_id=actor_id,
            outcome="FAILURE",
            details={"investigation_id": investigation_id, "target": target, "error": str(e)},
        )
        accept = request.headers.get("accept", "")
        content_type = request.headers.get("content-type", "")
        if "text/html" in accept or "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import quote_plus
            return RedirectResponse(
                url=f"/investigations/{investigation_id}?error={quote_plus(str(e))}#tab-active",
                status_code=status.HTTP_303_SEE_OTHER
            )
        raise StarletteHTTPException(status_code=403, detail="Nmap scan was not queued; verify tool availability, scope, and authorization.") from e

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-active",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/investigations/{investigation_id}/scans/vuln")
async def handle_trigger_vuln_scan(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    profile_id: str = Form("openvas-basic"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers Greenbone vulnerability assessment via form submission."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        raise StarletteHTTPException(status_code=401, detail="Authentication required")
    if not has_permission(current_user.role, "vulnerability.scan"):
        raise StarletteHTTPException(status_code=403, detail="Vulnerability scanning permission required")
    inv = require_investigation_access(inv, current_user)
    actor_id = current_user.id

    profile = get_vuln_profile(profile_id)
    if not profile:
        raise StarletteHTTPException(status_code=400, detail=f"Invalid profile '{profile_id}'")

    orchestrator = get_vuln_orchestrator()
    try:
        job = orchestrator.create_assessment_job(
            db=db, investigation=inv, target=target.strip(), profile_id=profile_id,
            actor_user=current_user, client_ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        )
    except (VulnerabilityAssessmentError, ValueError, PermissionError) as e:
        accept = request.headers.get("accept", "")
        content_type = request.headers.get("content-type", "")
        if "text/html" in accept or "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import quote_plus
            return RedirectResponse(
                url=f"/investigations/{investigation_id}?error={quote_plus(str(e))}#tab-vulns",
                status_code=status.HTTP_303_SEE_OTHER
            )
        raise StarletteHTTPException(status_code=403, detail="Assessment was not queued; verify target authorization and profile.") from e

    import asyncio
    asyncio.create_task(
        orchestrator.execute_assessment_job(
            job_id=job.id,
            investigation_id=investigation_id,
            target=job.target,
            profile_id=job.profile_id,
            requested_by=actor_id,
            client_ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        )
    )

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-vulns",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/scans/vuln/{job_id}/cancel")
def handle_cancel_vuln_scan(
    job_id: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Requests cooperative cancellation of a Greenbone task."""
    _validate_csrf(request, csrf_token)
    current_user = get_current_user_optional(request, db=db)
    if not current_user or not has_permission(current_user.role, "vulnerability.scan"):
        raise StarletteHTTPException(status_code=403, detail="Vulnerability scanning permission required")
    job = db.get(VulnerabilityScanJobModel, job_id)
    if not job:
        raise StarletteHTTPException(status_code=404, detail="Assessment job not found")
    require_investigation_access(db.get(InvestigationModel, job.investigation_id), current_user)
    orchestrator = get_vuln_orchestrator()
    try:
        orchestrator.cancel_job(db=db, job_id=job_id, actor_user=current_user,
                                reason="Cancelled by user via dashboard.",
                                client_ip=request.client.host if request.client else None,
                                request_id=getattr(request.state, "request_id", None))
    except VulnerabilityAssessmentError as exc:
        raise StarletteHTTPException(status_code=409, detail="Assessment cancellation could not be completed.") from exc

    return RedirectResponse(url="/scans", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/investigations/{investigation_id}/workflow/run")
async def handle_trigger_investigation_workflow(
    investigation_id: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers the full multi-stage investigation workflow via dashboard form."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        raise StarletteHTTPException(status_code=401, detail="Authentication required")
    if not has_permission(current_user.role, "investigation.create"):
        raise StarletteHTTPException(status_code=403, detail="Investigation workflow launch permission required")
    inv = require_investigation_access(inv, current_user)

    from app.services.workflow.orchestrator import InvestigationWorkflowOrchestrator
    orchestrator = InvestigationWorkflowOrchestrator(db=db)
    try:
        await orchestrator.execute_workflow(
            investigation_id=investigation_id,
            actor_user=current_user,
            client_ip=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
        )
    except Exception as e:
        logger.warning("Investigation workflow execution warning for %s: %s", investigation_id, e)

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-overview",
        status_code=status.HTTP_303_SEE_OTHER,
    )



# =============================================================================
# Consolidated PDF Report Download
# =============================================================================
@router.get("/investigations/{investigation_id}/report/pdf")
def download_investigation_pdf(
    investigation_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Generates and streams a professional ReportLab PDF dossier from persisted records."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user or not has_permission(current_user.role, "report.export"):
        raise StarletteHTTPException(status_code=403, detail="Report export permission required")
    inv = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    actor_name = current_user.username

    try:
        pdf_bytes = InvestigationReportGenerator.generate_pdf(
            investigation_id=investigation_id,
            db=db,
            generated_by=actor_name,
            dossier_title="FootprintIQ Comprehensive Reconnaissance Dossier",
        )
    except Exception:
        logger.exception("PDF report generation failed for investigation %s", investigation_id)
        raise StarletteHTTPException(status_code=500, detail="Failed to generate PDF report.")

    log_audit_event(
        db=db,
        event_type="REPORT_DOWNLOADED",
        actor_id=actor_name,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "PDF"},
    )

    filename = f"FootprintIQ-Dossier-{inv.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )


@router.get("/investigations/{investigation_id}/report/graphml")
def download_investigation_graphml(
    investigation_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Generates and streams a standard GraphML XML export for Gephi, Cytoscape, and Maltego."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user or not has_permission(current_user.role, "report.export"):
        raise StarletteHTTPException(status_code=403, detail="Report export permission required")
    inv = require_investigation_access(db.get(InvestigationModel, investigation_id), current_user)
    actor_name = current_user.username

    try:
        xml_content = GraphMLExporter.generate_graphml(investigation_id=investigation_id, db=db)
    except Exception:
        logger.exception("GraphML export failed for investigation %s", investigation_id)
        raise StarletteHTTPException(status_code=500, detail="Failed to generate GraphML export.")

    log_audit_event(
        db=db,
        event_type="REPORT_DOWNLOADED",
        actor_id=actor_name,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "GRAPHML"},
    )

    filename = f"FootprintIQ-KnowledgeGraph-{inv.id}.graphml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )



# =============================================================================
# Standalone Pages: Findings, Scans, Evidence, Audit, Admin
# =============================================================================
@router.get("/settings", response_class=HTMLResponse)
def render_settings(request: Request, db: Session = Depends(get_db)):
    """Displays account settings for the authenticated user."""
    ctx = _base_context(request, db=db, active_nav="settings")
    ctx["error"] = request.query_params.get("error")
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@router.post("/settings/password")
def handle_password_change(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Changes the signed-in user's password and clears the invalidated browser session."""
    _validate_csrf(request, csrf_token)
    try:
        change_user_password(
            db=db,
            user=current_user,
            current_password=current_password,
            new_password=new_password,
            confirm_password=confirm_password,
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/settings?error={quote(str(exc), safe='')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    response = RedirectResponse(url="/login?password_changed=1", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        secure=settings.cookie_secure,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    return response


@router.get("/admin/investigators", response_class=HTMLResponse)
def render_investigator_approvals(
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Lists pending and active investigator registrations for administrators."""
    ctx = _base_context(request, db=db, active_nav="approvals")
    ctx["pending_users"] = db.scalars(
        select(UserModel)
        .where(UserModel.role == "investigator", UserModel.account_status == "pending")
        .order_by(UserModel.created_at.asc())
    ).all()
    ctx["active_investigators"] = db.scalars(
        select(UserModel)
        .where(UserModel.role == "investigator", UserModel.account_status == "active")
        .order_by(UserModel.created_at.desc())
    ).all()
    admin_users = db.scalars(select(UserModel).where(UserModel.role == ROLE_ADMINISTRATOR)).all()
    ctx["admin_lookup"] = {u.id: (u.full_name or u.username) for u in admin_users}
    ctx["message"] = request.query_params.get("message") or request.query_params.get("error")
    return templates.TemplateResponse(request=request, name="admin_investigators.html", context=ctx)


@router.post("/admin/investigators/{user_id}/approve")
def handle_investigator_approval(
    user_id: str,
    request: Request,
    csrf_token: str = Form(...),
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Approves a pending investigator after administrator and CSRF validation."""
    _validate_csrf(request, csrf_token)
    user = db.get(UserModel, user_id)
    if not user:
        return RedirectResponse(
            url="/admin/investigators?error=Registration+not+found",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        transition_investigator_account(
            db, user, admin, "approve",
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/admin/investigators?error={quote(str(exc), safe='')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url="/admin/investigators?message=Investigator+approved",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/investigators/{user_id}/reject")
def handle_investigator_rejection(
    user_id: str,
    request: Request,
    csrf_token: str = Form(...),
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Rejects a pending investigator after administrator and CSRF validation."""
    _validate_csrf(request, csrf_token)
    user = db.get(UserModel, user_id)
    if not user:
        return RedirectResponse(
            url="/admin/investigators?error=Registration+not+found",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        transition_investigator_account(
            db, user, admin, "reject",
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/admin/investigators?error={quote(str(exc), safe='')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url="/admin/investigators?message=Investigator+rejected",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/investigators/{user_id}/deactivate")
def handle_investigator_deactivation(
    user_id: str,
    request: Request,
    csrf_token: str = Form(...),
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Deactivates an active investigator."""
    _validate_csrf(request, csrf_token)
    user = db.get(UserModel, user_id)
    if not user:
        return RedirectResponse(
            url="/admin/investigators?error=Investigator+not+found",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        toggle_investigator_active_status(
            db, user, admin, active=False,
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/admin/investigators?error={quote(str(exc), safe='')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url="/admin/investigators?message=Investigator+deactivated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/investigators/{user_id}/activate")
def handle_investigator_activation(
    user_id: str,
    request: Request,
    csrf_token: str = Form(...),
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Activates an inactive investigator."""
    _validate_csrf(request, csrf_token)
    user = db.get(UserModel, user_id)
    if not user:
        return RedirectResponse(
            url="/admin/investigators?error=Investigator+not+found",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        toggle_investigator_active_status(
            db, user, admin, active=True,
            request_id=getattr(request.state, "request_id", None),
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/admin/investigators?error={quote(str(exc), safe='')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url="/admin/investigators?message=Investigator+activated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/findings", response_class=HTMLResponse)
def render_findings(
    request: Request,
    q: Optional[str] = None,
    severity: Optional[str] = None,
    investigation_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Unified matrix of all vulnerability and exposure findings."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        return RedirectResponse(url="/login?next=/findings", status_code=status.HTTP_303_SEE_OTHER)
    ctx = _base_context(request, db=db, active_nav="findings")

    accessible_investigations = select(InvestigationModel.id)
    if current_user.role != ROLE_ADMINISTRATOR:
        accessible_investigations = accessible_investigations.where(InvestigationModel.owner_user_id == current_user.id)
    query = select(VulnerabilityFindingModel).where(
        VulnerabilityFindingModel.investigation_id.in_(accessible_investigations)
    )
    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.where(
            or_(
                VulnerabilityFindingModel.name.ilike(term),
                VulnerabilityFindingModel.host.ilike(term),
            )
        )
    if severity and severity.strip():
        query = query.where(VulnerabilityFindingModel.severity == severity.strip().lower())
    if investigation_id and investigation_id.strip():
        query = query.where(VulnerabilityFindingModel.investigation_id == investigation_id.strip())

    findings = db.scalars(
        query.order_by(
            case((VulnerabilityFindingModel.cvss_score.is_(None), 1), else_=0),
            VulnerabilityFindingModel.cvss_score.desc(),
        )
    ).all()
    investigations = db.scalars(
        select(InvestigationModel).where(InvestigationModel.id.in_(accessible_investigations)).order_by(InvestigationModel.name.asc())
    ).all()

    ctx.update({
        "findings": findings,
        "investigations": investigations,
        "search_query": q,
        "severity_filter": severity,
        "inv_filter": investigation_id,
    })
    return templates.TemplateResponse(request=request, name="findings.html", context=ctx)


@router.get("/scans", response_class=HTMLResponse)
def render_scans(request: Request, db: Session = Depends(get_db)):
    """Live scan execution monitor for passive, Nmap, and Greenbone jobs."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        return RedirectResponse(url="/login?next=/scans", status_code=status.HTTP_303_SEE_OTHER)
    ctx = _base_context(request, db=db, active_nav="scans")

    inv_scope = select(InvestigationModel.id)
    if current_user.role != ROLE_ADMINISTRATOR:
        inv_scope = inv_scope.where(InvestigationModel.owner_user_id == current_user.id)
    vuln_jobs = db.scalars(select(VulnerabilityScanJobModel).where(VulnerabilityScanJobModel.investigation_id.in_(inv_scope)).order_by(VulnerabilityScanJobModel.started_at.desc()).limit(25)).all()
    nmap_jobs = db.scalars(select(ActiveScanJobModel).where(ActiveScanJobModel.investigation_id.in_(inv_scope)).order_by(ActiveScanJobModel.started_at.desc()).limit(25)).all()
    collection_jobs = db.scalars(select(CollectionJobModel).where(CollectionJobModel.investigation_id.in_(inv_scope)).order_by(CollectionJobModel.started_at.desc()).limit(25)).all()

    ctx.update({
        "vuln_jobs": vuln_jobs,
        "nmap_jobs": nmap_jobs,
        "collection_jobs": collection_jobs,
    })
    return templates.TemplateResponse(request=request, name="scans.html", context=ctx)


@router.get("/evidence", response_class=HTMLResponse)
def render_evidence(request: Request, db: Session = Depends(get_db)):
    """Forensic evidence ledger with SHA-256 hashes."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        return RedirectResponse(url="/login?next=/evidence", status_code=status.HTTP_303_SEE_OTHER)
    ctx = _base_context(request, db=db, active_nav="evidence")

    inv_scope = select(InvestigationModel.id)
    if current_user.role != ROLE_ADMINISTRATOR:
        inv_scope = inv_scope.where(InvestigationModel.owner_user_id == current_user.id)
    evidence_list = db.scalars(select(EvidenceModel).where(EvidenceModel.investigation_id.in_(inv_scope)).order_by(EvidenceModel.collected_at.desc()).limit(50)).all()
    ctx.update({"evidence_list": evidence_list})
    return templates.TemplateResponse(request=request, name="evidence.html", context=ctx)


@router.get("/audit", response_class=HTMLResponse)
def render_audit(request: Request, db: Session = Depends(get_db)):
    """Security audit trail browser."""
    ctx = _base_context(request, db=db, active_nav="audit")

    audit_logs = db.scalars(select(AuditLogModel).order_by(AuditLogModel.timestamp.desc()).limit(50)).all()
    ctx.update({"audit_logs": audit_logs})
    return templates.TemplateResponse(request=request, name="audit.html", context=ctx)


@router.get("/admin/authorizations", response_class=HTMLResponse)
def render_admin_authorizations(request: Request, db: Session = Depends(get_db)):
    """Administrative target allowlist management."""
    ctx = _base_context(request, db=db, active_nav="admin")

    authorizations = db.scalars(select(TargetAuthorizationModel).order_by(TargetAuthorizationModel.created_at.desc())).all()
    ctx.update({"authorizations": authorizations})
    return templates.TemplateResponse(request=request, name="admin_authorizations.html", context=ctx)


@router.post("/admin/authorizations/{authorization_id}/revoke")
def handle_revoke_authorization(
    authorization_id: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Revokes a target authorization record."""
    _validate_csrf(request, csrf_token)
    authz = db.get(TargetAuthorizationModel, authorization_id)
    if not authz:
        raise StarletteHTTPException(status_code=404, detail=f"Authorization '{authorization_id}' not found.")

    current_user = get_current_user_optional(request, db=db)
    if not current_user or not has_permission(current_user.role, "scope.manage"):
        raise StarletteHTTPException(status_code=403, detail="Target authorization management permission required")
    inv = require_investigation_access(db.get(InvestigationModel, authz.investigation_id), current_user)
    if authz.is_revoked:
        return RedirectResponse(url=f"/investigations/{inv.id}#tab-authorizations", status_code=status.HTTP_303_SEE_OTHER)
    authz.is_revoked = True

    # Safeguard: cascade revocation to any unintended duplicate active records for same target
    duplicate_records = db.scalars(
        select(TargetAuthorizationModel).where(
            TargetAuthorizationModel.investigation_id == authz.investigation_id,
            TargetAuthorizationModel.target == authz.target,
            TargetAuthorizationModel.id != authz.id,
            TargetAuthorizationModel.is_revoked == False,
        )
    ).all()
    for dup in duplicate_records:
        dup.is_revoked = True

    db.commit()

    actor_id = current_user.id

    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_REVOKED",
        actor_id=actor_id,
        outcome="SUCCESS",
        details={
            "authorization_id": authorization_id,
            "investigation_id": authz.investigation_id,
            "target": authz.target,
            "duplicates_revoked": [d.id for d in duplicate_records],
        },
    )

    return RedirectResponse(url="/admin/authorizations", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/admin/tools", response_class=HTMLResponse)
def render_admin_tools(request: Request, db: Session = Depends(get_db)):
    """Scanner availability and diagnostic inspection."""
    ctx = _base_context(request, db=db, active_nav="admin")

    nmap_diag = NmapDetector().check_availability()
    greenbone_diag = GreenboneClient().check_status()

    ctx.update({
        "nmap_diag": nmap_diag,
        "greenbone_diag": greenbone_diag,
    })
    return templates.TemplateResponse(request=request, name="admin_tools.html", context=ctx)
