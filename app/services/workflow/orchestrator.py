"""End-to-End Investigation Workflow Orchestrator for FootprintIQ.

Coordinates the multi-stage forensic investigation pipeline:
1. Target Scope & Authorization Verification
2. Passive Reconnaissance (RDAP, DNS, CT, Search, theHarvester) -> SeaweedFS Evidence
3. Active Network Reconnaissance (Nmap Host & Port Discovery) -> SeaweedFS Evidence
4. Vulnerability Assessment (Greenbone / OpenVAS) -> SeaweedFS Evidence
5. Entity Normalization & Cross-Stage Finding Correlation
6. 5-Factor Exposure Scoring
7. Consolidated PDF & GraphML Dossier Generation
8. Deterministic Investigation Lifecycle State Transitions
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import log_audit_event
from app.core.security import has_permission
from app.models.investigation import InvestigationModel
from app.models.job import (
    JobModel,
    JOB_STATUS_QUEUED,
    JOB_STATUS_RUNNING,
    JOB_STATUS_COMPLETED,
    JOB_STATUS_FAILED,
    JOB_STATUS_CANCELLED,
    utc_now,
)
from app.models.user import UserModel
from app.services.active.runner import get_nmap_runner, NmapExecutionError
from app.services.active.profiles import get_scan_profile
from app.services.evidence_store import get_evidence_store
from app.services.investigation_access import require_investigation_access
from app.services.jobs.queue import get_job_queue, DuplicateJobError
from app.services.passive.orchestrator import PassiveReconOrchestrator
from app.services.reporting.graphml_generator import GraphMLExporter
from app.services.reporting.pdf_generator import InvestigationReportGenerator
from app.services.scoring.calculator import ExposureScorer
from app.services.target_authorization import verify_target_authorization, classify_target
from app.services.vuln.orchestrator import get_vuln_orchestrator, VulnerabilityAssessmentError
from app.services.workflow.correlation import InvestigationCorrelationService
from app.services.workflow.state_machine import (
    STATUS_DRAFT,
    STATUS_READY,
    STATUS_ACTIVE,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_PARTIALLY_COMPLETED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    can_transition,
    validate_transition,
    normalize_status,
)

logger = logging.getLogger("footprintiq.services.workflow.orchestrator")


class InvestigationWorkflowOrchestrator:
    """Coordinates end-to-end investigation workflows across all forensic stages."""

    def __init__(self, db: Session):
        self.db = db
        self.job_queue = get_job_queue()
        self.evidence_store = get_evidence_store()
        self.correlation_service = InvestigationCorrelationService(db)

    def _resolve_primary_target(self, investigation: InvestigationModel, requested_target: Optional[str] = None) -> str:
        """Determines the primary target from arguments or investigation scope."""
        if requested_target and requested_target.strip():
            return requested_target.strip()
        # Fall back to scope definitions in priority order
        if investigation.active_targets:
            return investigation.active_targets[0].strip()
        if investigation.owned_domains:
            return investigation.owned_domains[0].strip()
        if investigation.approved_ips:
            return investigation.approved_ips[0].strip()
        raise ValueError(f"Investigation '{investigation.id}' has no configured target scope.")

    def _check_cancellation(self, investigation_id: str, workflow_job_id: Optional[str] = None) -> bool:
        """Polls whether the investigation or linked durable job has received a cancellation signal."""
        try:
            self.db.expire_all()
            inv = self.db.get(InvestigationModel, investigation_id)
            if inv and normalize_status(inv.status) == STATUS_CANCELLED:
                return True

            if workflow_job_id:
                job = self.db.get(JobModel, workflow_job_id)
                if job and (job.cancellation_requested or job.status == JOB_STATUS_CANCELLED):
                    return True

            cancel_req = self.db.scalars(
                select(JobModel).where(
                    JobModel.investigation_id == investigation_id,
                    JobModel.cancellation_requested == True,
                )
            ).first()
            if cancel_req:
                return True
        except Exception as e:
            logger.warning("[%s] Error checking cancellation status: %s", investigation_id, e)
        return False

    async def execute_workflow(
        self,
        investigation_id: str,
        actor_user: UserModel,
        target: Optional[str] = None,
        scan_profile_id: str = "service_inventory",
        vuln_profile_id: str = "openvas-full-and-fast",
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
        workflow_job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes full multi-stage investigation workflow synchronously or within worker task."""
        inv = self.db.get(InvestigationModel, investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        require_investigation_access(inv, actor_user)
        resolved_target = self._resolve_primary_target(inv, target)
        clean_target = resolved_target.lower()

        # Reject DRAFT status - scope must be ready
        curr_status = normalize_status(inv.status)
        if curr_status == STATUS_DRAFT:
            raise ValueError("Draft investigations cannot execute workflow stages. Establish authorized scope first.")

        # Transition to RUNNING
        if can_transition(inv.status, STATUS_RUNNING):
            inv.status = STATUS_RUNNING
            self.db.commit()

        log_audit_event(
            db=self.db,
            event_type="INVESTIGATION_WORKFLOW_STARTED",
            outcome="SUCCESS",
            actor_id=actor_user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "investigation_id": investigation_id,
                "target": clean_target,
                "workflow_job_id": workflow_job_id,
            },
        )

        stages_log: List[Dict[str, Any]] = []
        is_partial = False
        workflow_failed = False
        fatal_error_msg: Optional[str] = None

        def _handle_cancellation(halted_stage: str) -> Dict[str, Any]:
            stages_log.append({
                "stage_name": halted_stage,
                "status": "CANCELLED",
                "timestamp": utc_now().isoformat(),
                "reason": f"Workflow halted cooperatively before {halted_stage} upon cancellation signal.",
            })
            if can_transition(inv.status, STATUS_CANCELLED):
                inv.status = STATUS_CANCELLED
                self.db.commit()

            if workflow_job_id:
                job = self.db.get(JobModel, workflow_job_id)
                if job and job.status not in (JOB_STATUS_COMPLETED, JOB_STATUS_FAILED, JOB_STATUS_CANCELLED):
                    job.status = JOB_STATUS_CANCELLED
                    job.completed_at = utc_now()
                    self.db.commit()

            log_audit_event(
                db=self.db,
                event_type="INVESTIGATION_WORKFLOW_CANCELLED",
                outcome="SUCCESS",
                actor_id=actor_user.id,
                request_id=request_id,
                ip_address=client_ip,
                details={
                    "investigation_id": investigation_id,
                    "target": clean_target,
                    "halted_at_stage": halted_stage,
                    "stages_executed_count": len(stages_log) - 1,
                },
            )
            return {
                "investigation_id": investigation_id,
                "target": clean_target,
                "workflow_status": STATUS_CANCELLED,
                "completed_at": utc_now().isoformat(),
                "stages": stages_log,
                "correlation_summary": {},
                "exposure_score": None,
            }

        # ---------------------------------------------------------------------
        # Pre-Stage 1 Cooperative Cancellation Check
        # ---------------------------------------------------------------------
        if self._check_cancellation(investigation_id, workflow_job_id):
            logger.info("[%s] Cooperative cancellation detected before Stage 1", investigation_id)
            return _handle_cancellation("STAGE_1_PASSIVE_RECON")

        # ---------------------------------------------------------------------
        # STAGE 1: Passive Reconnaissance
        # ---------------------------------------------------------------------
        t_stage1_start = utc_now()
        logger.info("[%s] Starting STAGE 1: Passive Reconnaissance on %s", investigation_id, clean_target)
        try:
            passive_orch = PassiveReconOrchestrator(
                db=self.db,
                investigation_id=investigation_id,
                actor_user=actor_user,
            )
            passive_res = await passive_orch.run(
                target=clean_target,
                client_ip=client_ip,
                request_id=request_id,
            )
            stages_log.append({
                "stage_name": "PASSIVE_RECONNAISSANCE",
                "status": "COMPLETED",
                "started_at": t_stage1_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "duration_seconds": round((utc_now() - t_stage1_start).total_seconds(), 2),
                "summary": passive_res.get("summary", {}),
            })
        except Exception as e:
            logger.warning("[%s] STAGE 1 Passive Recon warning: %s", investigation_id, e)
            stages_log.append({
                "stage_name": "PASSIVE_RECONNAISSANCE",
                "status": "FAILED",
                "started_at": t_stage1_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "error": str(e),
            })
            is_partial = True

        # ---------------------------------------------------------------------
        # Pre-Stage 2 Cooperative Cancellation Check
        # ---------------------------------------------------------------------
        if self._check_cancellation(investigation_id, workflow_job_id):
            logger.info("[%s] Cooperative cancellation detected before Stage 2", investigation_id)
            return _handle_cancellation("STAGE_2_ACTIVE_NMAP")

        # ---------------------------------------------------------------------
        # STAGE 2: Active Nmap Reconnaissance
        # ---------------------------------------------------------------------
        t_stage2_start = utc_now()
        logger.info("[%s] Evaluating STAGE 2: Active Nmap Reconnaissance on %s", investigation_id, clean_target)
        if not inv.active_scanning_enabled:
            stages_log.append({
                "stage_name": "ACTIVE_NMAP_SCAN",
                "status": "SKIPPED_NOT_CONFIGURED",
                "started_at": t_stage2_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "reason": "Active scanning is disabled for this investigation scope.",
            })
        else:
            is_nmap_auth, auth_reason = verify_target_authorization(
                db=self.db,
                investigation=inv,
                target=clean_target,
                operation="SCAN_ACTIVE",
                actor_user=actor_user,
                client_ip=client_ip,
                request_id=request_id,
            )
            if not is_nmap_auth:
                stages_log.append({
                    "stage_name": "ACTIVE_NMAP_SCAN",
                    "status": "SKIPPED_NOT_AUTHORIZED",
                    "started_at": t_stage2_start.isoformat(),
                    "completed_at": utc_now().isoformat(),
                    "reason": f"Active scanning not authorized: {auth_reason}",
                })
                is_partial = True
            else:
                try:
                    runner = get_nmap_runner()
                    profile = get_scan_profile(scan_profile_id)
                    if not profile:
                        scan_profile_id = "service_inventory"
                        profile = get_scan_profile(scan_profile_id)

                    job = await runner.create_scan_job(
                        db=self.db,
                        investigation=inv,
                        target=clean_target,
                        profile_id=scan_profile_id,
                        actor_user=actor_user,
                        client_ip=client_ip,
                        request_id=request_id,
                    )
                    # Execute synchronous/awaitable scan
                    from app.database import SessionLocal
                    await runner.execute_scan(
                        db_factory=SessionLocal,
                        job_id=job.id,
                        client_ip=client_ip,
                        request_id=request_id,
                    )
                    stages_log.append({
                        "stage_name": "ACTIVE_NMAP_SCAN",
                        "status": "COMPLETED",
                        "job_id": job.id,
                        "started_at": t_stage2_start.isoformat(),
                        "completed_at": utc_now().isoformat(),
                        "duration_seconds": round((utc_now() - t_stage2_start).total_seconds(), 2),
                    })
                except Exception as nmap_err:
                    logger.warning("[%s] STAGE 2 Nmap scan warning: %s", investigation_id, nmap_err)
                    stages_log.append({
                        "stage_name": "ACTIVE_NMAP_SCAN",
                        "status": "FAILED",
                        "started_at": t_stage2_start.isoformat(),
                        "completed_at": utc_now().isoformat(),
                        "error": str(nmap_err),
                    })
                    is_partial = True

        # ---------------------------------------------------------------------
        # Pre-Stage 3 Cooperative Cancellation Check
        # ---------------------------------------------------------------------
        if self._check_cancellation(investigation_id, workflow_job_id):
            logger.info("[%s] Cooperative cancellation detected before Stage 3", investigation_id)
            return _handle_cancellation("STAGE_3_VULN_ASSESSMENT")

        # ---------------------------------------------------------------------
        # STAGE 3: Vulnerability Assessment (Greenbone)
        # ---------------------------------------------------------------------
        t_stage3_start = utc_now()
        logger.info("[%s] Evaluating STAGE 3: Vulnerability Assessment on %s", investigation_id, clean_target)
        is_vuln_auth, vuln_reason = verify_target_authorization(
            db=self.db,
            investigation=inv,
            target=clean_target,
            operation="SCAN_VULN",
            actor_user=actor_user,
            client_ip=client_ip,
            request_id=request_id,
        )
        if not is_vuln_auth:
            stages_log.append({
                "stage_name": "VULNERABILITY_ASSESSMENT",
                "status": "SKIPPED_NOT_AUTHORIZED",
                "started_at": t_stage3_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "reason": f"Vulnerability assessment not authorized: {vuln_reason}",
            })
            is_partial = True
        else:
            try:
                vuln_orch = get_vuln_orchestrator()
                # Check Greenbone availability
                adapter_status = vuln_orch.adapter.check_availability() if hasattr(vuln_orch, "adapter") else {"configured": False}
                if not adapter_status.get("configured", False):
                    stages_log.append({
                        "stage_name": "VULNERABILITY_ASSESSMENT",
                        "status": "SKIPPED_UNAVAILABLE",
                        "started_at": t_stage3_start.isoformat(),
                        "completed_at": utc_now().isoformat(),
                        "reason": f"Greenbone Vulnerability Manager service is not configured or offline: {adapter_status.get('error', 'Not configured')}",
                    })
                    is_partial = True
                else:
                    import inspect
                    create_res = vuln_orch.create_assessment_job(
                        db=self.db,
                        investigation=inv,
                        target=clean_target,
                        profile_id=vuln_profile_id,
                        actor_user=actor_user,
                        client_ip=client_ip,
                        request_id=request_id,
                    )
                    vjob = await create_res if inspect.isawaitable(create_res) else create_res
                    from app.database import SessionLocal
                    await vuln_orch.execute_assessment_job(
                        job_id=vjob.id,
                        investigation_id=inv.id,
                        target=clean_target,
                        profile_id=vuln_profile_id,
                        requested_by=actor_user.username if hasattr(actor_user, "username") else str(actor_user),
                        client_ip=client_ip,
                        request_id=request_id,
                        db_factory=SessionLocal,
                    )
                    stages_log.append({
                        "stage_name": "VULNERABILITY_ASSESSMENT",
                        "status": "COMPLETED",
                        "job_id": vjob.id,
                        "started_at": t_stage3_start.isoformat(),
                        "completed_at": utc_now().isoformat(),
                    })
            except Exception as vuln_err:
                logger.warning("[%s] STAGE 3 Vulnerability assessment warning: %s", investigation_id, vuln_err)
                stages_log.append({
                    "stage_name": "VULNERABILITY_ASSESSMENT",
                    "status": "FAILED",
                    "started_at": t_stage3_start.isoformat(),
                    "completed_at": utc_now().isoformat(),
                    "error": str(vuln_err),
                })
                is_partial = True

        # ---------------------------------------------------------------------
        # Pre-Stage 4 Cooperative Cancellation Check
        # ---------------------------------------------------------------------
        if self._check_cancellation(investigation_id, workflow_job_id):
            logger.info("[%s] Cooperative cancellation detected before Stage 4", investigation_id)
            return _handle_cancellation("STAGE_4_FINDING_CORRELATION")

        # ---------------------------------------------------------------------
        # STAGE 4: Finding Correlation & Knowledge Graph
        # ---------------------------------------------------------------------
        t_stage4_start = utc_now()
        logger.info("[%s] Executing STAGE 4: Finding Correlation", investigation_id)
        correlation_result = {}
        try:
            correlation_result = self.correlation_service.correlate_investigation(investigation_id)
            stages_log.append({
                "stage_name": "FINDING_CORRELATION",
                "status": "COMPLETED",
                "started_at": t_stage4_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "summary": correlation_result.get("summary", {}),
            })
        except Exception as corr_err:
            logger.error("[%s] STAGE 4 Correlation error: %s", investigation_id, corr_err)
            stages_log.append({
                "stage_name": "FINDING_CORRELATION",
                "status": "FAILED",
                "started_at": t_stage4_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "error": str(corr_err),
            })
            is_partial = True

        # ---------------------------------------------------------------------
        # Pre-Stage 5 Cooperative Cancellation Check
        # ---------------------------------------------------------------------
        if self._check_cancellation(investigation_id, workflow_job_id):
            logger.info("[%s] Cooperative cancellation detected before Stage 5", investigation_id)
            return _handle_cancellation("STAGE_5_EXPOSURE_SCORING")

        # ---------------------------------------------------------------------
        # STAGE 5: Exposure Scoring
        # ---------------------------------------------------------------------
        t_stage5_start = utc_now()
        logger.info("[%s] Executing STAGE 5: Exposure Scoring", investigation_id)
        scoring_breakdown = None
        try:
            scoring_breakdown = ExposureScorer.calculate_for_investigation(investigation_id, self.db)
            stages_log.append({
                "stage_name": "EXPOSURE_SCORING",
                "status": "COMPLETED",
                "started_at": t_stage5_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "score": scoring_breakdown.total_score,
                "tier": scoring_breakdown.tier,
                "formula_version": scoring_breakdown.formula_version,
            })
        except Exception as score_err:
            logger.error("[%s] STAGE 5 Scoring error: %s", investigation_id, score_err)
            stages_log.append({
                "stage_name": "EXPOSURE_SCORING",
                "status": "FAILED",
                "started_at": t_stage5_start.isoformat(),
                "completed_at": utc_now().isoformat(),
                "error": str(score_err),
            })
            is_partial = True

        # ---------------------------------------------------------------------
        # Final Investigation Lifecycle Transition
        # ---------------------------------------------------------------------
        final_status = STATUS_PARTIALLY_COMPLETED if is_partial else STATUS_COMPLETED
        if can_transition(inv.status, final_status):
            inv.status = final_status
            self.db.commit()

        log_audit_event(
            db=self.db,
            event_type="INVESTIGATION_WORKFLOW_COMPLETED",
            outcome="SUCCESS" if final_status == STATUS_COMPLETED else "PARTIAL",
            actor_id=actor_user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "investigation_id": investigation_id,
                "final_status": final_status,
                "is_partial": is_partial,
                "stages_count": len(stages_log),
            },
        )

        return {
            "investigation_id": investigation_id,
            "target": clean_target,
            "workflow_status": final_status,
            "completed_at": utc_now().isoformat(),
            "stages": stages_log,
            "correlation_summary": correlation_result.get("summary", {}),
            "exposure_score": scoring_breakdown.to_dict() if scoring_breakdown else None,
        }

    def dispatch_workflow(
        self,
        investigation_id: str,
        actor_user: UserModel,
        target: Optional[str] = None,
        scan_profile_id: str = "service_inventory",
        vuln_profile_id: str = "full_and_fast",
    ) -> JobModel:
        """Enqueues workflow orchestration into the durable database-backed job queue."""
        inv = self.db.get(InvestigationModel, investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        require_investigation_access(inv, actor_user)
        resolved_target = self._resolve_primary_target(inv, target)

        if can_transition(inv.status, STATUS_QUEUED):
            inv.status = STATUS_QUEUED
            self.db.commit()

        job = self.job_queue.enqueue_job(
            db=self.db,
            investigation_id=investigation_id,
            job_type="WORKFLOW_ORCHESTRATION",
            operation="WORKFLOW_EXECUTE",
            target=resolved_target,
            requested_by=actor_user.id,
            parameters={
                "scan_profile_id": scan_profile_id,
                "vuln_profile_id": vuln_profile_id,
                "workflow_name": "end_to_end_investigation",
            },
            prevent_duplicates=True,
        )
        return job

    def cancel_workflow(
        self,
        investigation_id: str,
        actor_user: UserModel,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancels running or queued workflow jobs and transitions investigation to CANCELLED."""
        inv = self.db.get(InvestigationModel, investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        require_investigation_access(inv, actor_user)

        # Cancel active jobs for this investigation in queue
        active_jobs = self.db.scalars(
            select(JobModel).where(
                JobModel.investigation_id == investigation_id,
                JobModel.status.in_([JOB_STATUS_QUEUED, JOB_STATUS_RUNNING]),
            )
        ).all()

        cancelled_count = 0
        for j in active_jobs:
            self.job_queue.request_cancellation(
                db=self.db,
                job_id=j.id,
                reason=reason or "Investigation cancelled by investigator.",
                actor_id=actor_user.id,
            )
            cancelled_count += 1

        if can_transition(inv.status, STATUS_CANCELLED):
            inv.status = STATUS_CANCELLED
            self.db.commit()

        log_audit_event(
            db=self.db,
            event_type="INVESTIGATION_WORKFLOW_CANCELLED",
            outcome="SUCCESS",
            actor_id=actor_user.id,
            details={"investigation_id": investigation_id, "cancelled_jobs_count": cancelled_count},
        )

        return {
            "investigation_id": investigation_id,
            "status": STATUS_CANCELLED,
            "cancelled_jobs_count": cancelled_count,
        }

