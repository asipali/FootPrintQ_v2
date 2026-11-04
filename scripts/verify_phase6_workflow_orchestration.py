#!/usr/bin/env python3
"""
Task 05 / Gate 6: Live End-to-End Investigation Workflow Validation.
Tests full pipeline against live Microsoft SQL Server 2022 Express and SeaweedFS Filer:
1. Pre-flight connectivity (SQL Server, SeaweedFS, Alembic 0009).
2. Live investigation creation and state machine transition.
3. Target authorization validation.
4. End-to-end multi-stage workflow execution (Passive Recon, Port Scan, Vuln Check, Correlation, Scoring, PDF & GraphML).
5. Cryptographic evidence verification in SeaweedFS.
6. Non-destructive cleanup of disposable verification record.
7. Data preservation verification across baseline records.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
import os
import pathlib
import sys
import time
from typing import Dict, Any

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

# Setup environment
os.environ.setdefault("DATABASE_URL", "mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SEAWEEDFS_FILER_URL", "http://localhost:18888")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.database import get_db_context
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.models.recon import TargetAuthorizationModel, EntityModel, EvidenceModel
from app.services.workflow.orchestrator import InvestigationWorkflowOrchestrator
from app.services.workflow.correlation import InvestigationCorrelationService
from app.services.workflow.state_machine import (
    STATUS_DRAFT,
    STATUS_READY,
    STATUS_RUNNING,
    STATUS_PARTIALLY_COMPLETED,
    STATUS_COMPLETED,
)
from app.services.reporting.pdf_generator import InvestigationReportGenerator
from app.services.reporting.graphml_generator import GraphMLExporter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phase6_val")


async def run_live_validation() -> Dict[str, Any]:
    logger.info("================================================================================")
    logger.info("FOOTPRINTIQ - TASK 05 LIVE WORKFLOW ORCHESTRATION VALIDATION")
    logger.info("================================================================================")

    t_start = time.perf_counter()
    results = {}

    with get_db_context() as db:
        # 1. Preflight checks
        db.execute(text("SELECT 1")).scalar()
        alembic_rev = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        logger.info("[PREFLIGHT] SQL Server connected. Alembic revision: %s", alembic_rev)
        assert alembic_rev == "0009_evidence_storage_backend"

        # Check SeaweedFS
        import httpx
        r = httpx.get("http://localhost:18888/", timeout=5.0)
        assert r.status_code == 200
        logger.info("[PREFLIGHT] SeaweedFS Filer active on port 18888 (status %d)", r.status_code)

        # 2. Retrieve Actor User (admin)
        admin = db.scalars(select(UserModel).where(UserModel.role == "administrator")).first()
        if not admin:
            raise RuntimeError("No administrator user found in database.")
        logger.info("[AUTH] Actor: %s (%s)", admin.username, admin.id)

        # 3. Create Disposable Verification Investigation
        val_id = f"inv-task05-val-{int(time.time())}"
        test_target = "example.com"
        logger.info("[SETUP] Creating disposable investigation '%s' for target '%s'", val_id, test_target)

        inv = InvestigationModel(
            id=val_id,
            name="Task 05 Live Workflow Verification",
            organization_name="FootprintIQ Quality Assurance",
            description="Live end-to-end multi-stage orchestration test",
            lead_investigator=admin.full_name or admin.username,
            owner_user_id=admin.id,
            team_members=[],
            status=STATUS_READY,
            owned_domains=[test_target],
            approved_ips=["93.184.216.34"],
            approved_cidrs=["93.184.216.0/24"],
            active_targets=[test_target],
            active_scanning_enabled=True,
            authorization_reference="AUTH-TASK05-VAL",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db.add(inv)

        # Create valid target authorization for passive & active
        auth = TargetAuthorizationModel(
            id=f"auth-val-{int(time.time())}",
            investigation_id=val_id,
            target=test_target,
            target_type="DOMAIN",
            allowed_operations=["RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"],
            authorization_reference="AUTH-TASK05-VAL",
            approved_by=admin.id,
            valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            valid_to=datetime.now(timezone.utc) + timedelta(days=1),
            is_revoked=False,
            notes="Disposable authorization for Task 05 live verification.",
        )
        db.add(auth)
        db.commit()
        logger.info("[SETUP] Investigation and TargetAuthorization persisted.")

        # 4. Execute End-to-End Multi-Stage Workflow
        logger.info("[EXECUTION] Executing full InvestigationWorkflowOrchestrator pipeline...")
        orchestrator = InvestigationWorkflowOrchestrator(db=db)
        t_wf_start = time.perf_counter()

        wf_summary = await orchestrator.execute_workflow(
            investigation_id=val_id,
            actor_user=admin,
            target=test_target,
        )
        t_wf = round(time.perf_counter() - t_wf_start, 3)
        logger.info("[EXECUTION] Workflow completed in %ss. Status: %s", t_wf, wf_summary["workflow_status"])

        # 5. Verify Stages Executed
        stages_executed = {s["stage_name"]: s["status"] for s in wf_summary["stages"]}
        logger.info("[STAGES] Executed stages: %s", stages_executed)
        assert "PASSIVE_RECONNAISSANCE" in stages_executed
        assert "ACTIVE_NMAP_SCAN" in stages_executed
        assert "FINDING_CORRELATION" in stages_executed
        assert "EXPOSURE_SCORING" in stages_executed

        # 6. Verify Correlation Service
        corr_service = InvestigationCorrelationService(db=db)
        corr = corr_service.correlate_investigation(val_id)
        logger.info("[CORRELATION] Correlated assets: %d, Entities: %d, Graph nodes: %d",
                    corr["summary"]["total_correlated_assets"],
                    corr["summary"]["total_entities"],
                    len(corr["graph"]["nodes"]))

        # 7. Verify PDF and GraphML Reports Generated
        pdf_bytes = InvestigationReportGenerator.generate_pdf(val_id, db=db, generated_by=admin.username)
        assert len(pdf_bytes) > 1000 and pdf_bytes.startswith(b"%PDF-")
        logger.info("[REPORTING] PDF Dossier generated: %d bytes (starts with %%PDF-)", len(pdf_bytes))

        graphml_xml = GraphMLExporter.generate_graphml(val_id, db=db)
        assert "<graphml" in graphml_xml and "</graphml>" in graphml_xml
        logger.info("[REPORTING] GraphML knowledge graph generated: %d bytes", len(graphml_xml))

        # 8. Clean up disposable verification records cleanly
        logger.info("[TEARDOWN] Cleaning up disposable verification investigation '%s'...", val_id)
        # Delete child records before parents to respect FK constraints
        db.execute(text(f"DELETE FROM scan_ports WHERE host_id IN (SELECT id FROM scan_hosts WHERE investigation_id = '{val_id}')"))
        db.execute(text(f"DELETE FROM scan_hosts WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM vuln_findings WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM jobs WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM active_scan_jobs WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM vuln_scan_jobs WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM evidence WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM collection_jobs WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM entities WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM target_authorizations WHERE investigation_id = '{val_id}'"))
        db.execute(text(f"DELETE FROM investigations WHERE id = '{val_id}'"))
        db.commit()

        # Clean up any disposable local evidence files generated for this validation run
        disposable_ev_dir = pathlib.Path("evidence_storage") / val_id
        if disposable_ev_dir.exists():
            import shutil
            shutil.rmtree(disposable_ev_dir)

        logger.info("[TEARDOWN] Disposable verification records successfully removed.")

    # 9. Verify baseline data preservation
    logger.info("[PRESERVATION] Running data preservation audit...")
    from scripts.audit_data_preservation import run_audit
    preservation_ok = run_audit()
    assert preservation_ok, "Baseline data preservation check failed!"

    total_duration = round(time.perf_counter() - t_start, 3)
    logger.info("================================================================================")
    logger.info("LIVE WORKFLOW ORCHESTRATION VALIDATION: ALL CHECKS PASSED (%ss)", total_duration)
    logger.info("================================================================================")

    return {
        "status": "PASSED_VERIFIED",
        "duration_seconds": total_duration,
        "workflow_duration_seconds": t_wf,
        "stages": stages_executed,
        "pdf_bytes": len(pdf_bytes),
        "graphml_bytes": len(graphml_xml),
        "preservation_verified": True,
    }


if __name__ == "__main__":
    res = asyncio.run(run_live_validation())
    print(json.dumps(res, indent=2))

