"""Verification script for real Greenbone vulnerability assessment execution."""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import get_db_context
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.models.vulnerability import VulnerabilityScanJobModel
from app.services.vuln.orchestrator import VulnerabilityAssessmentOrchestrator
from app.services.vuln.profiles import get_vuln_profile

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("test_real_gvm_scan")

async def main():
    logger.info("Initializing Greenbone Orchestrator...")
    orchestrator = VulnerabilityAssessmentOrchestrator()
    
    # 1. Check availability
    status = orchestrator.adapter.check_availability()
    logger.info("Greenbone availability: %s", status)
    assert status.get("status") in ("HEALTHY", "READY"), f"GVM not healthy: {status}"

    inv_id = "inv-dbddbcd3a4"
    target_ip = "192.168.56.107"
    profile_id = "openvas-discovery"  # Service & OS discovery

    with get_db_context() as db:
        inv = db.get(InvestigationModel, inv_id)
        user = db.query(UserModel).filter(UserModel.role == "administrator").first()
        assert inv is not None, f"Investigation {inv_id} not found"
        assert user is not None, "Admin user not found"
        user_id = user.id
        
        logger.info("Creating assessment job for target %s in %s...", target_ip, inv_id)
        job = orchestrator.create_assessment_job(
            db=db,
            investigation=inv,
            target=target_ip,
            profile_id=profile_id,
            actor_user=user,
        )
        job_id = job.id
        logger.info("Job created: %s (Status: %s)", job_id, job.status)

    logger.info("Executing assessment job %s...", job_id)
    await orchestrator.execute_assessment_job(
        job_id=job_id,
        investigation_id=inv_id,
        target=target_ip,
        profile_id=profile_id,
        requested_by=user_id,
    )

    with get_db_context() as db:
        completed_job = db.get(VulnerabilityScanJobModel, job_id)
        logger.info("Job execution finished. Final status: %s, Progress: %s, Error: %s (%s)",
                    completed_job.status, completed_job.progress, completed_job.error_message, completed_job.error_category)
        logger.info("Evidence ID: %s, GVM Task ID: %s, GVM Report ID: %s, Duration: %s",
                    completed_job.evidence_id, completed_job.gvm_task_id, completed_job.gvm_report_id, completed_job.duration_seconds)

if __name__ == "__main__":
    asyncio.run(main())
