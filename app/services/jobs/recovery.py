"""Startup recovery service to detect stale leases, kill orphaned scanner subprocesses, and reconcile job state."""

from contextlib import contextmanager
import logging
import os
import signal
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.auth import log_audit_event
from app.models.job import (
    JobModel,
    JOB_STATUS_CLAIMED,
    JOB_STATUS_RUNNING,
    JOB_STATUS_FAILED,
    JOB_STATUS_CANCELLED,
    utc_now,
    ensure_utc,
)
from app.models.scan import ActiveScanJobModel
from app.models.vulnerability import VulnerabilityScanJobModel

logger = logging.getLogger("footprintiq.services.jobs.recovery")


class JobRecoveryService:
    """Detects and reconciles orphaned jobs and terminated worker processes after server reboot or crash."""

    @staticmethod
    def _is_pid_alive(pid: int) -> bool:
        """Checks whether an operating-system process is still alive."""
        if not pid or pid <= 0:
            return False
        try:
            if os.name == "nt":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(0x0400, False, pid)  # PROCESS_QUERY_INFORMATION
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except (OSError, ProcessLookupError, PermissionError):
            return False

    @staticmethod
    def _terminate_pid(pid: int) -> bool:
        """Safely terminates an orphaned child process."""
        if not pid or pid <= 0:
            return False
        try:
            if os.name == "nt":
                import subprocess
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
            else:
                os.kill(pid, signal.SIGKILL)
            return True
        except Exception as exc:
            logger.warning("Failed to terminate orphaned PID %d: %s", pid, exc)
            return False

    def recover_stale_jobs(self, db_factory: Any) -> Dict[str, Any]:
        """Scans for uncompleted jobs stranded in RUNNING or CLAIMED state upon server reboot."""
        recovered_jobs = 0
        reconciled_nmap = 0
        reconciled_vuln = 0
        now = utc_now()

        # Handle both sessionmakers/contextmanagers and raw Sessions (e.g. pytest db_session)
        is_raw_session = isinstance(db_factory, Session)
        if is_raw_session:
            db = db_factory
        else:
            session_obj = db_factory()
            if hasattr(session_obj, "__enter__"):
                return self._recover_with_context(session_obj)
            db = session_obj

        return self._do_recover(db, now)

    def _recover_with_context(self, ctx) -> Dict[str, Any]:
        with ctx as db:
            return self._do_recover(db, utc_now())

    def _do_recover(self, db: Session, now: datetime) -> Dict[str, Any]:
        recovered_jobs = 0
        reconciled_nmap = 0
        reconciled_vuln = 0

        # 1. Recover unified JobModel records
        stale_jobs = list(
            db.scalars(
                select(JobModel).where(
                    JobModel.status.in_([JOB_STATUS_CLAIMED, JOB_STATUS_RUNNING])
                )
            ).all()
        )

        for job in stale_jobs:
            logger.warning(
                "Recovering stranded job %s (type=%s, status=%s, worker=%s, pid=%s)",
                job.id, job.job_type, job.status, job.worker_id, job.process_pid
            )

            # Terminate any orphaned child process
            if job.process_pid and self._is_pid_alive(job.process_pid):
                logger.info("Terminating orphaned scanner PID %d for job %s", job.process_pid, job.id)
                self._terminate_pid(job.process_pid)

            # Transition job to FAILED
            job.status = JOB_STATUS_FAILED
            job.error_category = "SERVER_RESTARTED"
            job.error_message = (
                "Execution interrupted by application server restart/crash; "
                "stranded worker lease recovered on startup."
            )
            job.completed_at = now
            if job.started_at:
                job.duration_seconds = max(0.0, (ensure_utc(now) - ensure_utc(job.started_at)).total_seconds())

            # Synchronize legacy nmap record if present
            nmap_record = db.get(ActiveScanJobModel, job.id)
            if nmap_record and nmap_record.status in ("QUEUED", "RUNNING", "AUTHORIZING"):
                nmap_record.status = "FAILED"
                nmap_record.error_category = "SERVER_RESTARTED"
                nmap_record.error_message = job.error_message
                nmap_record.completed_at = now
                reconciled_nmap += 1

            # Synchronize legacy vulnerability record if present
            vuln_record = db.get(VulnerabilityScanJobModel, job.id)
            if vuln_record and vuln_record.status in ("QUEUED", "RUNNING", "AUTHORIZING", "CREATING_TASK"):
                vuln_record.status = "FAILED"
                vuln_record.error_category = "SERVER_RESTARTED"
                vuln_record.error_message = job.error_message
                vuln_record.completed_at = now
                reconciled_vuln += 1

            log_audit_event(
                db=db,
                event_type="JOB_RECOVERY_RECONCILED",
                outcome="SUCCESS",
                actor_id=job.requested_by,
                details={
                    "job_id": job.id,
                    "job_type": job.job_type,
                    "previous_worker": job.worker_id,
                    "terminated_pid": job.process_pid,
                },
            )
            recovered_jobs += 1

        # 2. Reconcile standalone ActiveScanJobModel records not tracked in jobs table
        orphan_nmap = list(
            db.scalars(
                select(ActiveScanJobModel).where(
                    ActiveScanJobModel.status.in_(["RUNNING", "AUTHORIZING"])
                )
            ).all()
        )
        for n_job in orphan_nmap:
            if n_job.status in ("RUNNING", "AUTHORIZING"):
                n_job.status = "FAILED"
                n_job.error_category = "SERVER_RESTARTED"
                n_job.error_message = "Scan interrupted by server restart; recovered on startup."
                n_job.completed_at = now
                reconciled_nmap += 1

        # 3. Reconcile standalone VulnerabilityScanJobModel records not tracked in jobs table
        orphan_vuln = list(
            db.scalars(
                select(VulnerabilityScanJobModel).where(
                    VulnerabilityScanJobModel.status.in_(["RUNNING", "AUTHORIZING", "CREATING_TASK"])
                )
            ).all()
        )
        for v_job in orphan_vuln:
            if v_job.status in ("RUNNING", "AUTHORIZING", "CREATING_TASK"):
                v_job.status = "FAILED"
                v_job.error_category = "SERVER_RESTARTED"
                v_job.error_message = "Assessment interrupted by server restart; recovered on startup."
                v_job.completed_at = now
                reconciled_vuln += 1

        db.commit()

        summary = {
            "recovered_jobs": recovered_jobs,
            "reconciled_nmap": reconciled_nmap,
            "reconciled_vuln": reconciled_vuln,
        }
        if recovered_jobs > 0 or reconciled_nmap > 0 or reconciled_vuln > 0:
            logger.info("Startup recovery complete: %s", summary)
        else:
            logger.info("Startup recovery scan complete: zero stranded jobs found.")
        return summary


_recovery_service_instance: Optional[JobRecoveryService] = None


def get_job_recovery() -> JobRecoveryService:
    global _recovery_service_instance
    if _recovery_service_instance is None:
        _recovery_service_instance = JobRecoveryService()
    return _recovery_service_instance
