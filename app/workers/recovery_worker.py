"""Lease and orphan job recovery worker."""

from app.services.jobs.recovery import JobRecoveryService


class RecoveryWorker:
    """Worker responsible for recovering orphaned jobs on startup and periodically."""

    @staticmethod
    def recover_orphans(db_session=None) -> int:
        """Run orphan recovery check."""
        return JobRecoveryService.recover_orphaned_jobs(db=db_session)

