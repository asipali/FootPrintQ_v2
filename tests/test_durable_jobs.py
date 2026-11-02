"""Tests for durable background job execution, queue management, and restart recovery."""

import asyncio
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.models.job import (
    JobModel,
    JOB_STATUS_QUEUED,
    JOB_STATUS_CLAIMED,
    JOB_STATUS_RUNNING,
    JOB_STATUS_COMPLETED,
    JOB_STATUS_FAILED,
    JOB_STATUS_RETRY_WAIT,
    JOB_STATUS_CANCEL_REQUESTED,
    JOB_STATUS_CANCELLED,
    JOB_STATUS_TIMED_OUT,
    utc_now,
)
from app.models.scan import ActiveScanJobModel
from app.models.vulnerability import VulnerabilityScanJobModel
from app.services.jobs.queue import JobQueueService, DuplicateJobError, get_job_queue
from app.services.jobs.recovery import JobRecoveryService, get_job_recovery
from app.services.jobs.worker import DurableJobWorker


@pytest.fixture
def test_investigation(db_session: Session, admin_user) -> InvestigationModel:
    inv = InvestigationModel(
        id=f"inv-jobs-{uuid.uuid4().hex[:10]}",
        name="Durable Jobs Test Investigation",
        organization_name="Lab",
        description="Testing durable background jobs",
        lead_investigator="Admin",
        owner_user_id=admin_user.id,
        status="active",
        approved_ips=["127.0.0.1"],
        active_targets=["127.0.0.1"],
        active_scanning_enabled=True,
    )
    db_session.add(inv)
    db_session.commit()
    return inv


@pytest.fixture
def test_evidence(db_session: Session, test_investigation) -> EvidenceModel:
    evi = EvidenceModel(
        id=f"evi-test-{uuid.uuid4().hex[:8]}",
        investigation_id=test_investigation.id,
        source_type="nmap",
        source_name="Nmap Test",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path=f"{test_investigation.id}/test.raw.txt",
        content_hash="abc123hash",
        content_size_bytes=100,
        collected_at=utc_now(),
    )
    db_session.add(evi)
    db_session.commit()
    return evi


def test_enqueue_job_persists_sanitized_record(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    params = {
        "target": "127.0.0.1",
        "profile_id": "basic_tcp",
        "api_key": "super-secret-key-12345",
        "nested": {"password": "confidential_pass", "safe": "value"},
    }
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
        parameters=params,
        max_retries=2,
    )

    assert job.id is not None
    assert job.status == JOB_STATUS_QUEUED
    assert job.progress == 0
    assert job.max_retries == 2
    assert job.retry_count == 0
    # Assert parameters sanitized
    assert job.parameters["api_key"] == "[REDACTED]"
    assert job.parameters["nested"]["password"] == "[REDACTED]"
    assert job.parameters["nested"]["safe"] == "value"


def test_enqueue_duplicate_active_job_rejected(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
        prevent_duplicates=True,
    )

    with pytest.raises(DuplicateJobError, match="already QUEUED"):
        queue.enqueue_job(
            db=db_session,
            investigation_id=test_investigation.id,
            job_type="NMAP_SCAN",
            operation="SCAN_ACTIVE",
            target="127.0.0.1",
            requested_by=admin_user.id,
            prevent_duplicates=True,
        )


def test_atomic_claim_next_job(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
    )

    # Worker 1 claims
    claimed = queue.claim_next_job(db=db_session, worker_id="worker-node-1", supported_types=["NMAP_SCAN"])
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == JOB_STATUS_CLAIMED
    assert claimed.worker_id == "worker-node-1"
    assert claimed.lease_expires_at is not None

    # Worker 2 attempts claim concurrently; should get None
    claimed_2 = queue.claim_next_job(db=db_session, worker_id="worker-node-2", supported_types=["NMAP_SCAN"])
    assert claimed_2 is None


def test_start_job_and_heartbeat_progress(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
    )
    queue.claim_next_job(db=db_session, worker_id="worker-node-1")

    started = queue.start_job(db=db_session, job_id=job.id, worker_id="worker-node-1", process_pid=99999)
    assert started.status == JOB_STATUS_RUNNING
    assert started.started_at is not None
    assert started.process_pid == 99999

    # Heartbeat pulse
    ok = queue.heartbeat(db=db_session, job_id=job.id, worker_id="worker-node-1", progress=45)
    assert ok is True
    fresh = queue.get_job(db_session, job.id)
    assert fresh.progress == 45
    assert fresh.heartbeat_at is not None


def test_complete_job_sets_duration_and_progress(db_session: Session, test_investigation, test_evidence, admin_user):
    queue = JobQueueService()
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
    )
    queue.claim_next_job(db=db_session, worker_id="worker-node-1")
    queue.start_job(db=db_session, job_id=job.id, worker_id="worker-node-1")

    completed = queue.complete_job(db=db_session, job_id=job.id, evidence_id=test_evidence.id)
    assert completed.status == JOB_STATUS_COMPLETED
    assert completed.progress == 100
    assert completed.evidence_id == test_evidence.id
    assert completed.completed_at is not None
    assert completed.duration_seconds is not None


def test_fail_job_retries_then_permanently_fails(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
        max_retries=1,
    )
    queue.claim_next_job(db=db_session, worker_id="worker-node-1")
    queue.start_job(db=db_session, job_id=job.id, worker_id="worker-node-1")

    # First failure -> moves to RETRY_WAIT
    failed_1 = queue.fail_job(db=db_session, job_id=job.id, error_category="NETWORK", error_message="timeout", allow_retry=True)
    assert failed_1.status == JOB_STATUS_RETRY_WAIT
    assert failed_1.retry_count == 1

    # Claim again and fail second time -> moves to permanent FAILED
    queue.claim_next_job(db=db_session, worker_id="worker-node-1")
    failed_2 = queue.fail_job(db=db_session, job_id=job.id, error_category="NETWORK", error_message="timeout", allow_retry=True)
    assert failed_2.status == JOB_STATUS_FAILED
    assert failed_2.retry_count == 1


def test_cancel_queued_job_immediately_cancels(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
    )
    success, msg = queue.request_cancellation(db=db_session, job_id=job.id, reason="User cancelled")
    assert success is True
    fresh = queue.get_job(db_session, job.id)
    assert fresh.status == JOB_STATUS_CANCELLED
    assert fresh.cancellation_requested is True


def test_cancel_running_job_sets_cancel_requested(db_session: Session, test_investigation, admin_user):
    queue = JobQueueService()
    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
    )
    queue.claim_next_job(db=db_session, worker_id="worker-node-1")
    queue.start_job(db=db_session, job_id=job.id, worker_id="worker-node-1")

    success, msg = queue.request_cancellation(db=db_session, job_id=job.id, reason="Emergency stop")
    assert success is True
    fresh = queue.get_job(db_session, job.id)
    assert fresh.status == JOB_STATUS_CANCEL_REQUESTED
    assert fresh.cancellation_requested is True
    assert fresh.cancellation_reason == "Emergency stop"


def test_startup_restart_recovery_reconciles_stranded_jobs(db_session: Session, test_investigation, admin_user):
    recovery = JobRecoveryService()

    # Seed stranded JobModel in RUNNING
    job_id = f"job-strand-{uuid.uuid4().hex[:8]}"
    durable_job = JobModel(
        id=job_id,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        parameters={},
        status=JOB_STATUS_RUNNING,
        progress=30,
        requested_by=admin_user.id,
        worker_id="old-crashed-worker",
        process_pid=999999,
        started_at=utc_now() - timedelta(minutes=10),
        created_at=utc_now() - timedelta(minutes=10),
        updated_at=utc_now() - timedelta(minutes=10),
    )
    # Seed corresponding ActiveScanJobModel
    nmap_job = ActiveScanJobModel(
        id=job_id,
        investigation_id=test_investigation.id,
        requested_by=admin_user.id,
        target="127.0.0.1",
        resolved_ips=["127.0.0.1"],
        scan_profile="basic_tcp",
        status="RUNNING",
    )
    db_session.add_all([durable_job, nmap_job])
    db_session.commit()

    # Run recovery passing raw db_session
    summary = recovery.recover_stale_jobs(db_factory=db_session)
    assert summary["recovered_jobs"] >= 1
    assert summary["reconciled_nmap"] >= 1

    recovered_durable = db_session.get(JobModel, job_id)
    recovered_nmap = db_session.get(ActiveScanJobModel, job_id)
    assert recovered_durable.status == JOB_STATUS_FAILED
    assert recovered_durable.error_category == "SERVER_RESTARTED"
    assert recovered_nmap.status == "FAILED"
    assert recovered_nmap.error_category == "SERVER_RESTARTED"


@pytest.mark.asyncio
async def test_durable_worker_executes_registered_handler(db_session: Session, test_investigation, test_evidence, admin_user):
    queue = JobQueueService()
    worker = DurableJobWorker(worker_id="test-async-worker", max_concurrency=2)
    executed_jobs = []

    evi_id = test_evidence.id

    async def mock_nmap_handler(db_factory, job_id):
        executed_jobs.append(job_id)
        return {"evidence_id": evi_id}

    worker.register_handler("NMAP_SCAN", mock_nmap_handler)

    job = queue.enqueue_job(
        db=db_session,
        investigation_id=test_investigation.id,
        job_type="NMAP_SCAN",
        operation="SCAN_ACTIVE",
        target="127.0.0.1",
        requested_by=admin_user.id,
    )

    # Run worker wrapper directly on claimed job
    claimed = queue.claim_next_job(db=db_session, worker_id=worker.worker_id)
    assert claimed is not None
    await worker._execute_job_wrapper(lambda: db_session, claimed.id, claimed.job_type)

    fresh = queue.get_job(db_session, job.id)
    assert fresh.status == JOB_STATUS_COMPLETED
    assert fresh.progress == 100
    assert fresh.evidence_id == evi_id
    assert fresh.id in executed_jobs
