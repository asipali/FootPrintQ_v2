"""Asynchronous background worker supervisor managing claiming, heartbeat loops, and execution."""

import asyncio
from contextlib import contextmanager
import logging
import socket
from typing import Any, Callable, Dict, List, Optional
import uuid

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.job import (
    JobModel,
    JOB_STATUS_RUNNING,
    JOB_STATUS_CANCELLED,
    JOB_STATUS_CANCEL_REQUESTED,
)
from app.services.jobs.queue import JobQueueService, get_job_queue

logger = logging.getLogger("footprintiq.services.jobs.worker")


@contextmanager
def _session_scope(db_factory: Any):
    """Context manager handling both session factories and direct Session fixtures."""
    if isinstance(db_factory, Session):
        yield db_factory
    else:
        obj = db_factory()
        if hasattr(obj, "__enter__"):
            with obj as db:
                yield db
        else:
            yield obj


class DurableJobWorker:
    """Asynchronous worker that polls the persistent job queue, leases jobs, and coordinates execution."""

    def __init__(
        self,
        worker_id: Optional[str] = None,
        max_concurrency: int = 4,
        supported_types: Optional[List[str]] = None,
    ):
        settings = get_settings()
        self.worker_id = worker_id or f"worker-{socket.gethostname()[:12]}-{uuid.uuid4().hex[:8]}"
        self.max_concurrency = max_concurrency or settings.NMAP_MAX_CONCURRENCY
        self.supported_types = supported_types or ["NMAP_SCAN", "VULN_SCAN", "PASSIVE_RECON"]
        self.queue = get_job_queue()
        self._running = False
        self._stop_event = asyncio.Event()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._handlers: Dict[str, Callable] = {}

    def register_handler(self, job_type: str, handler: Callable):
        """Registers an asynchronous handler callable for a specific job_type."""
        self._handlers[job_type] = handler

    async def start(self, db_factory: Any, poll_interval: float = 2.0):
        """Starts the worker polling loop."""
        self._running = True
        self._stop_event.clear()
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        logger.info(
            "Starting DurableJobWorker %s (concurrency=%d, types=%s)",
            self.worker_id, self.max_concurrency, self.supported_types
        )

        while self._running and not self._stop_event.is_set():
            try:
                # Wait for available concurrency slot
                await self._semaphore.acquire()

                # Poll and claim next available job
                claimed_job = None
                with _session_scope(db_factory) as db:
                    claimed_job = self.queue.claim_next_job(
                        db=db,
                        worker_id=self.worker_id,
                        supported_types=self.supported_types,
                        lease_duration_seconds=60,
                    )

                if claimed_job:
                    # Spawn job execution task
                    task = asyncio.create_task(
                        self._execute_job_wrapper(db_factory, claimed_job.id, claimed_job.job_type)
                    )
                    self._active_tasks[claimed_job.id] = task
                    task.add_done_callback(lambda t, jid=claimed_job.id: self._on_task_done(jid))
                else:
                    # No job claimed; release slot and wait
                    self._semaphore.release()
                    await asyncio.sleep(poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in worker polling loop: %s", exc, exc_info=True)
                try:
                    self._semaphore.release()
                except ValueError:
                    pass
                await asyncio.sleep(poll_interval)

        logger.info("DurableJobWorker %s stopped polling.", self.worker_id)

    def _on_task_done(self, job_id: str):
        """Releases semaphore slot and cleans task registry."""
        self._active_tasks.pop(job_id, None)
        if self._semaphore:
            try:
                self._semaphore.release()
            except ValueError:
                pass

    async def _execute_job_wrapper(self, db_factory: Any, job_id: str, job_type: str):
        """Coordinates execution, background heartbeat pulsing, and completion/failure transitions."""
        handler = self._handlers.get(job_type)
        if not handler:
            logger.error("No registered handler for job type '%s' (job %s)", job_type, job_id)
            with _session_scope(db_factory) as db:
                self.queue.fail_job(db, job_id, "CONFIG_ERROR", f"No worker handler registered for {job_type}")
            return

        heartbeat_task: Optional[asyncio.Task] = None
        try:
            # 1. Transition job to RUNNING
            with _session_scope(db_factory) as db:
                job = self.queue.start_job(db, job_id, self.worker_id)

            # 2. Spawn heartbeat loop (pulses every 5s)
            heartbeat_task = asyncio.create_task(self._heartbeat_loop(db_factory, job_id))

            # 3. Execute job handler
            logger.info("Worker %s executing job %s (%s)", self.worker_id, job_id, job_type)
            result = await handler(db_factory, job_id)

            # 4. Mark COMPLETED
            evidence_id = result.get("evidence_id") if isinstance(result, dict) else None
            with _session_scope(db_factory) as db:
                self.queue.complete_job(db, job_id, evidence_id=evidence_id)

        except asyncio.CancelledError:
            logger.warning("Task execution cancelled for job %s", job_id)
            with _session_scope(db_factory) as db:
                job = self.queue.get_job(db, job_id)
                if job and job.status not in ("COMPLETED", "FAILED", "CANCELLED"):
                    job.status = JOB_STATUS_CANCELLED
                    job.completed_at = job.updated_at
                    db.commit()
        except Exception as exc:
            logger.error("Unhandled exception during job execution %s: %s", job_id, exc, exc_info=True)
            with _session_scope(db_factory) as db:
                self.queue.fail_job(db, job_id, "EXECUTION_ERROR", str(exc))
        finally:
            if heartbeat_task and not heartbeat_task.done():
                heartbeat_task.cancel()

    async def _heartbeat_loop(self, db_factory: Any, job_id: str, interval: float = 5.0):
        """Periodically extends job lease while execution is active."""
        while True:
            try:
                await asyncio.sleep(interval)
                with _session_scope(db_factory) as db:
                    alive = self.queue.heartbeat(db, job_id, self.worker_id, lease_duration_seconds=60)
                    if not alive:
                        logger.warning("Heartbeat returned False for job %s; stopping pulse.", job_id)
                        break
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Error pulsing heartbeat for job %s: %s", job_id, exc)

    async def stop(self, timeout: float = 10.0):
        """Signals worker shutdown and gracefully awaits active job completion."""
        self._running = False
        self._stop_event.set()
        if self._active_tasks:
            logger.info("Worker %s awaiting %d active tasks...", self.worker_id, len(self._active_tasks))
            tasks = list(self._active_tasks.values())
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Worker %s shutdown timed out; cancelling remaining tasks.", self.worker_id)
                for t in tasks:
                    t.cancel()


_worker_instance: Optional[DurableJobWorker] = None


def get_job_worker() -> DurableJobWorker:
    global _worker_instance
    if _worker_instance is None:
        _worker_instance = DurableJobWorker()
    return _worker_instance
