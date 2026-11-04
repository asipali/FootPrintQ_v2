"""Workflow worker process polling durable queue."""

from typing import Optional
from app.services.jobs.worker import DurableJobWorker


class WorkflowWorker(DurableJobWorker):
    """Clean Architecture worker for background investigation workflow execution."""

    def __init__(self, worker_id: Optional[str] = None, poll_interval: float = 2.0):
        super().__init__(worker_id=worker_id, poll_interval=poll_interval)

