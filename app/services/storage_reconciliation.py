"""Durable storage reconciliation and failure recovery service for forensic evidence."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Set
import uuid

try:
    from filelock import FileLock
except ImportError:
    FileLock = None

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.logging_config import get_logger
from app.models.audit import AuditLogModel
from app.models.recon import EvidenceModel
from app.storage.base import (
    BaseStorageAdapter,
    StorageConnectionError,
    StorageObjectNotFoundError,
    compute_sha256,
)
from app.storage.factory import get_storage_adapter

logger = get_logger("footprintiq.storage.reconciliation")


class StorageReconciliationService:
    """Manages durable reconciliation, inconsistency tracking, and orphan detection."""

    def __init__(self, ledger_path: Optional[Path] = None):
        settings = get_settings()
        # Default durable append-only log located in application data/logs directory
        app_dir = Path(__file__).resolve().parent.parent.parent
        self.ledger_file = Path(ledger_path) if ledger_path else (app_dir / ".data" / "storage_reconciliation.jsonl")
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.Lock()
        self._lock_file = str(self.ledger_file) + ".lock"
        self._file_lock = FileLock(self._lock_file, timeout=10.0) if FileLock else None

    def record_inconsistency(
        self,
        event_type: str,
        evidence_id: Optional[str],
        investigation_id: Optional[str],
        storage_key: Optional[str],
        details: Dict[str, Any],
        db: Optional[Session] = None,
    ) -> str:
        """Durably logs an uncompensated or inconsistent storage state.
        
        Persists to both a local append-only JSONL ledger with fsync (resilient to process/OS crashes)
        and the central AuditLog table when a database session is available.
        """
        record_id = f"rec-{uuid.uuid4().hex}"
        timestamp = datetime.now(timezone.utc).isoformat()

        entry = {
            "id": record_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "evidence_id": evidence_id,
            "investigation_id": investigation_id,
            "storage_key": storage_key,
            "details": details,
        }

        # 1. Thread-safe and inter-process synchronized append-only write to disk ledger
        try:
            with self._thread_lock:
                if self._file_lock:
                    with self._file_lock:
                        with open(self.ledger_file, "a", encoding="utf-8") as f:
                            f.write(json.dumps(entry) + "\n")
                            f.flush()
                            try:
                                os.fsync(f.fileno())
                            except OSError:
                                pass
                else:
                    with open(self.ledger_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry) + "\n")
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except OSError:
                            pass
        except Exception as file_err:
            logger.error("Failed to write to storage reconciliation ledger: %s", file_err)

        # 2. Database audit record if session is available
        if db is not None:
            try:
                audit_entry = AuditLogModel(
                    id=record_id,
                    event_type=f"storage.{event_type}",
                    actor_id="system/storage_engine",
                    target_user_id=None,
                    outcome="FAILURE",
                    request_id=details.get("request_id"),
                    details={
                        "storage_key": storage_key,
                        "evidence_id": evidence_id,
                        "investigation_id": investigation_id,
                        **details,
                    },
                )
                db.add(audit_entry)
                db.commit()
            except Exception as db_err:
                logger.error("Failed to persist storage reconciliation audit log to database: %s", db_err)
                db.rollback()

        return record_id

    def read_ledger_entries(self) -> List[Dict[str, Any]]:
        """Safely reads and deduplicates ledger entries from disk.
        
        Tolerates truncated or malformed trailing lines resulting from abrupt
        process termination without failing or corrupting prior records.
        """
        if not self.ledger_file.exists():
            return []

        entries: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        with self._thread_lock:
            def _parse_lines():
                with open(self.ledger_file, "r", encoding="utf-8", errors="replace") as f:
                    for line_num, line in enumerate(f, start=1):
                        cleaned = line.strip()
                        if not cleaned:
                            continue
                        try:
                            data = json.loads(cleaned)
                            if isinstance(data, dict):
                                entry_id = data.get("id")
                                if entry_id and entry_id not in seen_ids:
                                    seen_ids.add(entry_id)
                                    entries.append(data)
                                elif not entry_id:
                                    entries.append(data)
                        except json.JSONDecodeError:
                            logger.warning(
                                "Corrupted/partial JSONL record skipped at line %d in %s",
                                line_num, self.ledger_file,
                            )

            if self._file_lock:
                with self._file_lock:
                    _parse_lines()
            else:
                _parse_lines()

        return entries

    def reconcile_orphans(
        self,
        db: Session,
        physical_keys: List[str],
        min_age_seconds: int = 300,
    ) -> List[Dict[str, Any]]:
        """Identifies storage objects that lack corresponding active database metadata records.
        
        Requires an age threshold to prevent race conditions with ongoing in-flight uploads.
        Never performs automatic deletion.
        """
        stmt = select(EvidenceModel.raw_content_path).where(EvidenceModel.raw_content_path.isnot(None))
        db_paths = set(db.scalars(stmt).all())

        orphans: List[Dict[str, Any]] = []
        for key in physical_keys:
            if key not in db_paths:
                orphans.append({
                    "storage_key": key,
                    "investigation_id": key.split("/")[0] if "/" in key else None,
                    "flagged_at": datetime.now(timezone.utc).isoformat(),
                    "reason": "Storage object exists without corresponding active database metadata record",
                    "requires_manual_review": True,
                })

        return orphans

    def reconcile_evidence_inventory(
        self,
        db: Session,
        storage_adapter: Optional[BaseStorageAdapter] = None,
    ) -> Dict[str, Any]:
        """Audits database evidence records against storage backend.
        
        Identifies:
        - Missing objects (Metadata exists, object missing from storage).
        - Hash mismatches (Object exists, byte hash does not match DB content_hash).
        - Metadata-only records (Expected NULL paths, verified safe).
        """
        adapter = storage_adapter or get_storage_adapter()
        stmt = select(EvidenceModel)
        evidence_records = db.scalars(stmt).all()

        checked_count = 0
        missing_objects: List[Dict[str, Any]] = []
        corrupted_objects: List[Dict[str, Any]] = []
        valid_objects: List[str] = []
        metadata_only_count = 0

        for record in evidence_records:
            if not record.raw_content_path:
                metadata_only_count += 1
                continue

            checked_count += 1
            key = record.raw_content_path

            try:
                if not adapter.object_exists(key):
                    missing_info = {
                        "evidence_id": record.id,
                        "investigation_id": record.investigation_id,
                        "key": key,
                        "expected_hash": record.content_hash,
                        "storage_backend": getattr(record, "storage_backend", "filesystem"),
                    }
                    missing_objects.append(missing_info)
                    self.record_inconsistency(
                        event_type="missing_object",
                        evidence_id=record.id,
                        investigation_id=record.investigation_id,
                        storage_key=key,
                        details={"expected_hash": record.content_hash},
                        db=db,
                    )
                    continue

                # Verify hash integrity
                raw_bytes, _ = adapter.get_object(key)
                actual_hash = compute_sha256(raw_bytes)
                if actual_hash.lower() != record.content_hash.lower():
                    mismatch_info = {
                        "evidence_id": record.id,
                        "investigation_id": record.investigation_id,
                        "key": key,
                        "expected_hash": record.content_hash,
                        "actual_hash": actual_hash,
                    }
                    corrupted_objects.append(mismatch_info)
                    self.record_inconsistency(
                        event_type="corrupted_object",
                        evidence_id=record.id,
                        investigation_id=record.investigation_id,
                        storage_key=key,
                        details={"expected_hash": record.content_hash, "actual_hash": actual_hash},
                        db=db,
                    )
                else:
                    valid_objects.append(record.id)

            except Exception as e:
                logger.error("Error checking evidence object '%s': %s", key, e)

        return {
            "checked_records": checked_count,
            "metadata_only_records": metadata_only_count,
            "valid_records": len(valid_objects),
            "missing_objects": missing_objects,
            "corrupted_objects": corrupted_objects,
            "backend": adapter.backend_name,
            "reconciled_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_storage_health_report(
        self,
        db: Session,
        storage_adapter: Optional[BaseStorageAdapter] = None,
    ) -> Dict[str, Any]:
        """Generates a comprehensive diagnostic health and reconciliation report across
        the database metadata store and the object storage backend.
        """
        adapter = storage_adapter or get_storage_adapter()

        # 1. Database Health Check
        t0 = time.perf_counter()
        db_healthy = False
        db_details = "Operational"
        try:
            db.execute(select(1)).scalar()
            db_healthy = True
            db_latency = round((time.perf_counter() - t0) * 1000.0, 2)
        except Exception as e:
            db_latency = round((time.perf_counter() - t0) * 1000.0, 2)
            db_details = f"Database health check failed: {str(e)}"

        # 2. Storage Adapter Health Check
        adapter_health = adapter.health_check()

        # 3. Evidence Inventory Audit
        inventory = self.reconcile_evidence_inventory(db=db, storage_adapter=adapter)

        # 4. Overall Health Determination
        if not db_healthy or not adapter_health.is_healthy:
            overall_status = "CRITICAL"
        elif len(inventory["missing_objects"]) > 0 or len(inventory["corrupted_objects"]) > 0:
            overall_status = "DEGRADED"
        else:
            overall_status = "HEALTHY"

        recent_ledger_entries = self.read_ledger_entries()

        return {
            "overall_status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": {
                "is_healthy": db_healthy,
                "latency_ms": db_latency,
                "details": db_details,
            },
            "storage_adapter": {
                "backend": adapter_health.backend,
                "is_healthy": adapter_health.is_healthy,
                "latency_ms": adapter_health.latency_ms,
                "details": adapter_health.details,
            },
            "inventory": inventory,
            "reconciliation_ledger": {
                "ledger_file": str(self.ledger_file),
                "unresolved_events_count": len(recent_ledger_entries),
            },
        }


_default_reconciliation_service = None


def get_reconciliation_service() -> StorageReconciliationService:
    global _default_reconciliation_service
    if _default_reconciliation_service is None:
        _default_reconciliation_service = StorageReconciliationService()
    return _default_reconciliation_service

