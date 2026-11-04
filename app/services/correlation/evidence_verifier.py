"""Phase F — Evidence Integrity and Traceability for FootprintIQ correlation engine."""

import hashlib
import logging
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.recon import EvidenceModel
from app.services.correlation.models import EvidenceVerificationState
from app.services.evidence_store import get_evidence_store

logger = logging.getLogger("footprintiq.services.correlation.evidence_verifier")


class EvidenceVerifier:
    """Verifies evidence integrity and cryptographic SHA-256 hashes against backend storage."""

    def __init__(self, db: Session):
        self.db = db
        self.evidence_store = get_evidence_store()
        self._cache: Dict[str, Tuple[EvidenceVerificationState, Optional[EvidenceModel]]] = {}

    def verify_evidence(self, evidence_id: Optional[str]) -> Tuple[EvidenceVerificationState, Optional[EvidenceModel]]:
        """Resolves an evidence reference, retrieves its payload, and checks SHA-256 hash match.
        
        Returns:
            (verification_status, evidence_model)
        """
        if not evidence_id:
            return EvidenceVerificationState.NOT_APPLICABLE, None

        if evidence_id in self._cache:
            return self._cache[evidence_id]

        evidence = self.db.get(EvidenceModel, evidence_id)
        if not evidence:
            logger.warning("Evidence reference '%s' not found in database.", evidence_id)
            res = (EvidenceVerificationState.UNAVAILABLE, None)
            self._cache[evidence_id] = res
            return res

        # If evidence recorded failed collection originally
        if evidence.collection_status != "SUCCESS" or not evidence.raw_content_path:
            logger.info("Evidence '%s' recorded non-success status '%s'.", evidence_id, evidence.collection_status)
            res = (EvidenceVerificationState.UNAVAILABLE, evidence)
            self._cache[evidence_id] = res
            return res

        # Retrieve raw content from EvidenceStore
        try:
            content_bytes, computed_hash = self.evidence_store.read_evidence(
                relative_path=evidence.raw_content_path,
                backend=evidence.storage_backend,
            )
        except Exception as e:
            logger.warning("Failed to retrieve evidence '%s' from backend '%s': %s", evidence_id, evidence.storage_backend, e)
            res = (EvidenceVerificationState.UNAVAILABLE, evidence)
            self._cache[evidence_id] = res
            return res

        # Verify SHA-256 hash
        if evidence.content_hash:
            if computed_hash.lower() == evidence.content_hash.lower():
                res = (EvidenceVerificationState.VERIFIED, evidence)
            else:
                logger.error(
                    "Evidence '%s' HASH MISMATCH! Recorded %s != Computed %s",
                    evidence_id, evidence.content_hash, computed_hash
                )
                res = (EvidenceVerificationState.HASH_MISMATCH, evidence)
        else:
            res = (EvidenceVerificationState.UNAVAILABLE, evidence)

        self._cache[evidence_id] = res
        return res

    def batch_verify(self, evidence_ids: List[str]) -> Dict[str, EvidenceVerificationState]:
        """Batch verifies multiple evidence references and returns verification state map."""
        results: Dict[str, EvidenceVerificationState] = {}
        for eid in evidence_ids:
            if eid:
                st, _ = self.verify_evidence(eid)
                results[eid] = st
        return results
