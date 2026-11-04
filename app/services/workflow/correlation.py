"""Investigation Finding Correlation & Knowledge Graph Engine for FootprintIQ.

Connects and deduplicates multi-source forensic findings across:
- Discovered domains, subdomains, IPs, and email entities.
- Active Nmap host discovery, open ports, and fingerprinting.
- Greenbone vulnerability findings and CVE associations.
- Raw evidence references and cryptographic provenance.
"""

from typing import Any, Dict
from sqlalchemy.orm import Session

from app.services.correlation.engine import CorrelationEngine


class InvestigationCorrelationService:
    """Consolidates cross-stage investigation findings into correlated asset profiles."""

    def __init__(self, db: Session):
        self.db = db
        self.engine = CorrelationEngine(db)

    def correlate_investigation(self, investigation_id: str) -> Dict[str, Any]:
        """Performs full cross-stage correlation for a given investigation."""
        return self.engine.run_correlation(investigation_id)
