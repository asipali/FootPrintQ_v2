"""Greenbone / OpenVAS vulnerability scanner adapter."""

from typing import Dict, Any, Optional
from app.application.common.interfaces.scanners import IGreenboneScannerPort
from app.services.vuln.orchestrator import VulnerabilityAssessmentOrchestrator


class GreenboneScannerAdapter(IGreenboneScannerPort):
    """Adapts VulnerabilityAssessmentOrchestrator to IGreenboneScannerPort."""

    def __init__(self, orchestrator: Optional[VulnerabilityAssessmentOrchestrator] = None):
        self.orchestrator = orchestrator

    def scan_target(
        self,
        target: str,
        config: str = "Full and fast"
    ) -> Dict[str, Any]:
        if not self.orchestrator:
            return {"status": "SKIPPED", "reason": "Greenbone orchestrator not configured"}
        return self.orchestrator.run(target=target)
