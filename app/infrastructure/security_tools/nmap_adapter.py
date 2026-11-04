"""Nmap security scanner adapter."""

from typing import Dict, Any, Optional
from app.application.common.interfaces.scanners import INmapScannerPort
from app.services.active.runner import NmapRunner


class NmapScannerAdapter(INmapScannerPort):
    """Adapts NmapRunner to application INmapScannerPort."""

    def __init__(self, runner: Optional[NmapRunner] = None):
        self.runner = runner or NmapRunner()

    def scan_target(
        self,
        target: str,
        ports: str = "top-100",
        timing: str = "T3"
    ) -> Dict[str, Any]:
        return self.runner.run(target=target, profile=ports)
