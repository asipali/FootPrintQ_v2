"""Scanner port interfaces for active reconnaissance and vulnerability assessment."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class INmapScannerPort(ABC):
    """Port for active network port scanning."""

    @abstractmethod
    def scan_target(
        self,
        target: str,
        ports: str = "top-100",
        timing: str = "T3"
    ) -> Dict[str, Any]:
        """Execute Nmap scan on target and return structured output."""
        pass


class IGreenboneScannerPort(ABC):
    """Port for vulnerability scanning."""

    @abstractmethod
    def scan_target(
        self,
        target: str,
        config: str = "Full and fast"
    ) -> Dict[str, Any]:
        """Execute vulnerability scan on target and return structured findings."""
        pass

