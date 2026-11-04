"""Reporting port interfaces for dossiers and graphs."""

from abc import ABC, abstractmethod
from typing import Dict, Any
from app.domain.reporting.entities import InvestigationDossier
from app.domain.correlation.entities import CorrelatedGraph


class IDossierReportPort(ABC):
    """Port for generating formatted investigation dossiers (PDF/HTML)."""

    @abstractmethod
    def generate_pdf_dossier(self, data: Dict[str, Any]) -> bytes:
        """Render investigation dossier to PDF bytes."""
        pass


class IGraphExporterPort(ABC):
    """Port for exporting intelligence graphs (GraphML, JSON)."""

    @abstractmethod
    def export_graphml(self, graph: CorrelatedGraph) -> str:
        """Export correlation graph to GraphML XML format."""
        pass

