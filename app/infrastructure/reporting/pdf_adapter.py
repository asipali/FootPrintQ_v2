"""PDF report generation adapter."""

from typing import Dict, Any, Optional
from app.application.common.interfaces.reporting import IDossierReportPort
from app.services.reporting.pdf_generator import InvestigationReportGenerator


class PDFDossierAdapter(IDossierReportPort):
    """Adapts InvestigationReportGenerator to application IDossierReportPort."""

    def __init__(self, generator: Optional[InvestigationReportGenerator] = None):
        self.generator = generator or InvestigationReportGenerator()

    def generate_pdf_dossier(self, data: Dict[str, Any]) -> bytes:
        return self.generator.generate(data)
