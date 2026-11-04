"""Reporting application service coordinating dossiers and graph exports."""

import hashlib
import uuid
from typing import Dict, Any
from app.application.common.interfaces.uow import IUnitOfWork
from app.application.common.interfaces.reporting import IDossierReportPort, IGraphExporterPort
from app.application.reporting.commands import GenerateDossierCommand, ExportGraphMLCommand
from app.domain.reporting.entities import InvestigationDossier
from app.domain.reporting.value_objects import ReportFormat, ReportMetadata
from app.domain.common.exceptions import EntityNotFoundException, UnauthorizedOperationException


class ReportingApplicationService:
    """Coordinates PDF dossier generation and GraphML export use cases."""

    def __init__(
        self,
        uow: IUnitOfWork,
        dossier_port: IDossierReportPort,
        graph_port: IGraphExporterPort,
    ):
        self.uow = uow
        self.dossier_port = dossier_port
        self.graph_port = graph_port

    def generate_pdf_dossier(self, cmd: GenerateDossierCommand) -> bytes:
        """Generate PDF dossier for authorized investigation."""
        with self.uow:
            inv = self.uow.investigations.get_by_id(cmd.investigation_id)
            if not inv:
                raise EntityNotFoundException(f"Investigation '{cmd.investigation_id}' not found.")
            if not inv.is_user_authorized(cmd.user_id, cmd.is_admin):
                raise UnauthorizedOperationException("Unauthorized to generate dossier for this investigation.")

            # Compile dossier payload
            data = {
                "investigation_id": inv.id,
                "name": inv.name,
                "organization_name": inv.organization_name,
                "description": inv.description,
                "lead_investigator": inv.lead_investigator,
                "status": inv.status.value,
            }
            return self.dossier_port.generate_pdf_dossier(data)

