"""Application Composition Root / Dependency Injection Bootstrap.

Centralizes construction and wiring of infrastructure adapters, repositories,
storage backends, and application use cases according to Clean Architecture.
"""

from typing import Optional
from sqlalchemy.orm import sessionmaker
from app.config import get_settings, Settings
from app.database import engine, SessionLocal, check_database_connection
from app.infrastructure.persistence.uow import SqlAlchemyUnitOfWork
from app.infrastructure.storage.filesystem_adapter import FilesystemStorageAdapter
from app.infrastructure.storage.seaweedfs_adapter import SeaweedFSStorageAdapter
from app.infrastructure.security_tools.nmap_adapter import NmapScannerAdapter
from app.infrastructure.security_tools.greenbone_adapter import GreenboneScannerAdapter
from app.infrastructure.reporting.pdf_adapter import PDFDossierAdapter
from app.infrastructure.reporting.graphml_adapter import GraphMLExportAdapter
from app.application.investigations.services import InvestigationApplicationService
from app.application.authorization.services import TargetAuthorizationService
from app.application.evidence.services import EvidenceApplicationService
from app.application.workflows.services import WorkflowApplicationService
from app.application.identity.services import IdentityApplicationService
from app.application.reporting.services import ReportingApplicationService
from app.infrastructure.logging import get_logger

logger = get_logger("footprintiq.bootstrap")


class ApplicationContainer:
    """Composition Root holding wired application services and infrastructure adapters."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.session_factory = SessionLocal
        self.uow = SqlAlchemyUnitOfWork(self.session_factory)

        # Storage adapters
        self.filesystem_storage = FilesystemStorageAdapter()
        self.seaweedfs_storage = SeaweedFSStorageAdapter()

        # Security tool ports
        self.nmap_scanner = NmapScannerAdapter()
        self.greenbone_scanner = GreenboneScannerAdapter()

        # Reporting ports
        self.dossier_generator = PDFDossierAdapter()
        self.graphml_exporter = GraphMLExportAdapter()

        # Application services
        self.investigation_service = InvestigationApplicationService(uow=self.uow)
        self.authorization_service = TargetAuthorizationService(uow=self.uow)
        self.evidence_service = EvidenceApplicationService(
            uow=self.uow,
            filesystem_storage=self.filesystem_storage,
            seaweedfs_storage=self.seaweedfs_storage,
        )
        self.workflow_service = WorkflowApplicationService(uow=self.uow)
        self.identity_service = IdentityApplicationService(uow=self.uow)
        self.reporting_service = ReportingApplicationService(
            uow=self.uow,
            dossier_port=self.dossier_generator,
            graph_port=self.graphml_exporter,
        )

    def verify_readiness(self) -> bool:
        """Verify database and infrastructure connectivity."""
        try:
            db_ok = check_database_connection()
            if not db_ok:
                logger.warning("Database connection check returned False during bootstrap.")
            return db_ok
        except Exception as e:
            logger.error("Readiness check encountered exception: %s", e)
            return False


_global_container: Optional[ApplicationContainer] = None


def bootstrap_application(settings: Optional[Settings] = None) -> ApplicationContainer:
    """Constructs and returns global ApplicationContainer singleton."""
    global _global_container
    if _global_container is None:
        _global_container = ApplicationContainer(settings=settings)
        logger.info("Application container successfully initialized via Clean Architecture bootstrap.")
    return _global_container

