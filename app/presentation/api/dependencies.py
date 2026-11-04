"""Presentation layer dependencies and dependency injection container bindings."""

from typing import Generator
from fastapi import Depends
from sqlalchemy.orm import Session
from app.database import get_db, SessionLocal
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


def get_uow() -> Generator[SqlAlchemyUnitOfWork, None, None]:
    """Dependency provider for Unit of Work."""
    uow = SqlAlchemyUnitOfWork(SessionLocal)
    try:
        yield uow
    finally:
        pass


def get_investigation_service(uow: SqlAlchemyUnitOfWork = Depends(get_uow)) -> InvestigationApplicationService:
    """Dependency provider for InvestigationApplicationService."""
    return InvestigationApplicationService(uow=uow)


def get_authorization_service(uow: SqlAlchemyUnitOfWork = Depends(get_uow)) -> TargetAuthorizationService:
    """Dependency provider for TargetAuthorizationService."""
    return TargetAuthorizationService(uow=uow)


def get_evidence_service(uow: SqlAlchemyUnitOfWork = Depends(get_uow)) -> EvidenceApplicationService:
    """Dependency provider for EvidenceApplicationService."""
    fs_adapter = FilesystemStorageAdapter()
    seaweed_adapter = SeaweedFSStorageAdapter()
    return EvidenceApplicationService(
        uow=uow,
        filesystem_storage=fs_adapter,
        seaweedfs_storage=seaweed_adapter,
    )


def get_workflow_service(uow: SqlAlchemyUnitOfWork = Depends(get_uow)) -> WorkflowApplicationService:
    """Dependency provider for WorkflowApplicationService."""
    return WorkflowApplicationService(uow=uow)


def get_identity_service(uow: SqlAlchemyUnitOfWork = Depends(get_uow)) -> IdentityApplicationService:
    """Dependency provider for IdentityApplicationService."""
    return IdentityApplicationService(uow=uow)


def get_reporting_service(uow: SqlAlchemyUnitOfWork = Depends(get_uow)) -> ReportingApplicationService:
    """Dependency provider for ReportingApplicationService."""
    dossier_port = PDFDossierAdapter()
    graph_port = GraphMLExportAdapter()
    return ReportingApplicationService(
        uow=uow,
        dossier_port=dossier_port,
        graph_port=graph_port,
    )

