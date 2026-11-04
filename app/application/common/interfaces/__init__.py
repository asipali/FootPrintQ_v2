"""Application layer common interfaces and ports."""

from app.application.common.interfaces.repositories import (
    IInvestigationRepository,
    IUserRepository,
    ITargetAuthorizationRepository,
    IEvidenceRepository,
    IJobRepository,
    IAuditLogRepository,
)
from app.application.common.interfaces.storage import IEvidenceStoragePort
from app.application.common.interfaces.scanners import INmapScannerPort, IGreenboneScannerPort
from app.application.common.interfaces.reporting import IDossierReportPort, IGraphExporterPort
from app.application.common.interfaces.uow import IUnitOfWork

__all__ = [
    "IInvestigationRepository",
    "IUserRepository",
    "ITargetAuthorizationRepository",
    "IEvidenceRepository",
    "IJobRepository",
    "IAuditLogRepository",
    "IEvidenceStoragePort",
    "INmapScannerPort",
    "IGreenboneScannerPort",
    "IDossierReportPort",
    "IGraphExporterPort",
    "IUnitOfWork",
]

