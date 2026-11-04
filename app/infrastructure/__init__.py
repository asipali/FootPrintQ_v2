"""Infrastructure layer package for FootprintIQ Clean Architecture.

Contains persistence (SQLAlchemy engines, repositories, UoW), storage adapters,
security scanner adapters, reporting tools, and system configuration.
"""

from app.infrastructure.persistence import (
    engine,
    SessionLocal,
    get_db,
    Base,
    SqlAlchemyUnitOfWork,
    SqlAlchemyInvestigationRepository,
    SqlAlchemyUserRepository,
    SqlAlchemyTargetAuthorizationRepository,
    SqlAlchemyEvidenceRepository,
    SqlAlchemyJobRepository,
    SqlAlchemyAuditLogRepository,
)
from app.infrastructure.storage import (
    FilesystemStorageAdapter,
    SeaweedFSStorageAdapter,
)
from app.infrastructure.security_tools import (
    NmapScannerAdapter,
    GreenboneScannerAdapter,
)
from app.infrastructure.reporting import (
    PDFDossierAdapter,
    GraphMLExportAdapter,
)
from app.infrastructure.configuration import settings, Settings
from app.infrastructure.logging import get_logger

__all__ = [
    "engine",
    "SessionLocal",
    "get_db",
    "Base",
    "SqlAlchemyUnitOfWork",
    "SqlAlchemyInvestigationRepository",
    "SqlAlchemyUserRepository",
    "SqlAlchemyTargetAuthorizationRepository",
    "SqlAlchemyEvidenceRepository",
    "SqlAlchemyJobRepository",
    "SqlAlchemyAuditLogRepository",
    "FilesystemStorageAdapter",
    "SeaweedFSStorageAdapter",
    "NmapScannerAdapter",
    "GreenboneScannerAdapter",
    "PDFDossierAdapter",
    "GraphMLExportAdapter",
    "settings",
    "Settings",
    "get_logger",
]

