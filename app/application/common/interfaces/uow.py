"""Unit of Work interface for transaction boundaries."""

from abc import ABC, abstractmethod
from typing import Any
from app.application.common.interfaces.repositories import (
    IInvestigationRepository,
    IUserRepository,
    ITargetAuthorizationRepository,
    IEvidenceRepository,
    IJobRepository,
    IAuditLogRepository,
)


class IUnitOfWork(ABC):
    """Transactional context manager defining repository boundaries."""

    investigations: IInvestigationRepository
    users: IUserRepository
    authorizations: ITargetAuthorizationRepository
    evidence: IEvidenceRepository
    jobs: IJobRepository
    audit_logs: IAuditLogRepository

    @abstractmethod
    def __enter__(self) -> "IUnitOfWork":
        pass

    @abstractmethod
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    @abstractmethod
    def commit(self) -> None:
        """Commit current transaction."""
        pass

    @abstractmethod
    def rollback(self) -> None:
        """Rollback current transaction."""
        pass

