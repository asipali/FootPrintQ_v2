"""SQLAlchemy Unit of Work implementation."""

from typing import Optional, Any
from sqlalchemy.orm import Session
from app.application.common.interfaces.uow import IUnitOfWork
from app.infrastructure.persistence.repositories.investigation_repo import SqlAlchemyInvestigationRepository
from app.infrastructure.persistence.repositories.user_repo import SqlAlchemyUserRepository
from app.infrastructure.persistence.repositories.authorization_repo import SqlAlchemyTargetAuthorizationRepository
from app.infrastructure.persistence.repositories.evidence_repo import SqlAlchemyEvidenceRepository
from app.infrastructure.persistence.repositories.job_repo import SqlAlchemyJobRepository
from app.infrastructure.persistence.repositories.audit_repo import SqlAlchemyAuditLogRepository


class SqlAlchemyUnitOfWork(IUnitOfWork):
    """SQLAlchemy implementation of Unit of Work managing transaction boundaries."""

    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.session: Optional[Session] = None

    def __enter__(self) -> "SqlAlchemyUnitOfWork":
        self.session = self.session_factory()
        self.investigations = SqlAlchemyInvestigationRepository(self.session)
        self.users = SqlAlchemyUserRepository(self.session)
        self.authorizations = SqlAlchemyTargetAuthorizationRepository(self.session)
        self.evidence = SqlAlchemyEvidenceRepository(self.session)
        self.jobs = SqlAlchemyJobRepository(self.session)
        self.audit_logs = SqlAlchemyAuditLogRepository(self.session)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.session:
            if exc_type is not None:
                self.rollback()
            self.session.close()

    def commit(self) -> None:
        if self.session:
            self.session.commit()

    def rollback(self) -> None:
        if self.session:
            self.session.rollback()

