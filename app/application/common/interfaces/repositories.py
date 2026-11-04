"""Repository port interfaces for Clean Architecture application layer."""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from app.domain.investigations.entities import Investigation
from app.domain.identity.entities import User, UserSession
from app.domain.authorization.entities import TargetAuthorization
from app.domain.evidence.entities import EvidenceItem
from app.domain.workflows.entities import WorkflowJob
from app.domain.audit.entities import SecurityAuditEvent


class IInvestigationRepository(ABC):
    """Port for investigation persistence."""

    @abstractmethod
    def get_by_id(self, investigation_id: str) -> Optional[Investigation]:
        """Retrieve investigation by ID."""
        pass

    @abstractmethod
    def list_all(self, limit: int = 100, offset: int = 0) -> List[Investigation]:
        """List investigations with pagination."""
        pass

    @abstractmethod
    def save(self, investigation: Investigation) -> Investigation:
        """Persist or update an investigation."""
        pass

    @abstractmethod
    def delete(self, investigation_id: str) -> bool:
        """Delete an investigation."""
        pass


class IUserRepository(ABC):
    """Port for user identity persistence."""

    @abstractmethod
    def get_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve user by ID."""
        pass

    @abstractmethod
    def get_by_username(self, username: str) -> Optional[User]:
        """Retrieve user by unique username."""
        pass

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[User]:
        """Retrieve user by email address."""
        pass

    @abstractmethod
    def save(self, user: User) -> User:
        """Save or update a user."""
        pass


class ITargetAuthorizationRepository(ABC):
    """Port for target authorizations."""

    @abstractmethod
    def get_by_id(self, auth_id: str) -> Optional[TargetAuthorization]:
        """Retrieve target authorization by ID."""
        pass

    @abstractmethod
    def list_by_investigation(self, investigation_id: str) -> List[TargetAuthorization]:
        """List all authorizations for an investigation."""
        pass

    @abstractmethod
    def find_active(self, investigation_id: str, target: str) -> Optional[TargetAuthorization]:
        """Find active authorization covering target."""
        pass

    @abstractmethod
    def save(self, auth: TargetAuthorization) -> TargetAuthorization:
        """Save authorization record."""
        pass


class IEvidenceRepository(ABC):
    """Port for forensic evidence persistence."""

    @abstractmethod
    def get_by_id(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Retrieve evidence item by ID."""
        pass

    @abstractmethod
    def list_by_investigation(self, investigation_id: str) -> List[EvidenceItem]:
        """List all evidence for an investigation."""
        pass

    @abstractmethod
    def save(self, item: EvidenceItem) -> EvidenceItem:
        """Save or update evidence record."""
        pass


class IJobRepository(ABC):
    """Port for durable job queue persistence."""

    @abstractmethod
    def get_by_id(self, job_id: str) -> Optional[WorkflowJob]:
        """Retrieve job by ID."""
        pass

    @abstractmethod
    def list_pending(self, limit: int = 10) -> List[WorkflowJob]:
        """Fetch unclaimed queued jobs."""
        pass

    @abstractmethod
    def save(self, job: WorkflowJob) -> WorkflowJob:
        """Save or update job state."""
        pass


class IAuditLogRepository(ABC):
    """Port for security audit logs."""

    @abstractmethod
    def log_event(self, event: SecurityAuditEvent) -> None:
        """Persist security audit event."""
        pass

