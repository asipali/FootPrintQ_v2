"""SQLAlchemy implementation of IAuditLogRepository."""

from sqlalchemy.orm import Session
from app.application.common.interfaces.repositories import IAuditLogRepository
from app.domain.audit.entities import SecurityAuditEvent
from app.models.audit import AuditLogModel


class SqlAlchemyAuditLogRepository(IAuditLogRepository):
    """Concrete repository mapping between SecurityAuditEvent and SQLAlchemy model."""

    def __init__(self, session: Session):
        self.session = session

    def log_event(self, event: SecurityAuditEvent) -> None:
        model = AuditLogModel(
            id=event.id,
            event_type=event.event_type,
            outcome=event.outcome,
            actor_id=event.actor_id,
            target_user_id=event.target_user_id,
            request_id=event.request_id,
            ip_address=event.ip_address,
            details=dict(event.details or {}),
            timestamp=event.timestamp,
        )
        self.session.add(model)
        self.session.flush()

