"""SQLAlchemy implementation of IUserRepository."""

from typing import Optional
from sqlalchemy.orm import Session
from app.application.common.interfaces.repositories import IUserRepository
from app.domain.identity.entities import User
from app.domain.identity.value_objects import UserRole, AccountStatus, Username, EmailAddress
from app.models.user import UserModel


class SqlAlchemyUserRepository(IUserRepository):
    """Concrete repository mapping between User domain entity and SQLAlchemy model."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, user_id: str) -> Optional[User]:
        model = self.session.get(UserModel, user_id)
        return self._to_domain(model) if model else None

    def get_by_username(self, username: str) -> Optional[User]:
        model = self.session.query(UserModel).filter(UserModel.username == username.strip().lower()).first()
        return self._to_domain(model) if model else None

    def get_by_email(self, email: str) -> Optional[User]:
        model = self.session.query(UserModel).filter(UserModel.email == email.strip().lower()).first()
        return self._to_domain(model) if model else None

    def save(self, user: User) -> User:
        model = self.session.get(UserModel, user.id)
        if not model:
            model = UserModel(id=user.id)
            self.session.add(model)

        model.username = user.username.value
        model.email = user.email.value
        model.password_hash = user.hashed_password
        model.full_name = user.full_name
        model.role = user.role.value
        model.account_status = user.status.value
        model.is_active = user.is_active
        model.failed_login_attempts = user.failed_login_attempts
        model.locked_until = user.locked_until

        self.session.flush()
        return self._to_domain(model)

    @staticmethod
    def _to_domain(model: UserModel) -> User:
        try:
            role_enum = UserRole(model.role.lower())
        except (ValueError, AttributeError):
            role_enum = UserRole.INVESTIGATOR

        try:
            status_enum = AccountStatus(model.account_status.lower())
        except (ValueError, AttributeError):
            status_enum = AccountStatus.ACTIVE

        return User(
            id=model.id,
            username=Username(model.username),
            email=EmailAddress(model.email),
            hashed_password=model.password_hash,
            full_name=model.full_name,
            role=role_enum,
            status=status_enum,
            is_active=model.is_active,
            failed_login_attempts=model.failed_login_attempts,
            locked_until=model.locked_until,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )
