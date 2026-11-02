"""Investigation visibility and mutation policy shared by Modules 05 and 06."""

from fastapi import HTTPException, status

from app.core.security import ROLE_ADMINISTRATOR
from app.models.investigation import InvestigationModel
from app.models.user import UserModel


def can_access_investigation(investigation: InvestigationModel, user: UserModel) -> bool:
    """Administrators can review all records; other users see only their own records.

    Historical investigations have no owner until explicitly assigned, so they remain
    available to administrators and are hidden from non-administrators.
    """
    return user.role == ROLE_ADMINISTRATOR or (
        investigation.owner_user_id is not None
        and investigation.owner_user_id == user.id
    )


def require_investigation_access(
    investigation: InvestigationModel | None,
    user: UserModel,
) -> InvestigationModel:
    """Return an accessible investigation or a non-disclosing 404 response."""
    if investigation is None or not can_access_investigation(investigation, user):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )
    return investigation
