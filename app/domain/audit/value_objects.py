"""Domain value objects for security auditing."""

from enum import Enum


class AuditAction(str, Enum):
    """Categorization of audited security actions."""
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    INVESTIGATION_CREATE = "investigation.create"
    INVESTIGATION_UPDATE = "investigation.update"
    INVESTIGATION_DELETE = "investigation.delete"
    TARGET_AUTHORIZE = "target.authorize"
    TARGET_REVOKE = "target.revoke"
    WORKFLOW_DISPATCH = "workflow.dispatch"
    WORKFLOW_CANCEL = "workflow.cancel"
    EVIDENCE_CREATE = "evidence.create"
    EVIDENCE_MIGRATE = "evidence.migrate"
    EVIDENCE_DELETE = "evidence.delete"

