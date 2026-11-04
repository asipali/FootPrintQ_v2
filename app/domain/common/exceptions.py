"""Pure domain exceptions hierarchy."""


class DomainException(Exception):
    """Base domain exception representing business rule violations."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class EntityNotFoundException(DomainException):
    """Raised when an entity requested by identity does not exist in domain context."""
    pass


class InvariantViolationException(DomainException):
    """Raised when a business invariant or value object constraint is breached."""
    pass


class UnauthorizedOperationException(DomainException):
    """Raised when a domain operation lacks required scope authorization."""
    pass


class InvalidStateTransitionException(DomainException):
    """Raised when an aggregate state transition violates the state machine guards."""
    pass

