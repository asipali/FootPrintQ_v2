"""Domain common abstractions."""

from app.domain.common.entities import Entity, AggregateRoot, utc_now
from app.domain.common.value_objects import (
    ValueObject,
    DomainName,
    IPAddress,
    CIDRBlock,
    SHA256Checksum,
)
from app.domain.common.exceptions import (
    DomainException,
    EntityNotFoundException,
    InvariantViolationException,
    UnauthorizedOperationException,
    InvalidStateTransitionException,
)
from app.domain.common.events import DomainEvent, DomainEventDispatcher, domain_event_dispatcher

__all__ = [
    "Entity",
    "AggregateRoot",
    "utc_now",
    "ValueObject",
    "DomainName",
    "IPAddress",
    "CIDRBlock",
    "SHA256Checksum",
    "DomainException",
    "EntityNotFoundException",
    "InvariantViolationException",
    "UnauthorizedOperationException",
    "InvalidStateTransitionException",
    "DomainEvent",
    "DomainEventDispatcher",
    "domain_event_dispatcher",
]

