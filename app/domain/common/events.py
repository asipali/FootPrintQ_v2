"""Pure domain events and in-memory event dispatcher."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Type, Any
import uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class DomainEvent:
    """Base domain event with event ID and creation timestamp."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at: datetime = field(default_factory=utc_now)


class DomainEventDispatcher:
    """In-memory synchronous domain event dispatcher for decoupling domain side-effects."""

    def __init__(self):
        self._handlers: Dict[Type[DomainEvent], List[Callable[[Any], None]]] = {}

    def register(self, event_type: Type[DomainEvent], handler: Callable[[Any], None]) -> None:
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def dispatch(self, event: DomainEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            handler(event)


# Global singleton dispatcher instance
domain_event_dispatcher = DomainEventDispatcher()
