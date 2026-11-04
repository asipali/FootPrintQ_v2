"""Pure domain base entities and aggregate roots for FootprintIQ."""

from abc import ABC
from datetime import datetime, timezone
from typing import Optional, List, Any


def utc_now() -> datetime:
    """Returns timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class Entity(ABC):
    """Base class for all domain entities. Equality based on identity (id)."""

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Entity):
            return False
        return getattr(self, "id", None) == getattr(other, "id", None)

    def __hash__(self) -> int:
        return hash(getattr(self, "id", None))


class AggregateRoot(Entity):
    """Aggregate root managing internal consistency and recording domain events."""

    def record_event(self, event: Any) -> None:
        if not hasattr(self, "_domain_events"):
            self._domain_events = []
        self._domain_events.append(event)

    def clear_events(self) -> List[Any]:
        if not hasattr(self, "_domain_events"):
            return []
        events = list(self._domain_events)
        self._domain_events.clear()
        return events
