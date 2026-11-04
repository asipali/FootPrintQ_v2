"""Pure domain value objects with invariant validation."""

from dataclasses import dataclass
import re
import ipaddress
from typing import Any
from app.domain.common.exceptions import InvariantViolationException


@dataclass(frozen=True)
class ValueObject:
    """Base class for all immutable domain value objects."""
    pass


@dataclass(frozen=True)
class DomainName(ValueObject):
    """Normalized domain name value object."""
    value: str

    def __post_init__(self):
        cleaned = self.value.strip().lower().rstrip(".")
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(domain_pattern, cleaned):
            raise InvariantViolationException(f"Invalid domain name format: '{self.value}'")
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class IPAddress(ValueObject):
    """Normalized IPv4 or IPv6 address value object."""
    value: str

    def __post_init__(self):
        cleaned = self.value.strip()
        try:
            addr = ipaddress.ip_address(cleaned)
            object.__setattr__(self, "value", addr.compressed.lower())
        except ValueError:
            raise InvariantViolationException(f"Invalid IP address format: '{self.value}'")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class CIDRBlock(ValueObject):
    """Normalized CIDR network block value object."""
    value: str

    def __post_init__(self):
        cleaned = self.value.strip()
        try:
            net = ipaddress.ip_network(cleaned, strict=True)
            object.__setattr__(self, "value", str(net))
        except ValueError:
            raise InvariantViolationException(f"Invalid CIDR network format: '{self.value}'")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class SHA256Checksum(ValueObject):
    """Cryptographic SHA-256 hash value object."""
    value: str

    def __post_init__(self):
        cleaned = self.value.strip().lower()
        if len(cleaned) != 64 or not all(c in "0123456789abcdef" for c in cleaned):
            raise InvariantViolationException(f"Invalid SHA-256 hex checksum: '{self.value}'")
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value

