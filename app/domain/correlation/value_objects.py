"""Domain value objects for intelligence correlation and graph analysis."""

from enum import Enum


class NodeType(str, Enum):
    """Types of graph nodes."""
    INVESTIGATION = "investigation"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    ORGANIZATION = "organization"
    CERTIFICATE = "certificate"


class RelationshipType(str, Enum):
    """Relationship semantics between graph nodes."""
    TARGETS = "targets"
    RESOLVES_TO = "resolves_to"
    RUNS_SERVICE = "runs_service"
    EXPOSES = "exposes"
    AFFECTED_BY = "affected_by"
    ISSUED_TO = "issued_to"
    ASSOCIATED_WITH = "associated_with"

