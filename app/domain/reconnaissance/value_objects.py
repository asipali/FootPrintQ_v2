"""Domain value objects for reconnaissance."""

from enum import Enum


class ReconType(str, Enum):
    """Types of reconnaissance modules."""
    PASSIVE_DNS = "passive_dns"
    WHOIS = "whois"
    CERTIFICATE = "certificate"
    HTTP_PROBE = "http_probe"
    ACTIVE_SCAN = "active_scan"
    PORT_SCAN = "port_scan"


class CollectionJobStatus(str, Enum):
    """Execution status for collection jobs."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"

