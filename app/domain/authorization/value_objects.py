"""Domain value objects for target authorization."""

from enum import Enum


class TargetType(str, Enum):
    """Types of targets subjected to authorization."""
    DOMAIN = "DOMAIN"
    IP = "IP"
    CIDR = "CIDR"


class OperationType(str, Enum):
    """Allowed operations on targets."""
    PASSIVE_DNS = "PASSIVE_DNS"
    WHOIS = "WHOIS"
    CERT_LOOKUP = "CERT_LOOKUP"
    HTTP_PROBE = "HTTP_PROBE"
    ACTIVE_SCAN = "ACTIVE_SCAN"
    VULN_SCAN = "VULN_SCAN"
    PORT_SCAN = "PORT_SCAN"
    FULL_WORKFLOW = "FULL_WORKFLOW"

