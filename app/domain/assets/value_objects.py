"""Domain value objects for discovered assets."""

from enum import Enum


class AssetType(str, Enum):
    """Categorization of discovered digital assets."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    URL = "url"


class AssetCriticality(str, Enum):
    """Business criticality of an asset."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

