"""Domain entities for digital assets."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from app.domain.common.entities import Entity, utc_now
from app.domain.assets.value_objects import AssetType, AssetCriticality


@dataclass
class Asset(Entity):
    """Generic discovered digital asset."""
    id: str
    investigation_id: str
    asset_type: AssetType
    identifier: str  # e.g., domain name, IP string
    attributes: Dict[str, Any] = field(default_factory=dict)
    criticality: AssetCriticality = AssetCriticality.LOW
    discovered_at: datetime = field(default_factory=utc_now)
    last_seen_at: datetime = field(default_factory=utc_now)


@dataclass
class HostAsset(Entity):
    """Discovered network host."""
    id: str
    investigation_id: str
    ip_address: str
    hostname: Optional[str] = None
    os_family: Optional[str] = None
    os_accuracy: Optional[int] = None
    is_up: bool = True
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass
class ServiceAsset(Entity):
    """Discovered network service or listening port."""
    id: str
    host_id: str
    investigation_id: str
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    state: str = "open"
    discovered_at: datetime = field(default_factory=utc_now)

