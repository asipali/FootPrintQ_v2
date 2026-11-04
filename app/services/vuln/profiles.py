"""Vetted, administrator-approved vulnerability assessment scan profiles for Greenbone / OpenVAS."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class VulnProfile:
    """Administrator-approved vulnerability assessment scan profile."""

    id: str
    name: str
    description: str
    gvm_config_name: str
    gvm_config_id: str
    intended_use: str
    allowed_target_types: List[str]
    timeout_seconds: int
    max_hosts: int
    is_enabled: bool
    operational_restrictions: str
    version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "gvm_config_name": self.gvm_config_name,
            "gvm_config_id": self.gvm_config_id,
            "intended_use": self.intended_use,
            "allowed_target_types": list(self.allowed_target_types),
            "timeout_seconds": self.timeout_seconds,
            "max_hosts": self.max_hosts,
            "is_enabled": self.is_enabled,
            "operational_restrictions": self.operational_restrictions,
            "version": self.version,
        }


# Standard predefined GVM scan config UUIDs
# Base: d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663
# Full and fast: daba56c8-73ec-11df-a475-002264764cea
# Discovery: 8715c877-47a0-438d-98a3-27c7a6ab2196
# Host Discovery: 2d3f051c-55ba-11e3-bf43-406186ea4fc5
# System Discovery: bbca7412-a950-11e3-9109-406186ea4fc5

VULN_PROFILES: Dict[str, VulnProfile] = {
    "openvas-basic": VulnProfile(
        id="openvas-basic",
        name="Greenbone Base / Conservative Assessment",
        description="Non-destructive vulnerability scan evaluating core network service vulnerabilities and misconfigurations.",
        gvm_config_name="Base",
        gvm_config_id="d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663",
        intended_use="Authorized lab targets and sensitive hosts requiring safe, non-invasive assessment.",
        allowed_target_types=["ipv4", "hostname"],
        timeout_seconds=1800,
        max_hosts=4,
        is_enabled=True,
        operational_restrictions="No denial-of-service, non-intrusive checks only, safe for production environments.",
        version="1.0",
    ),
    "openvas-full-and-fast": VulnProfile(
        id="openvas-full-and-fast",
        name="Greenbone Full and Fast Assessment",
        description="Comprehensive vulnerability scan using Greenbone's optimized Full and fast configuration.",
        gvm_config_name="Full and fast",
        gvm_config_id="daba56c8-73ec-11df-a475-002264764cea",
        intended_use="Standard authorized vulnerability assessments across lab environments and authorized target assets.",
        allowed_target_types=["ipv4", "hostname"],
        timeout_seconds=3600,
        max_hosts=8,
        is_enabled=True,
        operational_restrictions="Optimized checks with DoS plugins disabled by policy.",
        version="1.0",
    ),
    "openvas-discovery": VulnProfile(
        id="openvas-discovery",
        name="Greenbone Service & OS Discovery",
        description="Lightweight scan to enumerate services, operating systems, and basic security postures.",
        gvm_config_name="Discovery",
        gvm_config_id="8715c877-47a0-438d-98a3-27c7a6ab2196",
        intended_use="Pre-assessment network discovery and asset posture inventory.",
        allowed_target_types=["ipv4", "hostname"],
        timeout_seconds=900,
        max_hosts=16,
        is_enabled=True,
        operational_restrictions="Network discovery only, no vulnerability exploits attempted.",
        version="1.0",
    ),
    "openvas-host-discovery": VulnProfile(
        id="openvas-host-discovery",
        name="Greenbone Host Discovery",
        description="Non-intrusive host discovery detecting alive hosts without deep service exploitation.",
        gvm_config_name="Host Discovery",
        gvm_config_id="2d3f051c-55ba-11e3-bf43-406186ea4fc5",
        intended_use="Fast, non-invasive discovery of authorized network interfaces and alive assets.",
        allowed_target_types=["ipv4", "hostname"],
        timeout_seconds=600,
        max_hosts=32,
        is_enabled=True,
        operational_restrictions="Ping and ICMP/TCP echo only, zero vulnerability exploitation.",
        version="1.0",
    ),
}


def get_vuln_profile(profile_id: str) -> Optional[VulnProfile]:
    """Retrieve an approved vulnerability assessment profile by stable ID or alias."""
    if not profile_id:
        return None
    cleaned = str(profile_id).strip().lower()
    if cleaned in VULN_PROFILES:
        return VULN_PROFILES[cleaned]
    aliases = {
        "full_and_fast": "openvas-full-and-fast",
        "full-and-fast": "openvas-full-and-fast",
        "basic": "openvas-basic",
        "discovery": "openvas-discovery",
    }
    target_id = aliases.get(cleaned)
    if target_id and target_id in VULN_PROFILES:
        return VULN_PROFILES[target_id]
    return None


def list_vuln_profiles(include_disabled: bool = False) -> List[VulnProfile]:
    """List approved vulnerability assessment profiles."""
    if include_disabled:
        return list(VULN_PROFILES.values())
    return [p for p in VULN_PROFILES.values() if p.is_enabled]


def validate_vuln_profile(profile_id: str) -> VulnProfile:
    """Validate that the requested profile ID is known and enabled."""
    profile = get_vuln_profile(profile_id)
    if not profile:
        raise ValueError(f"Unknown vulnerability scan profile '{profile_id}'.")
    if not profile.is_enabled:
        raise ValueError(f"Vulnerability scan profile '{profile_id}' is disabled by policy.")
    return profile
