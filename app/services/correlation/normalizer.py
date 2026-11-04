"""Phase B — Normalized Asset Identity Model for FootprintIQ correlation engine."""

import ipaddress
import re
from typing import Any, Optional, Tuple
from urllib.parse import urlparse

from app.services.correlation.models import AssetType


def normalize_ipv4(ip_str: Optional[str]) -> Optional[str]:
    """Normalizes an IPv4 address to its canonical dotted-quad string.
    
    Rejects IPv6 addresses, CIDRs, or invalid formats.
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.IPv4Address(cleaned)
        return str(addr)
    except ValueError:
        return None


def normalize_ipv6(ip_str: Optional[str]) -> Optional[str]:
    """Normalizes an IPv6 address to standard compressed lowercase RFC 5952 representation.
    
    Rejects IPv4 addresses, CIDRs, or invalid formats.
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.IPv6Address(cleaned)
        return str(addr)
    except ValueError:
        return None


def normalize_ip(ip_str: Optional[str]) -> Tuple[Optional[str], Optional[AssetType]]:
    """Normalizes any IP address (IPv4 or IPv6) and identifies its AssetType."""
    if not ip_str or not isinstance(ip_str, str):
        return None, None
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if isinstance(addr, ipaddress.IPv4Address):
            return str(addr), AssetType.IP_ADDRESS
        elif isinstance(addr, ipaddress.IPv6Address):
            return str(addr), AssetType.IP_ADDRESS
    except ValueError:
        pass
    return None, None


def normalize_domain_name(domain: Optional[str]) -> Optional[str]:
    """Normalizes domain or subdomain into canonical lowercase FQDN.
    
    Rules:
    - Strips URL schemes (http://, https://).
    - Strips port numbers (:80, :443).
    - Strips paths, query strings, and trailing slashes.
    - Strips trailing dots (e.g. 'example.com.' -> 'example.com').
    - Strips wildcard prefixes (e.g. '*.example.com' -> 'example.com').
    - Preserves distinct subdomain boundaries (does NOT strip subdomains).
    - Rejects invalid characters and non-FQDN single labels.
    """
    if not domain or not isinstance(domain, str):
        return None

    cleaned = domain.strip().lower()

    # Strip scheme
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]

    # Strip port if present (before path)
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]

    # Strip trailing dot
    cleaned = cleaned.rstrip(".")

    # Strip wildcard prefix
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]

    # FQDN validation: must contain at least one dot, valid hostname characters
    if len(cleaned) < 3 or "." not in cleaned:
        return None

    # Disallow invalid characters
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$", cleaned):
        return None

    return cleaned


def normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    """Normalizes a hostname or machine name.
    
    Preserves exact hostname identity without merging distinct machines.
    """
    if not hostname or not isinstance(hostname, str):
        return None

    cleaned = hostname.strip().lower().rstrip(".")
    if not cleaned or len(cleaned) > 255:
        return None

    # Check for valid hostname label characters
    if re.match(r"^[a-z0-9]([a-z0-9\-_\.]{0,253}[a-z0-9])?$", cleaned):
        return cleaned
    return None


def normalize_port_protocol(port: Any, protocol: Optional[str] = None) -> Tuple[Optional[int], Optional[str]]:
    """Normalizes a network port number and transport protocol.
    
    Returns:
        (port_integer, protocol_str) e.g. (443, 'tcp')
    """
    port_val: Optional[int] = None
    if port is not None:
        try:
            p = int(port)
            if 1 <= p <= 65535:
                port_val = p
        except (ValueError, TypeError):
            pass

    proto_val: Optional[str] = None
    if protocol and isinstance(protocol, str):
        pr = protocol.strip().lower()
        if pr in ("tcp", "udp", "sctp", "icmp"):
            proto_val = pr

    if port_val is not None and proto_val is None:
        proto_val = "tcp"

    return port_val, proto_val


def normalize_service_name(service: Optional[str]) -> Optional[str]:
    """Normalizes a service or daemon name (e.g. 'HTTP', 'ssh-2.0' -> 'http', 'ssh')."""
    if not service or not isinstance(service, str):
        return None
    cleaned = service.strip().lower()
    cleaned = re.sub(r"[^a-z0-9\-_]", "", cleaned)
    return cleaned if cleaned else None


def normalize_url(url_str: Optional[str]) -> Optional[str]:
    """Normalizes a web URL to its canonical form with lowercase scheme and host."""
    if not url_str or not isinstance(url_str, str):
        return None
    try:
        parsed = urlparse(url_str.strip())
        if not parsed.scheme or not parsed.netloc:
            return None
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        # Drop default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        path = parsed.path or "/"
        # Strip trailing slash if root
        if path == "/":
            path = ""

        rebuilt = f"{scheme}://{netloc}{path}"
        if parsed.query:
            rebuilt += f"?{parsed.query}"
        return rebuilt
    except Exception:
        return None


def normalize_certificate_fingerprint(fp: Optional[str]) -> Optional[str]:
    """Normalizes a certificate SHA-256 fingerprint to canonical lowercase hex without colons."""
    if not fp or not isinstance(fp, str):
        return None
    cleaned = fp.strip().lower().replace(":", "").replace(" ", "")
    if len(cleaned) == 64 and all(c in "0123456789abcdef" for c in cleaned):
        return cleaned
    return None


def classify_and_normalize_asset(
    raw_value: str,
    explicit_type: Optional[str] = None,
) -> Tuple[Optional[str], AssetType, str]:
    """Classifies raw asset string and applies type-specific normalization.
    
    Returns:
        (canonical_value, asset_type, original_value)
    """
    original = str(raw_value).strip() if raw_value is not None else ""

    # 1. Check IP address
    norm_ip, ip_type = normalize_ip(original)
    if norm_ip:
        return norm_ip, AssetType.IP_ADDRESS, original

    # 2. Check URL
    if original.startswith("http://") or original.startswith("https://"):
        norm_u = normalize_url(original)
        if norm_u:
            return norm_u, AssetType.URL, original

    # 3. Check Domain / Subdomain
    norm_d = normalize_domain_name(original)
    if norm_d:
        # If explicit type specified SUBDOMAIN or DOMAIN, respect it
        if explicit_type and explicit_type.upper() == "SUBDOMAIN":
            return norm_d, AssetType.SUBDOMAIN, original
        # If it has more than 2 labels (e.g. portal.lab.example), classify as SUBDOMAIN
        labels = norm_d.split(".")
        atype = AssetType.SUBDOMAIN if len(labels) > 2 else AssetType.DOMAIN
        return norm_d, atype, original

    # 4. Check Certificate Fingerprint
    norm_cert = normalize_certificate_fingerprint(original)
    if norm_cert:
        return norm_cert, AssetType.CERTIFICATE, original

    # 5. Check Hostname
    norm_h = normalize_hostname(original)
    if norm_h:
        return norm_h, AssetType.HOST, original

    # Fallback to general HOST type
    return (original.lower() if original else None), AssetType.HOST, original
