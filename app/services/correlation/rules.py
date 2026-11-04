"""Phase C & D — Deterministic Correlation Rules and Confidence Provenance."""

from typing import Any, Dict, List, Optional, Tuple

from app.services.correlation.models import RelationshipStrength


class CorrelationRule:
    """Base class for versioned deterministic correlation rules."""
    rule_id: str
    rule_version: str = "1.0.0"
    description: str

    def evaluate(self, *args, **kwargs) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class HostPortVulnerabilityMatchRule(CorrelationRule):
    """Rule 1: Confirms vulnerability reported by Greenbone on open port detected by Nmap.
    
    Attributes evaluated:
    - Host IP match
    - Port number match
    - Transport protocol match
    - Nmap port state is 'open'
    """
    rule_id = "RULE-HOST-PORT-VULN-001"
    rule_version = "1.0.0"
    description = "Exact match between Nmap confirmed open port and Greenbone vulnerability finding."

    def evaluate(
        self,
        host_ip: str,
        nmap_port: int,
        nmap_protocol: str,
        nmap_state: str,
        vuln_port: Optional[int],
        vuln_protocol: Optional[str],
    ) -> Optional[Tuple[RelationshipStrength, float, List[str], str]]:
        if vuln_port is None or nmap_port != vuln_port:
            return None

        # Compare protocols (normalize tcp/udp)
        proto_a = (nmap_protocol or "tcp").lower()
        proto_b = (vuln_protocol or "tcp").lower()
        if proto_a != proto_b:
            return None

        if (nmap_state or "open").lower() == "open":
            matched_attrs = ["host_ip", "port_number", "protocol", "port_state_open"]
            summary = f"Confirmed open port {nmap_port}/{proto_a} on {host_ip} matches vulnerability finding."
            return (RelationshipStrength.CONFIRMED_MATCH, 1.0, matched_attrs, summary)

        # Filtered or closed port with vuln finding
        matched_attrs = ["host_ip", "port_number", "protocol", f"port_state_{nmap_state}"]
        summary = f"Port {nmap_port}/{proto_a} on {host_ip} matches finding but port state is {nmap_state}."
        return (RelationshipStrength.POSSIBLE_MATCH, 0.60, matched_attrs, summary)


class ServiceBannerMatchRule(CorrelationRule):
    """Rule 2: Corroborates service or application identity between Nmap and Greenbone."""
    rule_id = "RULE-SERVICE-BANNER-002"
    rule_version = "1.0.0"
    description = "Service and product identification match across active scanning and vulnerability assessment."

    def evaluate(
        self,
        nmap_service: Optional[str],
        nmap_product: Optional[str],
        vuln_name: str,
        vuln_description: Optional[str],
    ) -> Optional[Tuple[RelationshipStrength, float, List[str], str]]:
        if not nmap_service and not nmap_product:
            return None

        product_clean = (nmap_product or "").strip().lower()
        service_clean = (nmap_service or "").strip().lower()
        vuln_text = f"{vuln_name} {vuln_description or ''}".lower()

        matched_attrs = []
        if product_clean and len(product_clean) >= 3 and product_clean in vuln_text:
            matched_attrs.extend(["host_ip", "port_number", "service_product"])
            summary = f"Nmap product fingerprint '{nmap_product}' matches vulnerability advisory text."
            return (RelationshipStrength.CONFIRMED_MATCH, 0.95, matched_attrs, summary)

        if service_clean and len(service_clean) >= 3 and service_clean in vuln_text:
            matched_attrs.extend(["host_ip", "port_number", "service_name"])
            summary = f"Nmap service name '{nmap_service}' matches vulnerability advisory text."
            return (RelationshipStrength.STRONG_MATCH, 0.85, matched_attrs, summary)

        return None


class DNSHostResolutionRule(CorrelationRule):
    """Rule 3: Associates passive OSINT domain/subdomain entities to scanned network assets."""
    rule_id = "RULE-DNS-RESOLVES-003"
    rule_version = "1.0.0"
    description = "Passive reconnaissance hostname or domain resolves to scanned host IP address."

    def evaluate(
        self,
        domain_name: str,
        resolved_ips: List[str],
        scanned_ip: str,
    ) -> Optional[Tuple[RelationshipStrength, float, List[str], str]]:
        norm_scanned = scanned_ip.strip()
        matched_ips = [ip.strip() for ip in resolved_ips if ip.strip() == norm_scanned]
        if matched_ips:
            matched_attrs = ["domain_name", "resolved_ip_address"]
            summary = f"Passive entity '{domain_name}' resolves to active host '{norm_scanned}'."
            return (RelationshipStrength.STRONG_MATCH, 0.85, matched_attrs, summary)
        return None


class HostGeneralVulnerabilityRule(CorrelationRule):
    """Rule 4: Relates general or host-level vulnerability (no specific port) to host asset."""
    rule_id = "RULE-HOST-GENERAL-VULN-004"
    rule_version = "1.0.0"
    description = "General or unmapped host-level vulnerability associated with target asset."

    def evaluate(
        self,
        host_ip: str,
        vuln_port: Optional[int],
    ) -> Optional[Tuple[RelationshipStrength, float, List[str], str]]:
        if vuln_port is None:
            matched_attrs = ["host_ip", "host_level_unspecified_port"]
            summary = f"General host-level vulnerability applies to {host_ip} without specific port binding."
            return (RelationshipStrength.POSSIBLE_MATCH, 0.50, matched_attrs, summary)
        return None


class EvidenceAssetLinkRule(CorrelationRule):
    """Rule 5: Cryptographically verified forensic evidence linked to target asset."""
    rule_id = "RULE-EVIDENCE-ASSET-005"
    rule_version = "1.0.0"
    description = "Forensic evidence collection record directly targets investigation asset."

    def evaluate(
        self,
        asset_id: str,
        evidence_target: str,
        is_hash_verified: bool,
    ) -> Optional[Tuple[RelationshipStrength, float, List[str], str]]:
        if asset_id.strip().lower() == evidence_target.strip().lower():
            if is_hash_verified:
                matched_attrs = ["asset_identifier", "evidence_target", "sha256_hash_verified"]
                summary = f"Verified raw evidence object directly supports asset {asset_id}."
                return (RelationshipStrength.CONFIRMED_MATCH, 1.0, matched_attrs, summary)
            else:
                matched_attrs = ["asset_identifier", "evidence_target"]
                summary = f"Raw evidence references asset {asset_id} (hash unverified or pending)."
                return (RelationshipStrength.STRONG_MATCH, 0.80, matched_attrs, summary)
        return None

