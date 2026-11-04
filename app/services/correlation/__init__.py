"""FootprintIQ Correlation Package Initialization."""

from app.services.correlation.models import (
    AssetType,
    CorrelatedRelationship,
    EvidenceVerificationState,
    FindingLifecycleState,
    NormalizedAsset,
    RelationshipStrength,
)
from app.services.correlation.normalizer import (
    classify_and_normalize_asset,
    normalize_certificate_fingerprint,
    normalize_domain_name,
    normalize_hostname,
    normalize_ip,
    normalize_ipv4,
    normalize_ipv6,
    normalize_port_protocol,
    normalize_service_name,
    normalize_url,
)
from app.services.correlation.rules import (
    CorrelationRule,
    DNSHostResolutionRule,
    EvidenceAssetLinkRule,
    HostGeneralVulnerabilityRule,
    HostPortVulnerabilityMatchRule,
    ServiceBannerMatchRule,
)
from app.services.correlation.deduplicator import (
    VulnerabilityLifecycleTracker,
    compute_vulnerability_dedup_key,
)
from app.services.correlation.evidence_verifier import EvidenceVerifier
from app.services.correlation.engine import CorrelationEngine

__all__ = [
    "AssetType",
    "CorrelatedRelationship",
    "EvidenceVerificationState",
    "FindingLifecycleState",
    "NormalizedAsset",
    "RelationshipStrength",
    "classify_and_normalize_asset",
    "normalize_certificate_fingerprint",
    "normalize_domain_name",
    "normalize_hostname",
    "normalize_ip",
    "normalize_ipv4",
    "normalize_ipv6",
    "normalize_port_protocol",
    "normalize_service_name",
    "normalize_url",
    "CorrelationRule",
    "DNSHostResolutionRule",
    "EvidenceAssetLinkRule",
    "HostGeneralVulnerabilityRule",
    "HostPortVulnerabilityMatchRule",
    "ServiceBannerMatchRule",
    "VulnerabilityLifecycleTracker",
    "compute_vulnerability_dedup_key",
    "EvidenceVerifier",
    "CorrelationEngine",
]

