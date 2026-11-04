"""Domain layer package for FootprintIQ Clean Architecture.

Pure domain models, entities, value objects, exceptions, and domain events.
Zero framework (FastAPI/SQLAlchemy) dependencies.
"""

from app.domain.common import (
    Entity,
    AggregateRoot,
    utc_now,
    ValueObject,
    DomainName,
    IPAddress,
    CIDRBlock,
    SHA256Checksum,
    DomainException,
    EntityNotFoundException,
    InvariantViolationException,
    UnauthorizedOperationException,
    InvalidStateTransitionException,
    DomainEvent,
    DomainEventDispatcher,
    domain_event_dispatcher,
)
from app.domain.identity import UserRole, AccountStatus, Username, EmailAddress, User, UserSession
from app.domain.authorization import TargetType, OperationType, TargetAuthorization
from app.domain.investigations import InvestigationState, InvestigationScope, Investigation, VALID_TRANSITIONS
from app.domain.assets import AssetType, AssetCriticality, Asset, HostAsset, ServiceAsset
from app.domain.reconnaissance import ReconType, CollectionJobStatus, CollectionJob, ReconEntity, DNSHarvest, CertificateRecord
from app.domain.evidence import EvidenceStorageBackend, EvidenceCollectionStatus, EvidenceItem
from app.domain.findings import FindingSeverity, ScanFindingHost, ScanFindingPort, SecurityFinding
from app.domain.vulnerabilities import VulnerabilitySeverity, CVSSScore, VulnerabilityFinding, VulnerabilityScanJob
from app.domain.correlation import NodeType, RelationshipType, GraphNode, GraphEdge, CorrelatedGraph
from app.domain.workflows import JobStatus, WorkflowStage, WorkflowJob
from app.domain.reporting import ReportFormat, ReportMetadata, InvestigationDossier
from app.domain.audit import AuditAction, SecurityAuditEvent

__all__ = [
    # Common
    "Entity",
    "AggregateRoot",
    "utc_now",
    "ValueObject",
    "DomainName",
    "IPAddress",
    "CIDRBlock",
    "SHA256Checksum",
    "DomainException",
    "EntityNotFoundException",
    "InvariantViolationException",
    "UnauthorizedOperationException",
    "InvalidStateTransitionException",
    "DomainEvent",
    "DomainEventDispatcher",
    "domain_event_dispatcher",
    # Identity
    "UserRole",
    "AccountStatus",
    "Username",
    "EmailAddress",
    "User",
    "UserSession",
    # Authorization
    "TargetType",
    "OperationType",
    "TargetAuthorization",
    # Investigations
    "InvestigationState",
    "InvestigationScope",
    "Investigation",
    "VALID_TRANSITIONS",
    # Assets
    "AssetType",
    "AssetCriticality",
    "Asset",
    "HostAsset",
    "ServiceAsset",
    # Reconnaissance
    "ReconType",
    "CollectionJobStatus",
    "CollectionJob",
    "ReconEntity",
    "DNSHarvest",
    "CertificateRecord",
    # Evidence
    "EvidenceStorageBackend",
    "EvidenceCollectionStatus",
    "EvidenceItem",
    # Findings
    "FindingSeverity",
    "ScanFindingHost",
    "ScanFindingPort",
    "SecurityFinding",
    # Vulnerabilities
    "VulnerabilitySeverity",
    "CVSSScore",
    "VulnerabilityFinding",
    "VulnerabilityScanJob",
    # Correlation
    "NodeType",
    "RelationshipType",
    "GraphNode",
    "GraphEdge",
    "CorrelatedGraph",
    # Workflows
    "JobStatus",
    "WorkflowStage",
    "WorkflowJob",
    # Reporting
    "ReportFormat",
    "ReportMetadata",
    "InvestigationDossier",
    # Audit
    "AuditAction",
    "SecurityAuditEvent",
]

