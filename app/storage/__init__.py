"""Forensic storage package exposing storage adapters, metadata, and factory."""

from app.storage.base import (
    BaseStorageAdapter,
    StorageConnectionError,
    StorageError,
    StorageHealthStatus,
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectMetadata,
    StorageObjectNotFoundError,
    StorageSecurityError,
    compute_sha256,
    validate_and_normalize_key,
)
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.seaweedfs import SeaweedFSStorageAdapter
from app.storage.factory import get_storage_adapter, close_storage_adapters

__all__ = [
    "BaseStorageAdapter",
    "StorageObjectMetadata",
    "StorageHealthStatus",
    "StorageError",
    "StorageKeyExistsError",
    "StorageObjectNotFoundError",
    "StorageIntegrityError",
    "StorageConnectionError",
    "StorageSecurityError",
    "compute_sha256",
    "validate_and_normalize_key",
    "LocalFilesystemStorageAdapter",
    "SeaweedFSStorageAdapter",
    "get_storage_adapter",
    "close_storage_adapters",
]

