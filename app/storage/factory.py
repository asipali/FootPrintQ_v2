"""Storage adapter factory and lifecycle manager."""

from typing import Optional
from app.config import Settings, get_settings
from app.storage.base import BaseStorageAdapter
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.seaweedfs import SeaweedFSStorageAdapter

_adapter_cache = {}


def get_storage_adapter(
    settings: Optional[Settings] = None,
    backend_override: Optional[str] = None,
    force_new: bool = False,
    **kwargs,
) -> BaseStorageAdapter:
    """Returns a storage adapter instance according to application configuration or override.
    
    Args:
        settings: Application Settings object (defaults to get_settings()).
        backend_override: Force 'filesystem' or 'seaweedfs' (e.g. for testing/migration).
        force_new: Bypass singleton cache and create a fresh adapter instance.
        **kwargs: Extra parameters passed to the adapter constructor.
        
    Returns:
        Configured BaseStorageAdapter implementation.
    """
    app_settings = settings or get_settings()
    backend = (backend_override or app_settings.STORAGE_BACKEND).strip().lower()

    cache_key = f"{backend}_{app_settings.EVIDENCE_STORAGE_PATH if backend == 'filesystem' else app_settings.SEAWEEDFS_FILER_URL}"

    if not force_new and cache_key in _adapter_cache:
        return _adapter_cache[cache_key]

    if backend == "filesystem":
        adapter = LocalFilesystemStorageAdapter(
            base_path=kwargs.get("base_path") or app_settings.EVIDENCE_STORAGE_PATH
        )
    elif backend == "seaweedfs":
        adapter = SeaweedFSStorageAdapter(
            filer_url=kwargs.get("filer_url") or app_settings.SEAWEEDFS_FILER_URL,
            collection=kwargs.get("collection") or app_settings.SEAWEEDFS_COLLECTION,
            timeout=kwargs.get("timeout") or app_settings.SEAWEEDFS_TIMEOUT_SECONDS,
            max_retries=kwargs.get("max_retries") or app_settings.SEAWEEDFS_MAX_RETRIES,
            auth_token=kwargs.get("auth_token") or app_settings.SEAWEEDFS_AUTH_TOKEN,
            client=kwargs.get("client"),
        )
    else:
        raise ValueError(f"Unsupported storage backend: '{backend}'. Must be 'filesystem' or 'seaweedfs'.")

    if not force_new:
        _adapter_cache[cache_key] = adapter

    return adapter


def close_storage_adapters() -> None:
    """Closes all cached storage adapters and releases network client pools."""
    global _adapter_cache
    for adapter in _adapter_cache.values():
        try:
            adapter.close()
        except Exception:
            pass
    _adapter_cache.clear()

