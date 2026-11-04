"""SeaweedFS Filer HTTP REST API implementation of BaseStorageAdapter."""

from datetime import datetime, timezone
import email.utils
from io import BytesIO
import time
from typing import BinaryIO, Dict, Generator, Optional, Tuple, Union
import urllib.parse
import httpx

from app.config import get_settings
from app.logging_config import get_logger
from app.storage.base import (
    BaseStorageAdapter,
    StorageConnectionError,
    StorageHealthStatus,
    StorageIntegrityError,
    StorageKeyExistsError,
    StorageObjectMetadata,
    StorageObjectNotFoundError,
    StoragePayloadTooLargeError,
    StorageSecurityError,
    compute_sha256,
    validate_and_normalize_key,
    MAX_EVIDENCE_SIZE_BYTES,
)

logger = get_logger("footprintiq.storage.seaweedfs")


class SeaweedFSStorageAdapter(BaseStorageAdapter):
    """Forensic storage adapter backed by SeaweedFS Filer HTTP REST API.
    
    Interacts directly with the SeaweedFS Filer service over HTTP without external
    SDK dependencies, utilizing native hierarchical paths, streaming transfers,
    and cryptographic digest verification.
    """

    def __init__(
        self,
        filer_url: Optional[str] = None,
        collection: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        auth_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ):
        settings = get_settings()
        self.filer_url = (filer_url or settings.SEAWEEDFS_FILER_URL).rstrip("/")
        self.collection = (collection or settings.SEAWEEDFS_COLLECTION).strip("/")
        self.timeout = timeout if timeout is not None else settings.SEAWEEDFS_TIMEOUT_SECONDS
        self.max_retries = max_retries if max_retries is not None else settings.SEAWEEDFS_MAX_RETRIES
        self.auth_token = auth_token or settings.SEAWEEDFS_AUTH_TOKEN

        # Shared HTTP client with connection pooling and timeouts
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            headers = {"User-Agent": f"FootprintIQ-Storage/{settings.APP_VERSION}"}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout, connect=5.0),
                headers=headers,
                follow_redirects=True,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            )
            self._owns_client = True

    @property
    def backend_name(self) -> str:
        return "seaweedfs"

    def __repr__(self) -> str:
        return f"<SeaweedFSStorageAdapter filer_url='{self.filer_url}' collection='{self.collection}'>"

    def __str__(self) -> str:
        return f"SeaweedFSStorageAdapter(filer_url='{self.filer_url}', collection='{self.collection}')"

    def _build_url(self, key: str) -> str:
        """Constructs safe, fully-qualified URL for a given storage key in SeaweedFS Filer."""
        safe_key = validate_and_normalize_key(key)
        # Construct path: /{collection}/{safe_key} without duplicating collection prefix
        key_parts = [p for p in safe_key.split("/") if p]
        if self.collection:
            if key_parts and key_parts[0] == self.collection:
                path_segments = key_parts
            else:
                path_segments = [self.collection] + key_parts
        else:
            path_segments = key_parts
        encoded_path = "/".join(urllib.parse.quote(seg, safe="") for seg in path_segments if seg)
        return f"{self.filer_url}/{encoded_path}"

    def _execute_with_retry(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Executes HTTP request with bounded retry and exponential backoff for transient errors."""
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.request(method, url, **kwargs)
                if response.status_code in {502, 503, 504} and attempt < self.max_retries:
                    backoff = 0.25 * (2 ** (attempt - 1))
                    logger.warning(
                        "SeaweedFS transient status %d on %s %s (attempt %d/%d). Retrying in %.2fs",
                        response.status_code, method, url, attempt, self.max_retries, backoff,
                    )
                    time.sleep(backoff)
                    continue
                return response
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    backoff = 0.25 * (2 ** (attempt - 1))
                    logger.warning(
                        "SeaweedFS network failure on %s %s (attempt %d/%d): %s. Retrying in %.2fs",
                        method, url, attempt, self.max_retries, str(exc), backoff,
                    )
                    time.sleep(backoff)
                else:
                    break

        raise StorageConnectionError(
            f"SeaweedFS Filer unavailable after {self.max_retries} attempts: {str(last_exc)}"
        ) from last_exc

    def put_object(
        self,
        key: str,
        data: Union[bytes, BinaryIO, str],
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageObjectMetadata:
        url = self._build_url(key)

        # 1. Encode payload to raw bytes
        if isinstance(data, str):
            payload_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            payload_bytes = data
        elif hasattr(data, "read"):
            payload_bytes = data.read()
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8")
        else:
            payload_bytes = str(data).encode("utf-8")

        content_hash = compute_sha256(payload_bytes)
        size_bytes = len(payload_bytes)

        if size_bytes > MAX_EVIDENCE_SIZE_BYTES:
            raise StoragePayloadTooLargeError(
                f"Payload size ({size_bytes} bytes) exceeds maximum limit of {MAX_EVIDENCE_SIZE_BYTES} bytes."
            )

        # 2. Immutability and Idempotency check: Verify object does not already exist with different content
        if self.object_exists(key):
            try:
                existing_meta = self.get_object_metadata(key)
                if existing_meta.content_hash.lower() == content_hash.lower():
                    return existing_meta
            except Exception:
                pass
            raise StorageKeyExistsError(f"Evidence storage key already exists in SeaweedFS: '{key}'")

        # 3. Prepare headers and custom metadata
        headers = {
            "Content-Type": content_type,
            "X-Content-SHA256": content_hash,
            "X-Evidence-Key": key,
        }
        if metadata:
            for mk, mv in metadata.items():
                safe_k = "".join(c for c in mk if c.isalnum() or c in ("-", "_"))
                headers[f"Seaweed-Meta-{safe_k}"] = str(mv)

        # 4. Upload payload via HTTP PUT (Filer stores raw body at path)
        try:
            response = self._execute_with_retry("PUT", url, content=payload_bytes, headers=headers)
        except Exception as e:
            raise StorageConnectionError(f"Failed to persist object to SeaweedFS at '{key}': {str(e)}") from e

        if response.status_code not in {200, 201, 204}:
            raise StorageConnectionError(
                f"SeaweedFS PUT failed with HTTP {response.status_code}: {response.text[:256]}"
            )

        # 5. Read-back integrity verification: ensure payload stored matches expected hash
        try:
            verified_bytes, _ = self.get_object(key)
            readback_hash = compute_sha256(verified_bytes)
            if readback_hash.lower() != content_hash.lower():
                # Corrupted upload detected: perform immediate compensation deletion
                self.delete_object(key)
                raise StorageIntegrityError(
                    f"Uploaded object integrity mismatch for '{key}': sent {content_hash}, received {readback_hash}"
                )
        except StorageObjectNotFoundError as not_found_exc:
            raise StorageConnectionError(
                f"Uploaded object could not be read back for verification at '{key}': {str(not_found_exc)}"
            ) from not_found_exc

        created_at = datetime.now(timezone.utc)
        return StorageObjectMetadata(
            key=key,
            size_bytes=size_bytes,
            content_hash=content_hash,
            content_type=content_type,
            backend=self.backend_name,
            created_at=created_at,
            custom_metadata=metadata or {},
        )

    def get_object(self, key: str) -> Tuple[bytes, StorageObjectMetadata]:
        url = self._build_url(key)
        try:
            response = self._execute_with_retry("GET", url)
        except Exception as e:
            raise StorageConnectionError(f"Failed to retrieve object from SeaweedFS at '{key}': {str(e)}") from e

        if response.status_code == 404:
            raise StorageObjectNotFoundError(f"Storage object '{key}' not found in SeaweedFS.")

        if response.status_code != 200:
            raise StorageConnectionError(
                f"SeaweedFS GET failed with HTTP {response.status_code}: {response.text[:256]}"
            )

        payload_bytes = response.content
        computed_hash = compute_sha256(payload_bytes)

        # Parse date from response headers if available
        created_at = None
        last_modified = response.headers.get("Last-Modified")
        if last_modified:
            try:
                created_at = email.utils.parsedate_to_datetime(last_modified)
            except Exception:
                created_at = datetime.now(timezone.utc)

        # Extract custom metadata from headers
        custom_metadata = {}
        for h_name, h_val in response.headers.items():
            if h_name.lower().startswith("seaweed-meta-"):
                meta_k = h_name[len("seaweed-meta-"):]
                custom_metadata[meta_k] = h_val

        meta = StorageObjectMetadata(
            key=key,
            size_bytes=len(payload_bytes),
            content_hash=computed_hash,
            content_type=response.headers.get("Content-Type", "application/octet-stream"),
            backend=self.backend_name,
            created_at=created_at,
            custom_metadata=custom_metadata,
        )
        return payload_bytes, meta

    def get_object_stream(self, key: str, chunk_size: int = 65536) -> Generator[bytes, None, None]:
        url = self._build_url(key)
        try:
            with self._client.stream("GET", url) as response:
                if response.status_code == 404:
                    raise StorageObjectNotFoundError(f"Storage object '{key}' not found in SeaweedFS.")
                if response.status_code != 200:
                    raise StorageConnectionError(
                        f"SeaweedFS stream failed with HTTP {response.status_code}"
                    )
                for chunk in response.iter_bytes(chunk_size):
                    if chunk:
                        yield chunk
        except (StorageObjectNotFoundError, StorageConnectionError):
            raise
        except Exception as e:
            raise StorageConnectionError(f"SeaweedFS streaming interrupted for '{key}': {str(e)}") from e

    def delete_object(self, key: str) -> bool:
        url = self._build_url(key)
        try:
            response = self._execute_with_retry("DELETE", url)
        except Exception as e:
            raise StorageConnectionError(f"Failed to delete object from SeaweedFS at '{key}': {str(e)}") from e

        if response.status_code in {200, 202, 204}:
            return True
        if response.status_code == 404:
            return False

        raise StorageConnectionError(
            f"SeaweedFS DELETE failed with HTTP {response.status_code}: {response.text[:256]}"
        )

    def object_exists(self, key: str) -> bool:
        try:
            url = self._build_url(key)
            response = self._execute_with_retry("HEAD", url)
            return response.status_code == 200
        except (StorageSecurityError, ValueError):
            return False
        except Exception:
            return False

    def get_object_metadata(self, key: str) -> StorageObjectMetadata:
        url = self._build_url(key)
        try:
            response = self._execute_with_retry("HEAD", url)
        except Exception as e:
            raise StorageConnectionError(f"Failed to fetch metadata from SeaweedFS at '{key}': {str(e)}") from e

        if response.status_code == 404:
            raise StorageObjectNotFoundError(f"Storage object '{key}' not found in SeaweedFS.")

        if response.status_code != 200:
            raise StorageConnectionError(
                f"SeaweedFS HEAD failed with HTTP {response.status_code}"
            )

        content_length = int(response.headers.get("Content-Length", 0))
        content_type = response.headers.get("Content-Type", "application/octet-stream")
        content_hash = response.headers.get("X-Content-SHA256", "")

        created_at = None
        last_modified = response.headers.get("Last-Modified")
        if last_modified:
            try:
                created_at = email.utils.parsedate_to_datetime(last_modified)
            except Exception:
                created_at = datetime.now(timezone.utc)

        custom_metadata = {}
        for h_name, h_val in response.headers.items():
            if h_name.lower().startswith("seaweed-meta-"):
                meta_k = h_name[len("seaweed-meta-"):]
                custom_metadata[meta_k] = h_val

        return StorageObjectMetadata(
            key=key,
            size_bytes=content_length,
            content_hash=content_hash,
            content_type=content_type,
            backend=self.backend_name,
            created_at=created_at,
            custom_metadata=custom_metadata,
        )

    def verify_object_integrity(self, key: str, expected_hash: str) -> bool:
        payload_bytes, _ = self.get_object(key)
        computed_hash = compute_sha256(payload_bytes)

        if computed_hash.lower() != expected_hash.lower():
            raise StorageIntegrityError(
                f"Integrity check failed for '{key}' on SeaweedFS: expected {expected_hash}, computed {computed_hash}"
            )
        return True

    def health_check(self) -> StorageHealthStatus:
        start_time = time.perf_counter()
        try:
            # Query filer root endpoint with ?metadata=true or basic GET /
            response = self._client.get(f"{self.filer_url}/", timeout=httpx.Timeout(3.0))
            latency = (time.perf_counter() - start_time) * 1000.0

            if response.status_code in {200, 404}:
                # 200 = Filer listing; 404 = Root empty, but Filer is active and responding
                return StorageHealthStatus(
                    is_healthy=True,
                    backend=self.backend_name,
                    details=f"SeaweedFS Filer responsive at {self.filer_url} (HTTP {response.status_code}).",
                    latency_ms=round(latency, 2),
                )
            return StorageHealthStatus(
                is_healthy=False,
                backend=self.backend_name,
                details=f"SeaweedFS Filer returned unexpected status {response.status_code}.",
                latency_ms=round(latency, 2),
            )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return StorageHealthStatus(
                is_healthy=False,
                backend=self.backend_name,
                details=f"SeaweedFS Filer unreachable at {self.filer_url}: {str(e)}",
                latency_ms=round(latency, 2),
            )

    def close(self) -> None:
        """Closes the underlying HTTP client if owned by this adapter instance."""
        if self._owns_client and hasattr(self, "_client") and self._client is not None:
            try:
                self._client.close()
            except Exception as e:
                logger.warning("Error closing SeaweedFS HTTP client: %s", e)

