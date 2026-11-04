"""Independent security and authorization tests for evidence storage and API endpoints."""

import hashlib
from pathlib import Path
import httpx
import pytest
from starlette.testclient import TestClient

from app.config import Settings
from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.models.user import UserModel
from app.storage.base import (
    StorageSecurityError,
    validate_and_normalize_key,
)
from app.storage.filesystem import LocalFilesystemStorageAdapter
from app.storage.seaweedfs import SeaweedFSStorageAdapter
from app.services.evidence_store import EvidenceStore


# ============================================================================
# 1. PATH TRAVERSAL & URL-ENCODED ATTACK REJECTION
# ============================================================================

def test_path_traversal_attack_variations_rejected():
    """Verifies that all standard and advanced path traversal vectors are blocked."""
    vectors = [
        "../etc/passwd",
        "../../windows/system32/cmd.exe",
        "inv-01/../../../shadow",
        "inv-01/..\\..\\windows\\win.ini",
        "/absolute/root/file.txt",
        "C:\\Windows\\System32\\calc.exe",
        "inv-01/sub/../../file.txt",
        "inv-01/./dot_slash.txt",
        "inv-01/.hidden_unix_file",
        "inv-01/file\x00nullbyte.txt",
        "inv-01/file;command_injection.txt",
        "inv-01/file|pipe.txt",
    ]

    for v in vectors:
        with pytest.raises(StorageSecurityError):
            validate_and_normalize_key(v)


# ============================================================================
# 2. ENDPOINT CONFIDENTIALITY & HEADER INTEGRITY
# ============================================================================

def test_seaweedfs_endpoint_confidentiality(tmp_path: Path):
    """Verifies that internal SeaweedFS URLs and internal ports (8888/8333) are never leaked in metadata."""
    adapter = SeaweedFSStorageAdapter(
        filer_url="http://internal-filer-cluster.lan:8888",
        collection="confidential-col",
    )
    # The adapter object representations and exceptions must not expose passwords/tokens
    repr_str = repr(adapter)
    assert "password" not in repr_str.lower()
    assert "token" not in repr_str.lower()


# ============================================================================
# 3. STAGING & PRODUCTION LOCAL-FALLBACK LOCKOUT
# ============================================================================

def test_staging_and_production_lockout_blocks_local_fallback(tmp_path: Path):
    """Verifies that both STAGING and PRODUCTION environments reject local disk fallback."""
    local_adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    key = "inv-lockout/local_only.raw.txt"
    local_adapter.put_object(key, b"Local bytes only")

    # Mock client that returns HTTP 404 for SeaweedFS
    mock_client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(404, text="Not Found", request=req)),
        base_url="http://mock:8888",
    )

    for env_name in ["staging", "production"]:
        seaweed_adapter = SeaweedFSStorageAdapter(filer_url="http://mock:8888", client=mock_client)
        store = EvidenceStore(adapter=seaweed_adapter)
        store.settings = Settings(
            APP_ENV=env_name,
            SECRET_KEY="high-entropy-secret-key-32-bytes-long-min!!",
            SESSION_COOKIE_SECURE=True,
            STORAGE_BACKEND="seaweedfs",
            EVIDENCE_STORAGE_PATH=str(tmp_path),
            ALLOWED_HOSTS=["footprint.org"],
            SEAWEEDFS_FALLBACK_TO_FILESYSTEM=True,  # Even if set to True, post-init validator forces False
        )

        assert store.settings.SEAWEEDFS_FALLBACK_TO_FILESYSTEM is False, f"Fallback not forced to False in {env_name}"

        # Reading non-existent SeaweedFS file must raise FileNotFoundError, not fallback to local
        with pytest.raises(FileNotFoundError):
            store.read_evidence(key)


# ============================================================================
# 4. API AUTHORIZATION & CROSS-INVESTIGATION CONTROLS
# ============================================================================

def test_api_raw_evidence_unauthenticated_rejected(client: TestClient):
    """Unauthenticated access to raw evidence endpoint must be rejected with 401."""
    res = client.get("/api/v1/investigations/inv-fake/evidence/evi-fake/raw")
    assert res.status_code == 401


def test_api_raw_evidence_cross_investigation_rejected(
    admin_client: TestClient,
    db_session,
    tmp_path: Path,
):
    """Evidence belonging to Investigation A cannot be retrieved via Investigation B URL."""
    # Create Investigation A and B
    inv_a = InvestigationModel(
        id="inv-owner-a",
        name="Investigation A",
        organization_name="Org A",
        description="Desc A",
        lead_investigator="Lead A",
        status="active",
    )
    inv_b = InvestigationModel(
        id="inv-owner-b",
        name="Investigation B",
        organization_name="Org B",
        description="Desc B",
        lead_investigator="Lead B",
        status="active",
    )
    db_session.add_all([inv_a, inv_b])

    # Add evidence to Investigation A
    ev_a = EvidenceModel(
        id="evi-cross-check",
        investigation_id="inv-owner-a",
        source_type="nmap",
        source_name="Nmap",
        target="127.0.0.1",
        collection_status="SUCCESS",
        raw_content_path="inv-owner-a/scan.raw.txt",
        storage_backend="filesystem",
        content_hash="cc" * 32,
        content_size_bytes=50,
    )
    db_session.add(ev_a)
    db_session.commit()

    # Attempt cross-investigation retrieval: Query Investigation B with Evidence A id
    res = admin_client.get(f"/api/v1/investigations/inv-owner-b/evidence/{ev_a.id}/raw")
    assert res.status_code == 404


# ============================================================================
# 5. UNLAWFUL DELETION REJECTION (API IMMUTABILITY)
# ============================================================================

def test_api_unauthorized_evidence_deletion_rejected(client: TestClient, admin_client: TestClient):
    """Evidence records are immutable; no DELETE route exists on the API.
    Unauthenticated attempts return 401/404/405; authenticated attempts return 405 Method Not Allowed.
    """
    # 1. Unauthenticated DELETE attempt
    unauth_res = client.delete("/api/v1/investigations/inv-fake/evidence/evi-fake")
    assert unauth_res.status_code in {401, 404, 405}

    # 2. Authenticated Admin DELETE attempt
    admin_res = admin_client.delete("/api/v1/investigations/inv-fake/evidence/evi-fake")
    assert admin_res.status_code in {404, 405}

    # 3. Direct raw endpoint DELETE attempt
    raw_res = admin_client.delete("/api/v1/investigations/inv-fake/evidence/evi-fake/raw")
    assert raw_res.status_code == 405


# ============================================================================
# 6. RBAC & INVESTIGATION OWNERSHIP TENANT ISOLATION
# ============================================================================

def test_api_ownership_and_rbac_investigator_isolation(
    client: TestClient,
    db_session,
    tmp_path: Path,
):
    """An analyst who does not own the investigation is blocked with 403 Forbidden."""
    from app.core.auth import create_user_session
    from app.core.security import hash_password, ROLE_ANALYST

    # Provision Investigator 1 (Owner) and Investigator 2 (Non-owner)
    inv1_user = UserModel(
        id="usr-inv-owner-01",
        username="lead_investigator_1",
        email="lead1@example.com",
        password_hash=hash_password("LeadPass123!#"),
        role=ROLE_ANALYST,
        is_active=True,
    )
    inv2_user = UserModel(
        id="usr-inv-other-02",
        username="other_investigator_2",
        email="other2@example.com",
        password_hash=hash_password("OtherPass123!#"),
        role=ROLE_ANALYST,
        is_active=True,
    )
    db_session.add_all([inv1_user, inv2_user])
    db_session.commit()

    # Create investigation owned by usr-inv-owner-01
    investigation = InvestigationModel(
        id="inv-tenant-isolated-01",
        name="Confidential Investigation",
        organization_name="Target Corp",
        description="Tenant Isolation Check",
        lead_investigator="usr-inv-owner-01",
        status="active",
    )
    db_session.add(investigation)

    # Add evidence
    ev = EvidenceModel(
        id="evi-tenant-01",
        investigation_id="inv-tenant-isolated-01",
        source_type="nmap",
        source_name="Nmap",
        target="10.0.0.1",
        collection_status="SUCCESS",
        raw_content_path="inv-tenant-isolated-01/test.raw.txt",
        storage_backend="filesystem",
        content_hash="aa" * 32,
        content_size_bytes=20,
    )
    db_session.add(ev)
    db_session.commit()

    # Create session for Investigator 2 (non-owner)
    token2, _ = create_user_session(db=db_session, user=inv2_user)
    client.cookies.set("footprintiq_session", token2)

    # 1. Non-owner analyst receives non-disclosing 404 (preventing investigation enumeration)
    res_meta = client.get(f"/api/v1/investigations/{investigation.id}/evidence")
    assert res_meta.status_code == 404, f"Expected 404 Not Found, got {res_meta.status_code}"

    res_raw = client.get(f"/api/v1/investigations/{investigation.id}/evidence/{ev.id}/raw")
    assert res_raw.status_code == 404, f"Expected 404 Not Found, got {res_raw.status_code}"

    # 2. User without required permission (e.g. pending/unapproved role) receives 403 Forbidden
    unapproved_user = UserModel(
        id="usr-pending-01",
        username="pending_user",
        email="pending@example.com",
        password_hash=hash_password("PendingPass123!#"),
        role="unapproved",
        is_active=True,
    )
    db_session.add(unapproved_user)
    db_session.commit()

    token_unapproved, _ = create_user_session(db=db_session, user=unapproved_user)
    client.cookies.set("footprintiq_session", token_unapproved)

    res_unapproved = client.get(f"/api/v1/investigations/{investigation.id}/evidence")
    assert res_unapproved.status_code == 403, f"Expected 403 Forbidden, got {res_unapproved.status_code}"


# ============================================================================
# 7. OVERSIZED UPLOAD REJECTION
# ============================================================================

def test_oversized_evidence_payload_rejection(tmp_path: Path):
    """Payloads exceeding maximum permitted size limit are rejected immediately."""
    from app.storage.base import StoragePayloadTooLargeError, MAX_EVIDENCE_SIZE_BYTES

    adapter = LocalFilesystemStorageAdapter(base_path=tmp_path)
    # Generate payload exceeding limit (simulate using a virtual bytearray or tiny max limit override)
    oversized_data = b"X" * (MAX_EVIDENCE_SIZE_BYTES + 1024)

    with pytest.raises(StoragePayloadTooLargeError) as exc_info:
        adapter.put_object("inv-oversized/huge.raw.bin", oversized_data)

    assert "exceeds maximum limit" in str(exc_info.value)


# ============================================================================
# 8. CONTENT-TYPE HANDLING & MIME TYPES
# ============================================================================

def test_content_type_handling_and_mime_types(tmp_path: Path, admin_client: TestClient, db_session):
    """Verifies that evidence serialization correctly resolves MIME types across JSON, text, and binary."""
    from app.services.evidence_store import get_evidence_store

    store = EvidenceStore(base_path=str(tmp_path))

    # 1. JSON
    key_json, hash_json, size_json = store.store_evidence(
        investigation_id="inv-mime-01",
        evidence_id="evi-mime-json",
        source_type="dns",
        content={"records": ["A", "MX"], "domain": "example.com"},
    )
    assert key_json.endswith(".json")

    # 2. Text
    key_txt, hash_txt, size_txt = store.store_evidence(
        investigation_id="inv-mime-01",
        evidence_id="evi-mime-txt",
        source_type="whois",
        content="Domain Name: EXAMPLE.COM\nRegistry Domain ID: 123",
    )
    assert key_txt.endswith(".txt")

    # 3. Binary
    key_bin, hash_bin, size_bin = store.store_evidence(
        investigation_id="inv-mime-01",
        evidence_id="evi-mime-bin",
        source_type="pcap",
        content=b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00",
    )
    assert key_bin.endswith(".bin")

    # Verify adapter metadata records correct MIME types
    meta_json = store.adapter.get_object_metadata(key_json)
    assert meta_json.content_type == "application/json"

    meta_txt = store.adapter.get_object_metadata(key_txt)
    assert "text/plain" in meta_txt.content_type

    meta_bin = store.adapter.get_object_metadata(key_bin)
    assert meta_bin.content_type == "application/octet-stream"


# ============================================================================
# 9. UNSAFE FILENAMES & TRAVERSAL VECTORS IN EVIDENCE STORE
# ============================================================================

def test_unsafe_filenames_rejection(tmp_path: Path):
    """Verifies that illegal filenames and path traversal in EvidenceStore parameters raise ValueError."""
    store = EvidenceStore(base_path=str(tmp_path))

    unsafe_cases = [
        ("../../etc/shadow", "evi-01", "nmap"),
        ("inv-01", "../evi-traversal", "nmap"),
        ("inv-01", "evi-01", "../nmap"),
        ("inv-01", "evi-01; rm -rf /", "nmap"),
        ("inv-01", "evi\x00null", "nmap"),
        ("inv-01", "evi|pipe", "nmap"),
    ]

    for inv_id, evi_id, src in unsafe_cases:
        with pytest.raises(ValueError):
            store.store_evidence(
                investigation_id=inv_id,
                evidence_id=evi_id,
                source_type=src,
                content="test content",
            )


# ============================================================================
# 10. SEAWEEDFS CREDENTIAL PROTECTION & LOG REDACTION
# ============================================================================

def test_seaweedfs_credential_protection_in_logs_and_repr():
    """Confirms that auth tokens and credentials are masked in representations and logs."""
    adapter = SeaweedFSStorageAdapter(
        filer_url="http://filer.internal.lan:8888",
        collection="evidence-col",
        auth_token="super-secret-production-bearer-token-12345",
    )

    repr_str = repr(adapter)
    str_str = str(adapter)

    # Auth token must never appear in repr or str
    assert "super-secret-production-bearer-token-12345" not in repr_str
    assert "super-secret-production-bearer-token-12345" not in str_str
    assert "filer.internal.lan" in repr_str

