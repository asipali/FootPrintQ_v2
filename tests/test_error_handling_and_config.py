"""Tests verifying sanitized error handling, correlation IDs, and configuration validation."""

import pytest
from starlette.testclient import TestClient
from fastapi import FastAPI
from app.config import Settings
from app.main import create_app


def test_request_id_header_attached_to_responses(client: TestClient):
    """Verify that every response receives a unique correlation ID."""
    response = client.get("/health/live")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert response.headers["x-request-id"].startswith("req-")


def test_custom_request_id_preserved_when_provided(client: TestClient):
    """Verify client-supplied X-Request-ID is preserved in response headers."""
    custom_id = "req-client-audit-12345"
    response = client.get("/health/live", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == custom_id


def test_validation_error_returns_sanitized_422(authenticated_client: TestClient):
    """Requirement 9: Verify Pydantic validation failure returns sanitized 422 with request_id."""
    invalid_payload = {
        "name": "A",  # too short (min 3)
        # missing required organization_name, lead_investigator, description
    }
    authenticated_client.cookies.set("footprintiq_csrf", "csrf-test-token")
    response = authenticated_client.post(
        "/api/v1/investigations",
        json=invalid_payload,
        headers={"X-CSRF-Token": "csrf-test-token"},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["status_code"] == 422
    assert "Request validation failed" in data["error"]["message"]
    assert "request_id" in data["error"]


def test_unhandled_exception_returns_sanitized_500_without_stack_trace(test_settings: Settings, caplog):
    """Requirement 9: Verify unhandled exceptions return sanitized 500 without leaking stack traces."""
    app = create_app(settings=test_settings)

    # Inject a route that raises an unexpected internal error
    @app.get("/test/broken-internal-route")
    def broken_route():
        raise RuntimeError("SecretDatabaseInternalFailure: password=SuperSecretDbPassword123")

    with TestClient(app, raise_server_exceptions=False) as test_client:
        with caplog.at_level("ERROR"):
            response = test_client.get("/test/broken-internal-route")
        assert response.status_code == 500
        data = response.json()
        assert data["error"]["status_code"] == 500
        # Ensure stack trace and sensitive message were NOT leaked to client
        assert "SuperSecretDbPassword123" not in str(data)
        assert "RuntimeError" not in str(data)
        assert "internal server error occurred" in data["error"]["message"].lower()
        assert "request_id" in data["error"]
        assert "SuperSecretDbPassword123" not in caplog.text


def test_configuration_validation_rules():
    """Requirement 10: Verify typed configuration validation rules."""
    # 1. Development mode allows default secret
    dev_settings = Settings(
        APP_ENV="development",
        SECRET_KEY="dev-insecure-secret-key-change-in-production-only"
    )
    assert dev_settings.APP_ENV == "development"
    assert dev_settings.is_production is False

    # 2. Production mode strictly rejects default insecure secret key
    with pytest.raises(ValueError, match="CRITICAL: Production deployment requires a secure"):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="dev-insecure-secret-key-change-in-production-only"
        )

    # 3. Production mode strictly rejects DEBUG=True
    with pytest.raises(ValueError, match="CRITICAL: DEBUG mode must be disabled"):
        Settings(
            APP_ENV="production",
            DEBUG=True,
            SECRET_KEY="a-very-secure-random-production-secret-key-that-is-long"
        )

    # 4. Settings __repr__ must redact secrets
    safe_settings = Settings(
        APP_ENV="development",
        SECRET_KEY="sensitive-cryptographic-token-value"
    )
    repr_str = repr(safe_settings)
    assert "sensitive-cryptographic-token-value" not in repr_str
    assert "FootprintIQ" in repr_str


def test_staging_defaults_to_secure_cookie_and_rejects_insecure_override():
    strong_test_key = "A7!b9#C2@d5$E8%f1^G4&h6*J3(k0)M+Q8"
    staging = Settings(
        APP_ENV="staging", DEBUG=False, SECRET_KEY=strong_test_key,
        DEMO_ACCOUNTS_ENABLED=False, _env_file=None,
    )
    assert staging.cookie_secure is True
    with pytest.raises(ValueError, match="Secure session cookies"):
        Settings(
            APP_ENV="staging", DEBUG=False, SECRET_KEY=strong_test_key,
            SESSION_COOKIE_SECURE=False, DEMO_ACCOUNTS_ENABLED=False, _env_file=None,
        )


def test_same_site_none_requires_secure_cookie():
    with pytest.raises(ValueError, match="SameSite=None"):
        Settings(SESSION_COOKIE_SAMESITE="none", SESSION_COOKIE_SECURE=False)


def test_staging_rejects_debug_and_wildcard_hosts():
    strong_test_key = "A7!b9#C2@d5$E8%f1^G4&h6*J3(k0)M+Q8"
    with pytest.raises(ValueError, match="DEBUG mode must be disabled"):
        Settings(
            APP_ENV="staging", DEBUG=True, SECRET_KEY=strong_test_key,
            DEMO_ACCOUNTS_ENABLED=False, _env_file=None,
        )
    with pytest.raises(ValueError, match="Wildcard ALLOWED_HOSTS"):
        Settings(
            APP_ENV="staging", DEBUG=False, SECRET_KEY=strong_test_key,
            ALLOWED_HOSTS=["*"], DEMO_ACCOUNTS_ENABLED=False, _env_file=None,
        )


def test_staging_rejects_low_diversity_secret():
    with pytest.raises(ValueError, match="secure, high-entropy SECRET_KEY"):
        Settings(
            APP_ENV="staging", DEBUG=False, SECRET_KEY="a" * 48,
            DEMO_ACCOUNTS_ENABLED=False, _env_file=None,
        )


def test_trusted_host_middleware_enforces_configured_hosts(test_settings: Settings):
    app = create_app(settings=test_settings)
    with TestClient(app) as test_client:
        good = test_client.get("/health/live", headers={"Host": "localhost"})
        bad = test_client.get("/health/live", headers={"Host": "attacker.invalid"})
    assert good.status_code == 200
    assert bad.status_code == 400

