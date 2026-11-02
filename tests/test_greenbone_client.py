"""Unit tests verifying Greenbone client connectivity, configuration diagnostics, and error handling."""

import socket
import ssl
from unittest.mock import MagicMock, patch
import pytest

from app.integrations.greenbone_client import (
    GreenboneClient,
    GreenboneConnectionStatus,
    GreenboneNotConfiguredError,
    GreenboneConnectionError,
    GreenboneAuthenticationError,
    GreenboneOperationError,
)
from app.services.vuln.profiles import (
    list_vuln_profiles,
    get_vuln_profile,
    validate_vuln_profile,
)


def test_greenbone_client_not_configured():
    """Verify that Greenbone client detects missing configuration and reports NOT_CONFIGURED."""
    client = GreenboneClient(
        host=None,
        port=None,
        unix_socket=None,
        username=None,
        password=None,
    )
    assert client.is_configured is False
    assert client.endpoint_display == "none"

    status_report = client.check_status()
    assert status_report["status"] == GreenboneConnectionStatus.NOT_CONFIGURED.value
    assert status_report["configured"] is False
    assert status_report["authenticated"] is False
    assert "not configured" in status_report["error"].lower()

    with pytest.raises(GreenboneNotConfiguredError):
        client.get_connection()


def test_greenbone_client_unavailable_network_error():
    """Verify that connection failure or refused socket returns UNAVAILABLE without exposing credentials."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=59390,  # non-existent port
        username="admin",
        password="secretpassword",
        timeout=1,
    )
    assert client.is_configured is True
    assert client.endpoint_display == "127.0.0.1:59390"

    with patch("gvm.protocols.gmp.Gmp") as mock_gmp_cls:
        # Simulate connection refused
        mock_gmp_instance = MagicMock()
        mock_gmp_instance.__enter__.side_effect = ConnectionRefusedError("Connection refused")
        mock_gmp_cls.return_value = mock_gmp_instance

        status_report = client.check_status()
        assert status_report["status"] == GreenboneConnectionStatus.UNAVAILABLE.value
        assert status_report["configured"] is True
        assert status_report["authenticated"] is False
        assert "secretpassword" not in str(status_report)
        assert "ConnectionRefusedError" in status_report["error"] or "unavailable" in status_report["error"].lower()


def test_greenbone_client_tls_verification_failure():
    """Verify that TLS validation errors are reported explicitly."""
    client = GreenboneClient(
        host="gvm.internal.corp",
        port=9390,
        username="admin",
        password="secretpassword",
    )

    with patch("gvm.protocols.gmp.Gmp") as mock_gmp_cls:
        mock_gmp_instance = MagicMock()
        mock_gmp_instance.__enter__.side_effect = ssl.SSLCertVerificationError("Certificate verification failed")
        mock_gmp_cls.return_value = mock_gmp_instance

        status_report = client.check_status()
        assert status_report["status"] == GreenboneConnectionStatus.UNAVAILABLE.value
        assert "TLS verification failed" in status_report["error"]
        assert "secretpassword" not in str(status_report)


def test_greenbone_client_authentication_failure():
    """Verify that rejected credentials return AUTHENTICATION_FAILED without leaking secrets."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="scanner_svc",
        password="bad_password",
    )

    from gvm.errors import GvmResponseError

    with patch("gvm.protocols.gmp.Gmp") as mock_gmp_cls:
        mock_gmp = MagicMock()
        mock_gmp.__enter__.return_value = mock_gmp
        mock_gmp.authenticate.side_effect = GvmResponseError("Authentication failed: 400 Bad Request")
        mock_gmp_cls.return_value = mock_gmp

        status_report = client.check_status()
        assert status_report["status"] == GreenboneConnectionStatus.AUTHENTICATION_FAILED.value
        assert status_report["authenticated"] is False
        assert "bad_password" not in str(status_report)
        assert "authentication failed" in status_report["error"].lower()


def test_greenbone_client_ready_status():
    """Verify that successful connection and authentication returns READY and daemon version."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="admin",
        password="validpassword",
    )

    version_xml = '<get_version_response status="200" status_text="OK"><version>22.4.0</version></get_version_response>'

    with patch("gvm.protocols.gmp.Gmp") as mock_gmp_cls:
        mock_gmp = MagicMock()
        mock_gmp.__enter__.return_value = mock_gmp
        mock_gmp.authenticate.return_value = None
        mock_gmp.get_version.return_value = version_xml
        mock_gmp_cls.return_value = mock_gmp

        status_report = client.check_status()
        assert status_report["status"] == GreenboneConnectionStatus.READY.value
        assert status_report["authenticated"] is True
        assert status_report["version"] == "22.4.0"
        assert status_report["error"] is None


def test_vulnerability_profiles_validation():
    """Verify scan profile catalog lookup and validation."""
    profiles = list_vuln_profiles()
    assert len(profiles) >= 2
    profile_ids = [p.id for p in profiles]
    assert "openvas-basic" in profile_ids
    assert "openvas-full-and-fast" in profile_ids

    basic = get_vuln_profile("openvas-basic")
    assert basic is not None
    assert basic.gvm_config_name == "Base"
    assert basic.is_enabled is True
    assert basic.timeout_seconds > 0

    validated = validate_vuln_profile("openvas-basic")
    assert validated.id == "openvas-basic"

    with pytest.raises(ValueError, match="Unknown vulnerability scan profile"):
        validate_vuln_profile("non_existent_profile")


def test_greenbone_verified_tls_connection_checks_chain_and_hostname():
    client = GreenboneClient(host="gvm.lab", username="scanner", password="secret", tls_verify=True)
    raw_socket = MagicMock()
    tls_socket = MagicMock()
    tls_context = MagicMock()
    tls_context.wrap_socket.return_value = tls_socket
    with patch("app.integrations.greenbone_client.socket.socket", return_value=raw_socket), \
         patch("app.integrations.greenbone_client.ssl.create_default_context", return_value=tls_context) as create_context:
        connection = client.get_connection()
        actual = connection._new_socket()
    create_context.assert_called_once_with(cafile=None)
    tls_context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="gvm.lab")
    tls_socket.settimeout.assert_called_once()
    assert actual is tls_socket


def test_greenbone_task_status_reads_last_report_id():
    client = GreenboneClient(host="gvm.lab", username="scanner", password="secret")
    gmp = MagicMock()
    gmp.get_tasks.return_value = (
        '<get_tasks_response><task id="task-1"><status>Done</status><progress>100</progress>'
        '<last_report><report id="report-1"/></last_report></task></get_tasks_response>'
    )
    with patch.object(client, "_open_session", return_value=gmp):
        result = client.get_task_status("task-1")
    assert result["status"] == "Done"
    assert result["progress"] == 100
    assert result["report_id"] == "report-1"
