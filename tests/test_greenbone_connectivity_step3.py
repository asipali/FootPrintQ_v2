"""Unit and integration tests for Step 3: Greenbone / OpenVAS Connectivity & Authentication."""

import socket
import ssl
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from app.integrations.greenbone_client import (
    GreenboneClient,
    GreenboneConnectionStatus,
    GreenboneNotConfiguredError,
    GreenboneConnectionError,
    GreenboneAuthenticationError,
    GreenboneOperationError,
    TCPConnection,
)


def test_greenbone_not_configured():
    """Client reports NOT_CONFIGURED when host or credentials are missing."""
    client = GreenboneClient(host=None, port=None, unix_socket=None, username=None, password=None)
    assert client.is_configured is False
    assert client.endpoint_display == "none"

    status = client.health_check()
    assert status["status"] == GreenboneConnectionStatus.NOT_CONFIGURED.value
    assert status["configured"] is False
    assert status["authenticated"] is False
    assert "not configured" in status["error"].lower()


def test_greenbone_unreachable_socket_error():
    """Client reports UNREACHABLE on connection refusal without exposing secrets."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=59391,
        username="test_svc",
        password="supersecretpassword123!",
        timeout=1,
    )
    with patch.object(client, "connect", side_effect=GreenboneConnectionError("Connection refused")):
        status = client.health_check()
        assert status["status"] == GreenboneConnectionStatus.UNREACHABLE.value
        assert status["configured"] is True
        assert status["authenticated"] is False
        assert "supersecretpassword123!" not in str(status)
        assert "connection refused" in status["error"].lower()


def test_greenbone_authentication_failed():
    """Client reports AUTHENTICATION_FAILED when GVM rejects service account."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="wrong_user",
        password="wrong_password",
    )
    mock_gmp = MagicMock()
    with patch.object(client, "connect", return_value=mock_gmp), \
         patch.object(client, "authenticate", side_effect=GreenboneAuthenticationError("Authentication rejected")):
        status = client.health_check()
        assert status["status"] == GreenboneConnectionStatus.AUTHENTICATION_FAILED.value
        assert status["configured"] is True
        assert status["authenticated"] is False
        assert "wrong_password" not in str(status)
        assert "authentication failed" in status["error"].lower()
        mock_gmp.disconnect.assert_called()


def test_greenbone_service_unavailable_version_error():
    """Client reports SERVICE_UNAVAILABLE when version query fails after authentication."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="footprintiq_svc",
        password="valid_password",
    )
    mock_gmp = MagicMock()
    with patch.object(client, "connect", return_value=mock_gmp), \
         patch.object(client, "authenticate", return_value=True), \
         patch.object(client, "get_server_version", side_effect=Exception("Protocol error")):
        status = client.health_check()
        assert status["status"] == GreenboneConnectionStatus.SERVICE_UNAVAILABLE.value
        assert status["authenticated"] is True
        assert "valid_password" not in str(status)


def test_greenbone_scanner_unavailable_no_scanners():
    """Client reports SCANNER_UNAVAILABLE when no scanners are registered."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="footprintiq_svc",
        password="valid_password",
    )
    mock_gmp = MagicMock()
    mock_gmp.get_scanners.return_value = '<get_scanners_response status="200" status_text="OK"></get_scanners_response>'
    with patch.object(client, "connect", return_value=mock_gmp), \
         patch.object(client, "authenticate", return_value=True), \
         patch.object(client, "get_server_version", return_value="22.7"), \
         patch.object(client, "get_scanners", return_value=[]):
        status = client.health_check()
        assert status["status"] == GreenboneConnectionStatus.SCANNER_UNAVAILABLE.value
        assert status["version"] == "22.7"
        assert status["authenticated"] is True


def test_greenbone_scanner_unavailable_verification_fails():
    """Client reports SCANNER_UNAVAILABLE when default scanner fails verification."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="footprintiq_svc",
        password="valid_password",
    )
    mock_gmp = MagicMock()
    scanners = [{"id": "08b69003-5fc2-4037-a479-93b440211c73", "name": "OpenVAS Default", "type": "2", "status": ""}]
    verify_result = {"id": "08b69003-5fc2-4037-a479-93b440211c73", "status": "Error", "version": "Failed", "verified": False}
    with patch.object(client, "connect", return_value=mock_gmp), \
         patch.object(client, "authenticate", return_value=True), \
         patch.object(client, "get_server_version", return_value="22.7"), \
         patch.object(client, "get_scanners", return_value=scanners), \
         patch.object(client, "verify_scanner", return_value=verify_result):
        status = client.health_check()
        assert status["status"] == GreenboneConnectionStatus.SCANNER_UNAVAILABLE.value
        assert status["scanner_name"] == "OpenVAS Default"


def test_greenbone_healthy_full_handshake():
    """Client reports HEALTHY when connected, authenticated, version retrieved and scanner verified."""
    client = GreenboneClient(
        host="127.0.0.1",
        port=9390,
        username="footprintiq_svc",
        password="valid_password",
        use_tls=False,
    )
    mock_gmp = MagicMock()
    scanners = [{"id": "08b69003-5fc2-4037-a479-93b440211c73", "name": "OpenVAS Default", "type": "2", "status": ""}]
    verify_result = {"id": "08b69003-5fc2-4037-a479-93b440211c73", "status": "OK", "version": "OpenVAS 23.51.0", "verified": True}
    with patch.object(client, "connect", return_value=mock_gmp), \
         patch.object(client, "authenticate", return_value=True), \
         patch.object(client, "get_server_version", return_value="22.7"), \
         patch.object(client, "get_scanners", return_value=scanners), \
         patch.object(client, "verify_scanner", return_value=verify_result):
        status = client.health_check()
        assert status["status"] == GreenboneConnectionStatus.HEALTHY.value
        assert status["configured"] is True
        assert status["authenticated"] is True
        assert status["version"] == "22.7"
        assert status["scanner_name"] == "OpenVAS Default"
        assert status["scanner_status"] == "OpenVAS 23.51.0"
        assert status["connection_mode"] == "TCP (127.0.0.1:9390)"
        assert status["error"] is None
        assert "valid_password" not in str(status)


def test_greenbone_tcp_connection_protocol():
    """Verify TCPConnection implements python-gvm socket semantics correctly."""
    conn = TCPConnection(hostname="127.0.0.1", port=9390, timeout=5.0)
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b'<xml>data</xml>'

    with patch("socket.create_connection", return_value=mock_sock):
        conn.connect()
        assert conn._socket is not None

        conn.send(b'<test/>')
        mock_sock.sendall.assert_called_with(b'<test/>')

        data = conn.read()
        assert data == b'<xml>data</xml>'

        conn.finish_send()
        mock_sock.shutdown.assert_called_with(socket.SHUT_WR)

        conn.disconnect()
        assert conn._socket is None
        mock_sock.close.assert_called()


def test_greenbone_xml_parsing_helpers():
    """Verify XML parsers for scanners and verification responses."""
    scanners_xml = (
        '<get_scanners_response status="200" status_text="OK">'
        '<scanner id="uuid-1"><name>OpenVAS Default</name><type>2</type></scanner>'
        '<scanner id="uuid-2"><name>CVE</name><type>1</type></scanner>'
        '</get_scanners_response>'
    )
    scanners = GreenboneClient._parse_scanners(scanners_xml)
    assert len(scanners) == 2
    assert scanners[0]["id"] == "uuid-1"
    assert scanners[0]["name"] == "OpenVAS Default"
    assert scanners[1]["name"] == "CVE"

    verify_xml = '<verify_scanner_response status="200" status_text="OK"><version>OpenVAS 23.51.0</version></verify_scanner_response>'
    verify = GreenboneClient._parse_scanner_verify("uuid-1", verify_xml)
    assert verify["id"] == "uuid-1"
    assert verify["version"] == "OpenVAS 23.51.0"
    assert verify["verified"] is True

