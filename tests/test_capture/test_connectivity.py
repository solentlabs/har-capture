"""Tests for connectivity checking functions."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.connectivity import (
    ProtocolDetectionResult,
    _parse_target,
    check_basic_auth,
    check_device_connectivity,
    check_session_contamination,
    detect_protocol,
)

_MODULE = "har_capture.capture.connectivity"

# =============================================================================
# Test Data Tables
# =============================================================================

CONNECTIVITY_HTTP_ERROR_CASES = [
    (401, "Unauthorized", "auth_required"),
    (403, "Forbidden", "forbidden"),
    (404, "Not Found", "not_found"),
    (500, "Server Error", "server_error"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestCheckDeviceConnectivity:
    """Tests for check_device_connectivity function."""

    @patch("urllib.request.urlopen")
    def test_http_success(self, mock_urlopen: MagicMock) -> None:
        """Test successful HTTP connection."""
        mock_urlopen.return_value = MagicMock()

        reachable, scheme, error = check_device_connectivity("http://192.168.1.1")

        assert reachable is True
        assert scheme == "http"
        assert error is None

    @patch("urllib.request.urlopen")
    def test_https_success(self, mock_urlopen: MagicMock) -> None:
        """Test successful HTTPS connection."""
        mock_urlopen.return_value = MagicMock()

        reachable, scheme, error = check_device_connectivity("https://example.com")

        assert reachable is True
        assert scheme == "https"
        assert error is None

    @patch("urllib.request.urlopen")
    def test_http_scheme(self, mock_urlopen: MagicMock) -> None:
        """Test with HTTP scheme."""
        mock_urlopen.return_value = MagicMock()

        reachable, scheme, error = check_device_connectivity("http://example.com")

        assert reachable is True
        assert scheme == "http"
        assert error is None
        assert mock_urlopen.call_count == 1

    @patch(f"{_MODULE}.detect_protocol")
    @patch("urllib.request.urlopen")
    def test_bare_ip_auto_detects_protocol(
        self,
        mock_urlopen: MagicMock,
        mock_detect: MagicMock,
    ) -> None:
        """Bare IP without scheme triggers detect_protocol() and uses its result."""
        mock_detect.return_value = ProtocolDetectionResult(
            success=True,
            protocol="https",
            working_url="https://192.168.1.1",
        )
        mock_urlopen.return_value = MagicMock()

        reachable, scheme, error = check_device_connectivity("192.168.1.1")

        assert reachable is True
        assert scheme == "https"
        assert error is None
        mock_detect.assert_called_once()

    @patch(f"{_MODULE}.detect_protocol")
    def test_bare_hostname_unreachable_returns_detection_error(
        self,
        mock_detect: MagicMock,
    ) -> None:
        """When detect_protocol fails on a bare host, its error surfaces."""
        mock_detect.return_value = ProtocolDetectionResult(
            success=False,
            error="Cannot connect to example.com. Tried: TCP example.com:80 and example.com:443.",
        )

        reachable, _scheme, error = check_device_connectivity("example.com")

        assert reachable is False
        assert error is not None
        assert "Cannot connect to example.com" in error

    @patch(f"{_MODULE}.detect_protocol")
    @patch("urllib.request.urlopen")
    def test_explicit_scheme_skips_detect_protocol(
        self,
        mock_urlopen: MagicMock,
        mock_detect: MagicMock,
    ) -> None:
        """An explicit scheme bypasses auto-detection — the user has chosen."""
        mock_urlopen.return_value = MagicMock()

        reachable, scheme, _error = check_device_connectivity("http://192.168.1.1")

        assert reachable is True
        assert scheme == "http"
        mock_detect.assert_not_called()

    @pytest.mark.parametrize(
        ("status_code", "reason", "desc"),
        CONNECTIVITY_HTTP_ERROR_CASES,
        ids=[c[2] for c in CONNECTIVITY_HTTP_ERROR_CASES],
    )
    @patch("urllib.request.urlopen")
    def test_http_error_means_reachable(
        self,
        mock_urlopen: MagicMock,
        status_code: int,
        reason: str,
        desc: str,
    ) -> None:
        """Test HTTP errors (401, 403, etc.) mean target is reachable."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test/",
            code=status_code,
            msg=reason,
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )

        reachable, _scheme, error = check_device_connectivity("http://192.168.1.1")

        assert reachable is True, f"{desc}: HTTP {status_code} should mean reachable"
        assert error is None

    @patch("urllib.request.urlopen")
    def test_connection_refused(self, mock_urlopen: MagicMock) -> None:
        """Test connection refused returns not reachable."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        reachable, _scheme, error = check_device_connectivity("http://192.168.1.1")

        assert reachable is False
        assert error is not None
        assert "192.168.1.1" in error

    @patch("urllib.request.urlopen")
    def test_timeout(self, mock_urlopen: MagicMock) -> None:
        """Test connection timeout returns not reachable."""
        mock_urlopen.side_effect = urllib.error.URLError("timed out")

        reachable, _scheme, error = check_device_connectivity("http://192.168.1.1", timeout=1)

        assert reachable is False
        assert error is not None

    @patch("urllib.request.urlopen")
    def test_generic_exception(self, mock_urlopen: MagicMock) -> None:
        """Test generic exception is handled."""
        mock_urlopen.side_effect = Exception("Something went wrong")

        reachable, _scheme, error = check_device_connectivity("http://192.168.1.1")

        assert reachable is False
        assert error is not None
        assert "Something went wrong" in error

    @patch("urllib.request.urlopen")
    def test_ssl_context_for_https(self, mock_urlopen: MagicMock) -> None:
        """Test HTTPS uses SSL context that ignores cert errors."""
        mock_urlopen.return_value = MagicMock()

        check_device_connectivity("https://self-signed.example.com")

        # Check that context parameter was passed
        call_kwargs = mock_urlopen.call_args[1]
        assert "context" in call_kwargs
        ctx = call_kwargs["context"]
        assert isinstance(ctx, ssl.SSLContext)


class TestCheckBasicAuth:
    """Tests for check_basic_auth function."""

    @patch("urllib.request.urlopen")
    def test_no_auth_required(self, mock_urlopen: MagicMock) -> None:
        """Test detection when no auth is required."""
        mock_urlopen.return_value = MagicMock()

        requires_auth, realm = check_basic_auth("http://example.com/")

        assert requires_auth is False
        assert realm is None

    @patch("urllib.request.urlopen")
    def test_basic_auth_with_realm(self, mock_urlopen: MagicMock) -> None:
        """Test detection of Basic Auth with realm."""
        error = urllib.error.HTTPError(
            url="http://test/",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=None,
        )
        error.headers = {"WWW-Authenticate": 'Basic realm="Router Admin"'}
        mock_urlopen.side_effect = error

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is True
        assert realm == "Router Admin"

    @patch("urllib.request.urlopen")
    def test_basic_auth_without_quotes(self, mock_urlopen: MagicMock) -> None:
        """Test detection of Basic Auth with realm without quotes."""
        error = urllib.error.HTTPError(
            url="http://test/",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=None,
        )
        error.headers = {"WWW-Authenticate": "Basic realm=Router"}
        mock_urlopen.side_effect = error

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is True
        assert realm == "Router"

    @patch("urllib.request.urlopen")
    def test_basic_auth_no_realm(self, mock_urlopen: MagicMock) -> None:
        """Test detection of Basic Auth without realm."""
        error = urllib.error.HTTPError(
            url="http://test/",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=None,
        )
        error.headers = {"WWW-Authenticate": "Basic"}
        mock_urlopen.side_effect = error

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is True
        assert realm is None

    @patch("urllib.request.urlopen")
    def test_non_basic_auth_401(self, mock_urlopen: MagicMock) -> None:
        """Test 401 with non-Basic auth (e.g., Digest)."""
        error = urllib.error.HTTPError(
            url="http://test/",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=None,
        )
        error.headers = {"WWW-Authenticate": "Digest realm=test"}
        mock_urlopen.side_effect = error

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is False
        assert realm is None

    @patch("urllib.request.urlopen")
    def test_non_401_http_error(self, mock_urlopen: MagicMock) -> None:
        """Test non-401 HTTP errors don't indicate auth required."""
        error = urllib.error.HTTPError(
            url="http://test/",
            code=403,
            msg="Forbidden",
            hdrs=MagicMock(),
            fp=None,
        )
        error.headers = {}
        mock_urlopen.side_effect = error

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is False
        assert realm is None

    @patch("urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen: MagicMock) -> None:
        """Test connection errors return False."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is False
        assert realm is None

    @patch("urllib.request.urlopen")
    def test_generic_exception(self, mock_urlopen: MagicMock) -> None:
        """Test generic exceptions return False."""
        mock_urlopen.side_effect = Exception("Something broke")

        requires_auth, realm = check_basic_auth("http://192.168.1.1/")

        assert requires_auth is False
        assert realm is None

    @patch("urllib.request.urlopen")
    def test_https_url_uses_ssl_context(self, mock_urlopen: MagicMock) -> None:
        """Test HTTPS URLs use SSL context."""
        mock_urlopen.return_value = MagicMock()

        check_basic_auth("https://192.168.1.1/")

        call_kwargs = mock_urlopen.call_args[1]
        assert "context" in call_kwargs


class TestParseTargetEdgeCases:
    """Edge cases for _parse_target — exercises the wrapper over _strip_protocol.

    Note: ftp:// and other non-http schemes are no longer recognized — har-capture
    only handles http/https targets, so non-http schemes are returned with
    scheme=None (the input is treated as a bare host string). See _strip_protocol.
    """

    def test_empty_path(self) -> None:
        """Test URL with empty path."""
        host, scheme = _parse_target("http://example.com")
        assert host == "example.com"
        assert scheme == "http"

    def test_url_with_query_string(self) -> None:
        """Test URL with query string - host still extracted."""
        host, scheme = _parse_target("http://example.com/path?query=1")
        assert host == "example.com"
        assert scheme == "http"

    def test_url_with_fragment(self) -> None:
        """Test URL with fragment - host still extracted."""
        host, scheme = _parse_target("http://example.com/path#section")
        assert host == "example.com"
        assert scheme == "http"

    def test_ipv6_address(self) -> None:
        """Test IPv6 address parsing."""
        host, scheme = _parse_target("http://[::1]:8080")
        assert "[::1]:8080" in host
        assert scheme == "http"


# =============================================================================
# Test Data Tables — Session Contamination
# =============================================================================

# fmt: off
SESSION_CONTAMINATION_LOGIN_PAGES = [
    (b"<html><body><form><input type='password'></form></body></html>",       "password field"),
    (b"<html><body><h1>Login</h1><form action='/auth'></form></body></html>", "login keyword"),
    (b"<html><body>Please sign in to continue</body></html>",                "sign in text"),
    (b"<html><body>Please authenticate to access this resource</body></html>", "authenticate keyword"),
]

SESSION_CONTAMINATION_DATA_PAGES = [
    (b"<html><body><h1>Device Status</h1><table><tr><td>Downstream</td><td>Channel 1</td></tr></table>" + b"x" * 100, "admin data page"),
    (b'{"systemInfo":{"model":"MB8611","firmware":"2.3.1"},"uptime":123456}' + b" " * 50,                              "JSON device data"),
]
# fmt: on


class TestCheckSessionContamination:
    """Tests for check_session_contamination function."""

    @patch("urllib.request.urlopen")
    def test_401_means_clean(self, mock_urlopen: MagicMock) -> None:
        """401 response means auth is required — no live session."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test/",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=None,
        )

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None

    @patch("urllib.request.urlopen")
    def test_403_means_clean(self, mock_urlopen: MagicMock) -> None:
        """403 response means auth is required — no live session."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test/",
            code=403,
            msg="Forbidden",
            hdrs=MagicMock(),
            fp=None,
        )

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None

    @pytest.mark.parametrize(
        ("body", "desc"),
        SESSION_CONTAMINATION_LOGIN_PAGES,
        ids=[c[1] for c in SESSION_CONTAMINATION_LOGIN_PAGES],
    )
    @patch("urllib.request.urlopen")
    def test_login_page_means_clean(
        self,
        mock_urlopen: MagicMock,
        body: bytes,
        desc: str,
    ) -> None:
        """200 with login page indicators means clean state."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = body
        mock_urlopen.return_value = mock_resp

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False, f"{desc}: login page should not be flagged"
        assert message is None

    @pytest.mark.parametrize(
        ("body", "desc"),
        SESSION_CONTAMINATION_DATA_PAGES,
        ids=[c[1] for c in SESSION_CONTAMINATION_DATA_PAGES],
    )
    @patch("urllib.request.urlopen")
    def test_data_page_means_contaminated(
        self,
        mock_urlopen: MagicMock,
        body: bytes,
        desc: str,
    ) -> None:
        """200 with data content and no login indicators means live session."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = body
        mock_urlopen.return_value = mock_resp

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is True, f"{desc}: data page should be flagged"
        assert message is not None
        assert "live session" in message

    @patch("urllib.request.urlopen")
    def test_tiny_response_means_clean(self, mock_urlopen: MagicMock) -> None:
        """Very small 200 response (redirect stub) is not flagged."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html><body>OK</body></html>"  # < 100 bytes
        mock_urlopen.return_value = mock_resp

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None

    @patch("urllib.request.urlopen")
    def test_empty_response_means_clean(self, mock_urlopen: MagicMock) -> None:
        """Empty 200 response is not flagged."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b""
        mock_urlopen.return_value = mock_resp

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None

    @patch("urllib.request.urlopen")
    def test_connection_error_means_clean(self, mock_urlopen: MagicMock) -> None:
        """Connection errors don't block capture."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None

    @patch("urllib.request.urlopen")
    def test_timeout_means_clean(self, mock_urlopen: MagicMock) -> None:
        """Timeout doesn't block capture."""
        mock_urlopen.side_effect = TimeoutError("timed out")

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None

    @patch("urllib.request.urlopen")
    def test_https_uses_ssl_context(self, mock_urlopen: MagicMock) -> None:
        """HTTPS URLs use SSL context for self-signed certs."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html><body>Login</body></html>" + b" " * 100
        mock_urlopen.return_value = mock_resp

        check_session_contamination("https://192.168.100.1/")

        call_kwargs = mock_urlopen.call_args[1]
        assert "context" in call_kwargs
        ctx = call_kwargs["context"]
        assert isinstance(ctx, ssl.SSLContext)

    @patch("urllib.request.urlopen")
    def test_non_200_status_means_clean(self, mock_urlopen: MagicMock) -> None:
        """Non-200 success status (e.g., 204) means clean state."""
        mock_resp = MagicMock()
        mock_resp.status = 302
        mock_urlopen.return_value = mock_resp

        contaminated, message = check_session_contamination("http://192.168.100.1/")

        assert contaminated is False
        assert message is None


# =============================================================================
# detect_protocol() — table-driven scenario bench
# =============================================================================
#
# Adapted from cable_modem_monitor_core/tests/test_connectivity.py with the
# legacy-TLS classification dropped — har-capture can't act on it (Chromium
# runs its own TLS stack), so the probe just reports whether HTTPS is usable.
# The SECLEVEL=0 cipher tolerance in `_tls_handshake` is what's load-bearing
# (it lets the handshake complete against legacy modems instead of falsely
# falling back to HTTP) and is exercised by `TestTlsHandshake` directly.
#
# Each row drives one full detect_protocol() invocation. ``tls_outcome`` is
# None when the TLS handshake is not expected to run (either :443 was
# closed or the user pinned http://…). When set, it's the bool that
# ``_tls_handshake`` returns.

_DetectCase = tuple[
    str,  # description
    str,  # input host
    bool,  # :80 open?
    bool,  # :443 open?
    bool | None,  # _tls_handshake mock return; None if not called
    bool,  # expected success
    str | None,  # expected protocol
    str | None,  # expected working_url ("…" or None)
    list[int],  # expected ports passed to _tcp_probe
]

# fmt: off
DETECT_PROTOCOL_CASES: list[_DetectCase] = [
    ("http_only",
     "192.168.100.1",  True,  False, None,
     True,  "http",  "http://192.168.100.1",  [80, 443]),
    ("https_handshake_completes_https_wins",
     "192.168.100.1",  True,  True,  True,
     True,  "https", "https://192.168.100.1", [80, 443]),
    ("https_handshake_fails_falls_back_to_http",
     "192.168.100.1",  True,  True,  False,
     True,  "http",  "http://192.168.100.1",  [80, 443]),
    ("https_only",
     "192.168.100.1",  False, True,  True,
     True,  "https", "https://192.168.100.1", [80, 443]),
    ("https_open_but_handshake_fails_no_http",
     "192.168.100.1",  False, True,  False,
     False, None,    None,                     [80, 443]),
    ("both_ports_closed",
     "192.168.100.1",  False, False, None,
     False, None,    None,                     [80, 443]),
    ("explicit_http_skips_tls_probe",
     "http://192.168.100.1", True, True, None,
     True,  "http",  "http://192.168.100.1",  [80]),
    ("explicit_https_skips_http_probe",
     "https://192.168.100.1", True, True, True,
     True,  "https", "https://192.168.100.1", [443]),
    ("explicit_http_with_port_probes_only_that_port",
     "http://127.0.0.1:36771", True, False, None,
     True,  "http",  "http://127.0.0.1:36771", [36771]),
    ("explicit_https_with_port_probes_only_that_port",
     "https://127.0.0.1:8443", False, True, True,
     True,  "https", "https://127.0.0.1:8443", [8443]),
    ("ipv6_bracketed_https_handshake_completes",
     "[::1]:8443", False, True, True,
     True,  "https", "https://[::1]:8443", [8443, 8443]),
    ("ipv6_bracketed_http_only",
     "[::1]", True, False, None,
     True,  "http", "http://[::1]", [80, 443]),
]
# fmt: on


@pytest.mark.parametrize(
    "description, host, port_80_open, port_443_open, tls_outcome, "
    "expected_success, expected_protocol, expected_working_url, expected_tcp_ports",
    DETECT_PROTOCOL_CASES,
    ids=[c[0] for c in DETECT_PROTOCOL_CASES],
)
class TestDetectProtocol:
    """Protocol detection — one row per scenario in DETECT_PROTOCOL_CASES."""

    def test_detection_outcome(
        self,
        description: str,
        host: str,
        port_80_open: bool,
        port_443_open: bool,
        tls_outcome: bool | None,
        expected_success: bool,
        expected_protocol: str | None,
        expected_working_url: str | None,
        expected_tcp_ports: list[int],
    ) -> None:
        """One detect_protocol() invocation per row.

        Bracketed-IPv6 inputs additionally assert the address family
        passed to ``_tcp_probe`` is ``AF_INET6`` (capture-everything
        philosophy: don't silently false-fail v6-only targets).
        """
        import socket as _socket

        tcp_calls: list[int] = []
        tcp_families: list[int] = []

        def tcp_side_effect(
            host: str,
            port: int,
            timeout: float,
            *,
            address_family: int = _socket.AF_INET,
        ) -> bool:
            tcp_calls.append(port)
            tcp_families.append(address_family)
            # When user provides a custom port, both http_port and https_port
            # collapse to it. The row's port_80_open / port_443_open booleans
            # then map by *intent*: for an http://-prefixed input, port_80_open
            # governs the user port; for an https://-prefixed input,
            # port_443_open governs it. detect_protocol only probes one port
            # in the explicit-prefix case, so this disambiguates cleanly.
            if port == 80:
                return port_80_open
            if port == 443:
                return port_443_open
            return port_443_open or port_80_open

        tls_patch = (
            patch(f"{_MODULE}._tls_handshake", return_value=tls_outcome)
            if tls_outcome is not None
            else patch(f"{_MODULE}._tls_handshake")
        )
        with (
            patch(f"{_MODULE}._tcp_probe", side_effect=tcp_side_effect),
            tls_patch as tls,
        ):
            result = detect_protocol(host)

        assert result.success is expected_success, description
        assert result.protocol == expected_protocol, description
        if expected_working_url is None:
            assert result.working_url is None, description
            assert result.error is not None, description
        else:
            assert result.working_url == expected_working_url, description

        assert tcp_calls == expected_tcp_ports, description

        # Bracketed IPv6 inputs must select AF_INET6 across every probe;
        # everything else must stay on AF_INET.
        expected_family = _socket.AF_INET6 if "[" in host else _socket.AF_INET
        assert all(f == expected_family for f in tcp_families), (
            f"{description}: expected family {expected_family}, got {tcp_families}"
        )

        if tls_outcome is None:
            tls.assert_not_called()
        else:
            tls.assert_called_once()


# =============================================================================
# _strip_protocol() — pure helper, exhaustive table
# =============================================================================

# fmt: off
_STRIP_PROTOCOL_CASES = [
    ("bare_ip",                   "192.168.100.1",            (None,    "192.168.100.1")),
    ("bare_hostname",             "modem.local",              (None,    "modem.local")),
    ("http_prefix",               "http://192.168.100.1",     ("http",  "192.168.100.1")),
    ("https_prefix",              "https://192.168.100.1",    ("https", "192.168.100.1")),
    ("http_with_path",            "http://192.168.100.1/x",   ("http",  "192.168.100.1")),
    ("https_with_path_and_query", "https://m.local/a?b=1",    ("https", "m.local")),
    ("bare_ip_with_path",         "192.168.100.1/login",      (None,    "192.168.100.1")),
    ("http_with_port",            "http://192.168.100.1:8080", ("http", "192.168.100.1:8080")),
]
# fmt: on


@pytest.mark.parametrize(
    "description, host, expected",
    _STRIP_PROTOCOL_CASES,
    ids=[c[0] for c in _STRIP_PROTOCOL_CASES],
)
def test_strip_protocol(description: str, host: str, expected: tuple[str | None, str]) -> None:
    """_strip_protocol returns (protocol, bare_host_with_optional_port)."""
    from har_capture.capture.connectivity import _strip_protocol

    assert _strip_protocol(host) == expected, description


# =============================================================================
# _split_host_port() — pure helper, exhaustive table
# =============================================================================

# fmt: off
_SPLIT_HOST_PORT_CASES = [
    ("ipv4_no_port",             "192.168.100.1",        ("192.168.100.1", None)),
    ("ipv4_with_port",           "192.168.100.1:8080",   ("192.168.100.1", 8080)),
    ("hostname_no_port",         "modem.local",          ("modem.local",   None)),
    ("hostname_with_port",       "modem.local:8443",     ("modem.local",   8443)),
    ("loopback_with_high_port",  "127.0.0.1:36771",      ("127.0.0.1",     36771)),
    ("ipv6_bracketed_no_port",   "[::1]",                ("::1",           None)),
    ("ipv6_bracketed_with_port", "[::1]:8080",           ("::1",           8080)),
    ("ipv6_bracketed_partial",   "[::1",                 ("[::1",          None)),
    ("trailing_colon_no_port",   "host:",                ("host:",         None)),
]
# fmt: on


@pytest.mark.parametrize(
    "description, host, expected",
    _SPLIT_HOST_PORT_CASES,
    ids=[c[0] for c in _SPLIT_HOST_PORT_CASES],
)
def test_split_host_port(description: str, host: str, expected: tuple[str, int | None]) -> None:
    """_split_host_port returns (hostname, port|None) preserving IPv6 bracket form."""
    from har_capture.capture.connectivity import _split_host_port

    assert _split_host_port(host) == expected, description


class TestTcpProbe:
    """Direct tests for _tcp_probe — IPv4 pinning and resolution failure."""

    @patch(f"{_MODULE}.socket.getaddrinfo")
    def test_resolution_failure_returns_false(self, mock_gai: MagicMock) -> None:
        from har_capture.capture.connectivity import _tcp_probe

        mock_gai.side_effect = OSError("name not known")
        assert _tcp_probe("nope.invalid", 80, timeout=1.0) is False

    @patch(f"{_MODULE}.socket.socket")
    @patch(f"{_MODULE}.socket.getaddrinfo")
    def test_defaults_to_ipv4(self, mock_gai: MagicMock, mock_socket: MagicMock) -> None:
        """Default ``getaddrinfo`` family is AF_INET.

        Protects against dual-stack false-fail on IPv4-only LAN devices.
        """
        import socket as _socket

        from har_capture.capture.connectivity import _tcp_probe

        mock_gai.return_value = [
            (_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("192.168.100.1", 80)),
        ]
        mock_socket.return_value.connect.return_value = None

        _tcp_probe("192.168.100.1", 80, timeout=1.0)

        mock_gai.assert_called_once()
        call_kwargs = mock_gai.call_args.kwargs
        assert call_kwargs.get("family") == _socket.AF_INET

    @patch(f"{_MODULE}.socket.socket")
    @patch(f"{_MODULE}.socket.getaddrinfo")
    def test_passes_ipv6_family_when_requested(
        self,
        mock_gai: MagicMock,
        mock_socket: MagicMock,
    ) -> None:
        """``address_family=AF_INET6`` propagates through to ``getaddrinfo``.

        Bracketed IPv6 targets must reach the v6 resolver — the IPv4 default
        would silently false-fail and drop captures of v6-only devices.
        """
        import socket as _socket

        from har_capture.capture.connectivity import _tcp_probe

        mock_gai.return_value = [
            (_socket.AF_INET6, _socket.SOCK_STREAM, 0, "", ("::1", 8443, 0, 0)),
        ]
        mock_socket.return_value.connect.return_value = None

        _tcp_probe("::1", 8443, timeout=1.0, address_family=_socket.AF_INET6)

        mock_gai.assert_called_once()
        assert mock_gai.call_args.kwargs.get("family") == _socket.AF_INET6

    @patch(f"{_MODULE}.socket.socket")
    @patch(f"{_MODULE}.socket.getaddrinfo")
    def test_connect_failure_returns_false(
        self,
        mock_gai: MagicMock,
        mock_socket: MagicMock,
    ) -> None:
        """Connect-time OSError on a resolved address returns False (closed port)."""
        import socket as _socket

        from har_capture.capture.connectivity import _tcp_probe

        mock_gai.return_value = [
            (_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("192.168.100.1", 80)),
        ]
        mock_socket.return_value.connect.side_effect = OSError("connection refused")

        assert _tcp_probe("192.168.100.1", 80, timeout=1.0) is False
        mock_socket.return_value.close.assert_called_once()


class TestTlsHandshake:
    """Direct tests for _tls_handshake — completes against any TLS version."""

    @pytest.mark.parametrize(
        "negotiated_version",
        ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"],
    )
    @patch(f"{_MODULE}.socket.create_connection")
    @patch(f"{_MODULE}.ssl.SSLContext")
    def test_completes_for_all_tls_versions(
        self,
        mock_context_cls: MagicMock,
        mock_create_conn: MagicMock,
        negotiated_version: str,
    ) -> None:
        """SECLEVEL=0 cipher tolerance completes the handshake on any TLS version.

        Legacy devices (TLS 1.0/1.1, SSLv3) must succeed here — without that
        tolerance we'd false-fail HTTPS and capture HTTP instead, the inverse
        CM1200 trap.
        """
        from har_capture.capture.connectivity import _tls_handshake

        raw_sock = MagicMock()
        mock_create_conn.return_value.__enter__.return_value = raw_sock

        tls_sock = MagicMock()
        tls_sock.version.return_value = negotiated_version
        ctx = mock_context_cls.return_value
        ctx.wrap_socket.return_value.__enter__.return_value = tls_sock

        assert _tls_handshake("192.168.100.1", 443, timeout=2.0) is True

    @patch(f"{_MODULE}.socket.create_connection")
    def test_handshake_failure_returns_false(
        self,
        mock_create_conn: MagicMock,
    ) -> None:
        import ssl as _ssl

        from har_capture.capture.connectivity import _tls_handshake

        mock_create_conn.side_effect = _ssl.SSLError("handshake failure")

        assert _tls_handshake("192.168.100.1", 443, timeout=2.0) is False


class TestProtocolDetectionResult:
    """ProtocolDetectionResult dataclass."""

    def test_defaults(self) -> None:
        """Default values for a failed result."""
        result = ProtocolDetectionResult(success=False)
        assert result.protocol is None
        assert result.working_url is None
        assert result.error is None


class TestTargetPath:
    """target_path — the user-facing "your path was ignored" signal.

    _strip_protocol silently drops the path; the CLI uses target_path to
    warn instead of capturing the wrong page (a bare-root capture cost a
    wasted CM2500 run on 2026-08-19).
    """

    # fmt: off
    PATH_CASES = [
        ("https://192.168.100.1/DocsisStatus.htm", "/DocsisStatus.htm",  "https_with_path"),
        ("http://host/page.htm",                   "/page.htm",          "http_with_path"),
        ("192.168.100.1/DocsisStatus.htm",         "/DocsisStatus.htm",  "bare_host_with_path"),
        ("https://host/a/b?q=1",                   "/a/b?q=1",           "nested_path_with_query"),
        ("https://192.168.100.1",                  "",                   "no_path"),
        ("https://192.168.100.1/",                 "",                   "bare_trailing_slash"),
        ("192.168.100.1",                          "",                   "bare_ip"),
        ("192.168.100.1:8080",                     "",                   "host_with_port"),
        ("https://[::1]:8443/page",                "/page",              "ipv6_with_path"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("target", "expected", "desc"),
        PATH_CASES,
        ids=[c[2] for c in PATH_CASES],
    )
    def test_target_path(self, target: str, expected: str, desc: str) -> None:
        from har_capture.capture.connectivity import target_path

        assert target_path(target) == expected, desc
