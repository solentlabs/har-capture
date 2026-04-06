"""Tests for connectivity checking functions."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.connectivity import (
    _parse_target,
    check_basic_auth,
    check_device_connectivity,
    check_session_contamination,
)

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

    def test_missing_scheme_returns_error(self) -> None:
        """Test bare hostname/IP without scheme returns error."""
        reachable, _scheme, error = check_device_connectivity("192.168.1.1")

        assert reachable is False
        assert error is not None
        assert "http://" in error
        assert "https://" in error

    def test_missing_scheme_hostname(self) -> None:
        """Test bare hostname without scheme returns error."""
        reachable, _scheme, error = check_device_connectivity("example.com")

        assert reachable is False
        assert error is not None
        assert "Missing scheme" in error

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
    """Additional edge case tests for _parse_target."""

    def test_ftp_scheme_preserved(self) -> None:
        """Test non-http schemes are preserved."""
        host, scheme = _parse_target("ftp://files.example.com")
        assert host == "files.example.com"
        assert scheme == "ftp"

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
