"""Tests for pre-capture diagnostic probes.

Test Coverage:
    - Auth challenge probe (401 Basic, 401 Digest, 200, Set-Cookie, body preview, errors)
    - HEAD support probe (200, 401, 405, connection error, timeout)
    - ICMP probe (success, no latency, failure, timeout, command not found, platform flags)
    - run_probes orchestrator (all succeed, partial failure, hostname extraction)
    - Integration: real HTTPS server with self-signed cert (trustme)

Test Strategy:
    - Table-driven with @pytest.mark.parametrize
    - Mocked urllib and subprocess to avoid real network/system calls
    - Integration tests against a local TLS server for HTTPS probe validation
"""

from __future__ import annotations

import json
import logging
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.probes import (
    _BODY_PREVIEW_CAP,
    _headers_dict,
    _read_body_preview,
    probe_auth_challenge,
    probe_head_support,
    probe_icmp,
    run_probes,
)

# =============================================================================
# Helpers
# =============================================================================


def _make_http_error(
    code: int,
    headers: dict[str, str] | None = None,
    body: str = "",
    multi_cookies: list[str] | None = None,
) -> urllib.error.HTTPError:
    """Create an HTTPError with controllable headers and body."""
    msg = HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v
    if multi_cookies:
        for cookie in multi_cookies:
            msg["Set-Cookie"] = cookie
    fp = BytesIO(body.encode("utf-8")) if body else None
    err = urllib.error.HTTPError(
        url="http://test/",
        code=code,
        msg="error",
        hdrs=msg,
        fp=fp,
    )
    err.headers = msg
    return err


def _make_response(
    status: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
    multi_cookies: list[str] | None = None,
) -> MagicMock:
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status = status
    msg = HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v
    if multi_cookies:
        for cookie in multi_cookies:
            msg["Set-Cookie"] = cookie
    resp.headers = msg
    resp.read.return_value = body.encode("utf-8")
    return resp


class _HeadersNoGetAll:
    """Mock headers object that lacks get_all (exercises AttributeError fallback)."""

    def __init__(self, headers: dict[str, str] | None = None) -> None:
        self._headers = headers or {}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._headers.get(key, default)

    def items(self) -> list[tuple[str, str]]:
        return list(self._headers.items())


def _make_response_no_get_all(status: int = 200, body: str = "", cookie: str | None = None) -> MagicMock:
    """Create a mock response whose headers lack get_all."""
    resp = MagicMock()
    resp.status = status
    hdrs = {} if cookie is None else {"Set-Cookie": cookie}
    resp.headers = _HeadersNoGetAll(hdrs)
    resp.read.return_value = body.encode("utf-8")
    return resp


def _make_http_error_no_get_all(
    code: int,
    headers: dict[str, str] | None = None,
    cookie: str | None = None,
) -> urllib.error.HTTPError:
    """Create an HTTPError whose headers lack get_all."""
    hdrs = dict(headers or {})
    if cookie:
        hdrs["Set-Cookie"] = cookie
    headers_obj = _HeadersNoGetAll(hdrs)
    err = urllib.error.HTTPError(
        url="http://test/",
        code=code,
        msg="error",
        hdrs=headers_obj,
        fp=None,  # type: ignore[arg-type]
    )
    err.headers = headers_obj  # type: ignore[assignment]
    return err


# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
AUTH_CHALLENGE_CASES = [
    # (description, side_effect_factory, expected_status, expected_www_auth, expected_cookies, expected_error_is_none)
    (
        "401_basic",
        lambda: _make_http_error(401, {"WWW-Authenticate": 'Basic realm="Router Admin"'}),
        401, 'Basic realm="Router Admin"', [], True,
    ),
    (
        "401_digest",
        lambda: _make_http_error(401, {"WWW-Authenticate": 'Digest realm="test", nonce="abc"'}),
        401, 'Digest realm="test", nonce="abc"', [], True,
    ),
    (
        "200_no_auth",
        lambda: _make_response(200, body="<html>OK</html>"),
        200, None, [], True,
    ),
    (
        "200_with_cookies",
        lambda: _make_response(200, body="<html>OK</html>", multi_cookies=["PHPSESSID=xyz789", "theme=dark"]),
        200, None, ["PHPSESSID=xyz789", "theme=dark"], True,
    ),
    (
        "200_with_www_authenticate",
        lambda: _make_response(200, body="<html>OK</html>", headers={"WWW-Authenticate": "Negotiate"}),
        200, "Negotiate", [], True,
    ),
    (
        "set_cookie_capture",
        lambda: _make_http_error(
            401,
            {"WWW-Authenticate": "Basic"},
            multi_cookies=["PHPSESSID=abc123", "lang=en"],
        ),
        401, "Basic", ["PHPSESSID=abc123", "lang=en"], True,
    ),
    (
        "body_preview",
        lambda: _make_http_error(401, {"WWW-Authenticate": "Basic"}, body="<html>Unauthorized</html>"),
        401, "Basic", [], True,
    ),
    (
        "200_cookies_no_get_all",
        lambda: _make_response_no_get_all(200, body="<html>OK</html>", cookie="sid=fallback"),
        200, None, ["sid=fallback"], True,
    ),
    (
        "401_cookies_no_get_all",
        lambda: _make_http_error_no_get_all(401, {"WWW-Authenticate": "Basic"}, cookie="sid=err"),
        401, "Basic", ["sid=err"], True,
    ),
    (
        "connection_error",
        lambda: urllib.error.URLError("Connection refused"),
        None, None, [], False,
    ),
]
# fmt: on

# fmt: off
HEAD_SUPPORT_CASES = [
    # (description, side_effect, expected_supported, expected_status, expected_error_is_none)
    ("head_200",     _make_response(200),                     True,  200,  True),
    ("head_401",     _make_http_error(401),                   True,  401,  True),
    ("head_405",     _make_http_error(405),                   True,  405,  True),
    ("conn_error",   urllib.error.URLError("refused"),         False, None, False),
    ("timeout",      urllib.error.URLError("timed out"),       False, None, False),
]
# fmt: on

# fmt: off
ICMP_CASES = [
    # (description, returncode, stdout, timeout_expired, file_not_found, expected_reachable, expected_latency, expected_error_is_none)
    ("ping_success",         0, "time=2.1 ms",           False, False, True,  2.1,  True),
    ("ping_no_latency",      0, "reply from 192.168.1.1", False, False, True,  None, True),
    ("ping_failure",         1, "",                       False, False, False, None, True),
    ("ping_timeout",         None, None,                  True,  False, False, None, False),
    ("ping_not_found",       None, None,                  False, True,  False, None, False),
]
# fmt: on

# fmt: off
ICMP_PLATFORM_CASES = [
    # (platform, expected_flag)
    ("linux",   "-W"),
    ("darwin",  "-t"),
    ("win32",   "-w"),
]
# fmt: on

# fmt: off
RUN_PROBES_HOSTNAME_CASES = [
    # (url, expected_host)
    ("http://192.168.1.1/",          "192.168.1.1"),
    ("https://router.local:8443/",   "router.local"),
    ("http://example.com/path",      "example.com"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestProbeAuthChallenge:
    """Tests for probe_auth_challenge function."""

    @pytest.mark.parametrize(
        (
            "desc",
            "side_effect_factory",
            "expected_status",
            "expected_www_auth",
            "expected_cookies",
            "expected_error_is_none",
        ),
        AUTH_CHALLENGE_CASES,
        ids=[c[0] for c in AUTH_CHALLENGE_CASES],
    )
    def test_auth_challenge(
        self,
        desc: str,
        side_effect_factory: object,
        expected_status: int | None,
        expected_www_auth: str | None,
        expected_cookies: list[str],
        expected_error_is_none: bool,
    ) -> None:
        """Test auth challenge probe with various server responses."""
        side_effect = side_effect_factory() if callable(side_effect_factory) else side_effect_factory

        with patch.object(
            urllib.request.OpenerDirector,
            "open",
            side_effect=side_effect if isinstance(side_effect, Exception) else None,
        ) as mock_open:
            if not isinstance(side_effect, Exception):
                mock_open.return_value = side_effect

            result = probe_auth_challenge("http://192.168.1.1/", timeout=5)

        assert result["probe"] == "auth_challenge"
        assert result["status_code"] == expected_status
        assert result["www_authenticate"] == expected_www_auth
        if expected_cookies:
            assert result["set_cookie"] == expected_cookies
        if expected_error_is_none:
            assert result["error"] is None
        else:
            assert result["error"] is not None

    def test_body_preview_cap(self) -> None:
        """Test body preview is capped at _BODY_PREVIEW_CAP chars."""
        long_body = "x" * (_BODY_PREVIEW_CAP + 500)
        error = _make_http_error(401, {"WWW-Authenticate": "Basic"}, body=long_body)

        with patch.object(urllib.request.OpenerDirector, "open", side_effect=error):
            result = probe_auth_challenge("http://192.168.1.1/")

        assert len(result["body_preview"]) <= _BODY_PREVIEW_CAP

    def test_https_ssl_context(self) -> None:
        """Test HTTPS URL installs SSL context via HTTPSHandler in build_opener."""
        resp = _make_response(200)

        with (
            patch("urllib.request.build_opener") as mock_build_opener,
            patch.object(urllib.request.OpenerDirector, "open", return_value=resp),
        ):
            mock_build_opener.return_value = urllib.request.OpenerDirector()
            probe_auth_challenge("https://192.168.1.1/")

        # Verify build_opener received an HTTPSHandler with a permissive SSL context
        args = mock_build_opener.call_args[0]
        https_handlers = [a for a in args if isinstance(a, urllib.request.HTTPSHandler)]
        assert https_handlers, f"Expected HTTPSHandler in build_opener args, got {args}"
        assert https_handlers[0]._context.check_hostname is False

    def test_https_no_context_kwarg_to_open(self) -> None:
        """Test HTTPS does NOT pass context kwarg to opener.open() (the original bug)."""
        resp = _make_response(200)

        with patch.object(urllib.request.OpenerDirector, "open", return_value=resp) as mock_open:
            probe_auth_challenge("https://192.168.1.1/")

        # The bug was passing context= to open(); verify it's not there
        assert "context" not in (mock_open.call_args.kwargs or {}), (
            "context kwarg should NOT be passed to OpenerDirector.open()"
        )

    def test_redirect_not_followed(self) -> None:
        """Test 3xx redirect is NOT followed by _NoRedirectHandler."""
        # _NoRedirectHandler suppresses redirects, so a 302 should raise HTTPError
        error_302 = _make_http_error(302, {"Location": "http://192.168.1.1/login"})

        with patch.object(urllib.request.OpenerDirector, "open", side_effect=error_302):
            result = probe_auth_challenge("http://192.168.1.1/")

        assert result["status_code"] == 302
        assert result["error"] is None


class TestProbeHeadSupport:
    """Tests for probe_head_support function."""

    @pytest.mark.parametrize(
        ("desc", "side_effect", "expected_supported", "expected_status", "expected_error_is_none"),
        HEAD_SUPPORT_CASES,
        ids=[c[0] for c in HEAD_SUPPORT_CASES],
    )
    @patch("urllib.request.urlopen")
    def test_head_support(
        self,
        mock_urlopen: MagicMock,
        desc: str,
        side_effect: object,
        expected_supported: bool,
        expected_status: int | None,
        expected_error_is_none: bool,
    ) -> None:
        """Test HEAD support probe with various server responses."""
        if isinstance(side_effect, Exception):
            mock_urlopen.side_effect = side_effect
        else:
            mock_urlopen.return_value = side_effect

        result = probe_head_support("http://192.168.1.1/", timeout=5)

        assert result["probe"] == "head_support"
        assert result["supported"] is expected_supported
        assert result["status_code"] == expected_status
        if expected_error_is_none:
            assert result["error"] is None
        else:
            assert result["error"] is not None


class TestProbeIcmp:
    """Tests for probe_icmp function."""

    @pytest.mark.parametrize(
        (
            "desc",
            "returncode",
            "stdout",
            "timeout_expired",
            "file_not_found",
            "expected_reachable",
            "expected_latency",
            "expected_error_is_none",
        ),
        ICMP_CASES,
        ids=[c[0] for c in ICMP_CASES],
    )
    @patch("subprocess.run")
    def test_icmp(
        self,
        mock_run: MagicMock,
        desc: str,
        returncode: int | None,
        stdout: str | None,
        timeout_expired: bool,
        file_not_found: bool,
        expected_reachable: bool,
        expected_latency: float | None,
        expected_error_is_none: bool,
    ) -> None:
        """Test ICMP probe with various ping outcomes."""
        if timeout_expired:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=5)
        elif file_not_found:
            mock_run.side_effect = FileNotFoundError("ping not found")
        else:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["ping"], returncode=returncode, stdout=stdout or "", stderr=""
            )

        result = probe_icmp("192.168.1.1", timeout=5)

        assert result["probe"] == "icmp"
        assert result["reachable"] is expected_reachable
        assert result["latency_ms"] == expected_latency
        if expected_error_is_none:
            assert result["error"] is None
        else:
            assert result["error"] is not None

    @pytest.mark.parametrize(
        ("platform", "expected_flag"),
        ICMP_PLATFORM_CASES,
        ids=[c[0] for c in ICMP_PLATFORM_CASES],
    )
    @patch("subprocess.run")
    def test_platform_flags(
        self,
        mock_run: MagicMock,
        platform: str,
        expected_flag: str,
    ) -> None:
        """Test platform-specific ping flags."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping"], returncode=0, stdout="time=1.0 ms", stderr=""
        )

        with patch("har_capture.capture.probes.sys") as mock_sys:
            mock_sys.platform = platform
            probe_icmp("192.168.1.1", timeout=5)

        cmd = mock_run.call_args[0][0]
        assert expected_flag in cmd, f"Expected {expected_flag} in {cmd} for {platform}"

    @patch("subprocess.run")
    def test_latency_with_less_than_sign(self, mock_run: MagicMock) -> None:
        """Test latency parsing with 'time<1 ms' format (Windows)."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ping"], returncode=0, stdout="time<1 ms", stderr=""
        )

        result = probe_icmp("192.168.1.1", timeout=5)

        assert result["reachable"] is True
        assert result["latency_ms"] == 1.0


class TestRunProbes:
    """Tests for run_probes orchestrator."""

    @patch("har_capture.capture.probes.probe_icmp")
    @patch("har_capture.capture.probes.probe_head_support")
    @patch("har_capture.capture.probes.probe_auth_challenge")
    def test_all_succeed(
        self,
        mock_auth: MagicMock,
        mock_head: MagicMock,
        mock_icmp: MagicMock,
    ) -> None:
        """Test all probes run and results are assembled."""
        mock_auth.return_value = {"probe": "auth_challenge", "status_code": 401}
        mock_head.return_value = {"probe": "head_support", "supported": True}
        mock_icmp.return_value = {"probe": "icmp", "reachable": True}

        result = run_probes("http://192.168.1.1/")

        assert "ran_at" in result
        assert result["target_url"] == "http://192.168.1.1/"
        assert result["auth_challenge"]["status_code"] == 401
        assert result["head_support"]["supported"] is True
        assert result["icmp"]["reachable"] is True

    @patch("har_capture.capture.probes.probe_icmp")
    @patch("har_capture.capture.probes.probe_head_support")
    @patch("har_capture.capture.probes.probe_auth_challenge")
    def test_partial_failure(
        self,
        mock_auth: MagicMock,
        mock_head: MagicMock,
        mock_icmp: MagicMock,
    ) -> None:
        """Test probes still return results when some fail."""
        mock_auth.return_value = {"probe": "auth_challenge", "error": "connection refused"}
        mock_head.return_value = {"probe": "head_support", "supported": False}
        mock_icmp.return_value = {"probe": "icmp", "reachable": False, "error": "ping not found"}

        result = run_probes("http://192.168.1.1/")

        assert result["auth_challenge"]["error"] == "connection refused"
        assert result["head_support"]["supported"] is False
        assert result["icmp"]["error"] == "ping not found"

    @pytest.mark.parametrize(
        ("url", "expected_host"),
        RUN_PROBES_HOSTNAME_CASES,
        ids=[c[0].split("//")[1].split("/")[0] for c in RUN_PROBES_HOSTNAME_CASES],
    )
    @patch("har_capture.capture.probes.probe_icmp")
    @patch("har_capture.capture.probes.probe_head_support")
    @patch("har_capture.capture.probes.probe_auth_challenge")
    def test_hostname_extraction(
        self,
        mock_auth: MagicMock,
        mock_head: MagicMock,
        mock_icmp: MagicMock,
        url: str,
        expected_host: str,
    ) -> None:
        """Test hostname is correctly extracted from URL for ICMP."""
        mock_auth.return_value = {}
        mock_head.return_value = {}
        mock_icmp.return_value = {}

        run_probes(url)

        mock_icmp.assert_called_once()
        actual_host = mock_icmp.call_args[0][0]
        assert actual_host == expected_host, f"Expected {expected_host}, got {actual_host}"


# =============================================================================
# Integration Tests — real HTTPS server with self-signed cert
# =============================================================================

trustme = pytest.importorskip("trustme", reason="trustme not installed")

_log = logging.getLogger(__name__)


class _ProbeTestHandler(BaseHTTPRequestHandler):
    """Minimal handler for probe integration tests."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress logging."""

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Test Realm"')
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            self.end_headers()
            self.wfile.write(b"<html>Unauthorized</html>")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=authed; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(b"<html>OK</html>")

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()


class _RedirectHandler(BaseHTTPRequestHandler):
    """Handler that always returns 302."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress logging."""

    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1/redirected")
        self.end_headers()


def _start_server(
    handler_class: type,
    ssl_ctx: ssl.SSLContext | None = None,
) -> tuple[HTTPServer, int]:
    """Start a threaded HTTP(S) server on a random port, return (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), handler_class)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


@pytest.fixture(scope="module")
def _tls_context() -> tuple:
    """Create a trustme CA and server SSL context."""
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)
    ca.configure_trust(server_ctx)
    return ca, server_ctx


def _shutdown_quietly(server: HTTPServer) -> None:
    """Shut down a server, suppressing SSL errors from daemon threads."""
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        _log.debug("server shutdown error (expected for TLS)", exc_info=True)


@pytest.fixture(scope="module")
def https_auth_server(_tls_context: tuple) -> str:
    """HTTPS server that returns 401 with WWW-Authenticate: Basic."""
    _ca, server_ctx = _tls_context
    server, port = _start_server(_ProbeTestHandler, ssl_ctx=server_ctx)
    yield f"https://127.0.0.1:{port}/"
    _shutdown_quietly(server)


@pytest.fixture(scope="module")
def http_auth_server() -> str:
    """Plain HTTP server that returns 401 with WWW-Authenticate: Basic."""
    server, port = _start_server(_ProbeTestHandler)
    yield f"http://127.0.0.1:{port}/"
    _shutdown_quietly(server)


@pytest.fixture(scope="module")
def http_redirect_server() -> str:
    """Plain HTTP server that always returns 302."""
    server, port = _start_server(_RedirectHandler)
    yield f"http://127.0.0.1:{port}/"
    _shutdown_quietly(server)


# fmt: off
INTEGRATION_AUTH_CASES = [
    # (description, fixture_name, expected_status, expected_www_auth_contains, expected_error)
    ("http_401_basic",  "http_auth_server",  401, "Basic", None),
    ("https_401_basic", "https_auth_server", 401, "Basic", None),
]
# fmt: on


@pytest.mark.integration
class TestProbeIntegrationHTTPS:
    """Integration tests hitting real local HTTP/HTTPS servers."""

    @pytest.mark.parametrize(
        ("desc", "fixture_name", "expected_status", "expected_www_auth", "expected_error"),
        INTEGRATION_AUTH_CASES,
        ids=[c[0] for c in INTEGRATION_AUTH_CASES],
    )
    def test_auth_challenge_real_server(
        self,
        desc: str,
        fixture_name: str,
        expected_status: int,
        expected_www_auth: str,
        expected_error: str | None,
        request: pytest.FixtureRequest,
    ) -> None:
        """Auth probe captures 401 + WWW-Authenticate from real HTTP/HTTPS servers."""
        url = request.getfixturevalue(fixture_name)
        result = probe_auth_challenge(url, timeout=5)

        assert result["error"] == expected_error, f"Unexpected error: {result['error']}"
        assert result["status_code"] == expected_status
        assert expected_www_auth in (result["www_authenticate"] or "")

    def test_https_captures_cookies(self, https_auth_server: str) -> None:
        """HTTPS auth probe captures Set-Cookie headers."""
        result = probe_auth_challenge(https_auth_server, timeout=5)

        assert result["status_code"] == 401
        assert len(result["set_cookie"]) > 0
        assert any("sid=" in c for c in result["set_cookie"])

    def test_https_captures_body_preview(self, https_auth_server: str) -> None:
        """HTTPS auth probe captures body preview from 401 response."""
        result = probe_auth_challenge(https_auth_server, timeout=5)

        assert "Unauthorized" in result["body_preview"]

    def test_redirect_not_followed(self, http_redirect_server: str) -> None:
        """Auth probe captures 302 status instead of following the redirect."""
        result = probe_auth_challenge(http_redirect_server, timeout=5)

        assert result["status_code"] == 302
        assert result["error"] is None

    def test_head_support_http(self, http_auth_server: str) -> None:
        """HEAD probe works against real HTTP server."""
        result = probe_head_support(http_auth_server, timeout=5)

        assert result["supported"] is True
        assert result["status_code"] is not None

    def test_200_captures_cookies(self, http_auth_server: str) -> None:
        """Auth probe captures Set-Cookie headers from error responses."""
        # probe_auth_challenge sends unauthenticated GET, so _ProbeTestHandler
        # returns 401 with Set-Cookie. Verifies cookie extraction on error path.
        result = probe_auth_challenge(http_auth_server, timeout=5)
        assert result["status_code"] == 401
        assert any("sid=" in c for c in result["set_cookie"])

    def test_head_support_https(self, https_auth_server: str) -> None:
        """HEAD probe works against real HTTPS server with self-signed cert."""
        result = probe_head_support(https_auth_server, timeout=5)

        assert result["supported"] is True
        assert result["status_code"] is not None
        assert result["error"] is None


# =============================================================================
# Table-driven tests for helper functions (fixture data)
# =============================================================================

_PROBES_FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "test_probes.json"
with _PROBES_FIXTURE_PATH.open() as _pf:
    _PROBES_FIXTURES = json.load(_pf)

READ_BODY_PREVIEW_CASES = _PROBES_FIXTURES["read_body_preview_cases"]
HEADERS_DICT_CASES = _PROBES_FIXTURES["headers_dict_cases"]


class TestReadBodyPreview:
    """Table-driven tests for _read_body_preview helper."""

    @pytest.mark.parametrize(
        "case",
        READ_BODY_PREVIEW_CASES,
        ids=[c["id"] for c in READ_BODY_PREVIEW_CASES],
    )
    def test_read_body_preview(self, case: dict) -> None:
        """Test _read_body_preview with various file-pointer states."""
        if case.get("fp") is None and "fp_bytes" not in case and "fp_str" not in case:
            result = _read_body_preview(None)
        elif case.get("fp_raises"):
            fp = MagicMock()
            fp.read.side_effect = OSError("read failed")
            result = _read_body_preview(fp)
        elif "fp_bytes" in case:
            result = _read_body_preview(BytesIO(case["fp_bytes"].encode()))
        elif "fp_str" in case:
            fp = MagicMock()
            fp.read.return_value = case["fp_str"]
            result = _read_body_preview(fp)
        else:
            result = _read_body_preview(None)

        assert result == case["expect"]

    def test_truncation_at_cap(self) -> None:
        """Test body is truncated at _BODY_PREVIEW_CAP."""
        long_body = "x" * (_BODY_PREVIEW_CAP + 500)
        fp = MagicMock()
        fp.read.return_value = long_body
        result = _read_body_preview(fp)
        assert len(result) == _BODY_PREVIEW_CAP


class TestHeadersDict:
    """Table-driven tests for _headers_dict helper."""

    @pytest.mark.parametrize(
        "case",
        HEADERS_DICT_CASES,
        ids=[c["id"] for c in HEADERS_DICT_CASES],
    )
    def test_headers_dict(self, case: dict) -> None:
        """Test _headers_dict with various header objects."""
        if case.get("headers") is None and not case.get("items_raises"):
            result = _headers_dict(None)
        elif case.get("items_raises"):
            mock_headers = MagicMock()
            mock_headers.items.side_effect = AttributeError("no items")
            result = _headers_dict(mock_headers)
        else:
            mock_headers = MagicMock()
            mock_headers.items.return_value = list(case["headers"].items())
            result = _headers_dict(mock_headers)

        assert result == case["expect"]
