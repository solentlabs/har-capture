"""Tests for pre-capture diagnostic probes.

Test Coverage:
    - Auth challenge probe (401 Basic, 401 Digest, 200, Set-Cookie, body preview, errors)
    - HEAD support probe (200, 401, 405, connection error, timeout)
    - ICMP probe (success, no latency, failure, timeout, command not found, platform flags)
    - run_probes orchestrator (all succeed, partial failure, hostname extraction)

Test Strategy:
    - Table-driven with @pytest.mark.parametrize
    - Mocked urllib and subprocess to avoid real network/system calls
"""

from __future__ import annotations

import subprocess
import urllib.error
import urllib.request
from http.client import HTTPMessage
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.probes import (
    _BODY_PREVIEW_CAP,
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


def _make_response(status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> MagicMock:
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status = status
    msg = HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v
    resp.headers = msg
    resp.read.return_value = body.encode("utf-8")
    return resp


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
        """Test HTTPS URL uses SSL context for self-signed certs."""
        resp = _make_response(200)

        with patch.object(urllib.request.OpenerDirector, "open", return_value=resp) as mock_open:
            probe_auth_challenge("https://192.168.1.1/")

        # Verify context kwarg was passed
        call_kwargs = mock_open.call_args
        # The open call may have positional or keyword args; check for context
        assert any(hasattr(arg, "check_hostname") for arg in (call_kwargs.args or [])) or "context" in (
            call_kwargs.kwargs or {}
        )


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
