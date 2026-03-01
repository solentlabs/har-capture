"""Pre-capture diagnostic probes.

Runs unauthenticated HTTP and ICMP probes before the Playwright session
to capture auth challenge headers, HEAD support, and ICMP reachability.
Results are stored as ``log._probes`` metadata in the HAR output.
"""

from __future__ import annotations

import logging
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

_LOGGER = logging.getLogger(__name__)

_BODY_PREVIEW_CAP = 1024


# =============================================================================
# Helpers
# =============================================================================


def _make_ssl_context() -> ssl.SSLContext:
    """Create an SSL context that accepts self-signed certificates."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Suppress urllib's default redirect following."""

    def redirect_request(
        self,
        req: urllib.request.Request,  # noqa: ARG002
        fp: Any,  # noqa: ARG002
        code: int,  # noqa: ARG002
        msg: str,  # noqa: ARG002
        headers: Any,  # noqa: ARG002
        newurl: str,  # noqa: ARG002
    ) -> None:
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    """Build a urllib opener that does not follow redirects."""
    return urllib.request.build_opener(_NoRedirectHandler)


def _read_body_preview(fp: Any) -> str:
    """Read up to _BODY_PREVIEW_CAP chars from a file-like response body."""
    if fp is None:
        return ""
    try:
        raw = fp.read(_BODY_PREVIEW_CAP + 256)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return raw[:_BODY_PREVIEW_CAP]
    except Exception:
        return ""


def _headers_dict(headers: Any) -> dict[str, str]:
    """Convert an http.client.HTTPMessage to a plain dict."""
    if headers is None:
        return {}
    try:
        return dict(headers.items())
    except Exception:
        return {}


# =============================================================================
# Probe functions
# =============================================================================


def probe_auth_challenge(url: str, timeout: int = 10) -> dict[str, Any]:
    """Send an unauthenticated GET to capture the server's auth challenge.

    Args:
        url: Target URL to probe.
        timeout: Request timeout in seconds.

    Returns:
        Dict with keys: probe, timestamp, status_code, www_authenticate,
        set_cookie, headers, body_preview, error.
    """
    result: dict[str, Any] = {
        "probe": "auth_challenge",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "status_code": None,
        "www_authenticate": None,
        "set_cookie": [],
        "headers": {},
        "body_preview": "",
        "error": None,
    }

    opener = _build_opener()
    req = urllib.request.Request(url, method="GET")  # noqa: S310

    try:
        kwargs: dict[str, Any] = {"timeout": timeout}
        if url.startswith("https://"):
            kwargs["context"] = _make_ssl_context()
        resp = opener.open(req, **kwargs)
        result["status_code"] = resp.status
        result["headers"] = _headers_dict(resp.headers)
        result["body_preview"] = _read_body_preview(resp)
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["headers"] = _headers_dict(e.headers)
        result["www_authenticate"] = e.headers.get("WWW-Authenticate") if e.headers else None
        if e.headers:
            try:
                result["set_cookie"] = e.headers.get_all("Set-Cookie") or []
            except AttributeError:
                val = e.headers.get("Set-Cookie")
                result["set_cookie"] = [val] if val else []
        result["body_preview"] = _read_body_preview(e.fp)
    except Exception as e:
        result["error"] = str(e)

    return result


def probe_head_support(url: str, timeout: int = 10) -> dict[str, Any]:
    """Send a HEAD request to check if the server supports it.

    Args:
        url: Target URL to probe.
        timeout: Request timeout in seconds.

    Returns:
        Dict with keys: probe, timestamp, supported, status_code, headers, error.
    """
    result: dict[str, Any] = {
        "probe": "head_support",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "supported": False,
        "status_code": None,
        "headers": {},
        "error": None,
    }

    req = urllib.request.Request(url, method="HEAD")  # noqa: S310

    try:
        kwargs: dict[str, Any] = {"timeout": timeout}
        if url.startswith("https://"):
            kwargs["context"] = _make_ssl_context()
        resp = urllib.request.urlopen(req, **kwargs)  # noqa: S310
        result["supported"] = True
        result["status_code"] = resp.status
        result["headers"] = _headers_dict(resp.headers)
    except urllib.error.HTTPError as e:
        result["supported"] = True
        result["status_code"] = e.code
        result["headers"] = _headers_dict(e.headers)
    except Exception as e:
        result["supported"] = False
        result["error"] = str(e)

    return result


def probe_icmp(host: str, timeout: int = 5) -> dict[str, Any]:
    """Send a single ICMP ping to check host reachability.

    Args:
        host: Hostname or IP address (no scheme/port).
        timeout: Ping timeout in seconds.

    Returns:
        Dict with keys: probe, timestamp, reachable, latency_ms, error.
    """
    result: dict[str, Any] = {
        "probe": "icmp",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "reachable": False,
        "latency_ms": None,
        "error": None,
    }

    # Build platform-specific ping command
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-t", str(timeout), host]
    else:
        # Linux and other POSIX
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        proc = subprocess.run(  # noqa: S603, PLW1510
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        if proc.returncode == 0:
            result["reachable"] = True
            # Parse latency from stdout
            match = re.search(r"time[=<](\d+\.?\d*)\s*ms", proc.stdout)
            if match:
                result["latency_ms"] = float(match.group(1))
        else:
            result["reachable"] = False
    except subprocess.TimeoutExpired:
        result["error"] = "ping timed out"
    except FileNotFoundError:
        result["error"] = "ping command not found"
    except Exception as e:
        result["error"] = str(e)

    return result


# =============================================================================
# Orchestrator
# =============================================================================


def run_probes(url: str, timeout: int = 10) -> dict[str, Any]:
    """Run all pre-capture diagnostic probes.

    Args:
        url: Target URL to probe.
        timeout: Timeout for HTTP probes (ICMP uses timeout // 2).

    Returns:
        Dict with keys: ran_at, target_url, auth_challenge, head_support, icmp.
    """
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or url

    return {
        "ran_at": datetime.now(tz=timezone.utc).isoformat(),
        "target_url": url,
        "auth_challenge": probe_auth_challenge(url, timeout=timeout),
        "head_support": probe_head_support(url, timeout=timeout),
        "icmp": probe_icmp(host, timeout=max(1, timeout // 2)),
    }
