"""Target connectivity checking utilities.

This module provides functions to check target reachability and authentication
requirements before launching the browser capture.
"""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from har_capture.capture.probes import make_ssl_context

_LOGGER = logging.getLogger(__name__)

# Response body indicators that a login/authentication page is being served.
# If none of these appear in a 200 response, the device likely has a live
# session and is serving authenticated content without requiring login.
_LOGIN_PAGE_INDICATORS = (
    b"password",
    b"login",
    b"sign in",
    b"signin",
    b"log in",
    b"authenticate",
)


def _urlopen_with_ssl(
    url: str,
    timeout: int = 5,
    method: str = "GET",
) -> Any:
    """Make an HTTP(S) request, accepting self-signed certificates.

    Args:
        url: Target URL (http:// or https://)
        timeout: Connection timeout in seconds
        method: HTTP method

    Returns:
        The HTTP response object.

    Raises:
        urllib.error.HTTPError: On HTTP-level errors (401, 403, etc.)
        urllib.error.URLError: On connection-level errors
    """
    req = urllib.request.Request(url, method=method)
    if url.startswith("https://"):
        ctx = make_ssl_context()
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    return urllib.request.urlopen(req, timeout=timeout)


def _parse_target(target: str) -> tuple[str, str | None]:
    """Parse a target string into hostname and optional scheme.

    Handles various input formats:
    - Full URL: "https://example.com" -> ("example.com", "https")
    - URL with path: "https://example.com/page" -> ("example.com", "https")
    - Hostname only: "example.com" -> ("example.com", None)
    - IP address: "192.168.1.1" -> ("192.168.1.1", None)
    - IP with port: "192.168.1.1:8080" -> ("192.168.1.1:8080", None)
    - IPv6 address: "[::1]" -> ("[::1]", None)
    - IPv6 URL: "https://[::1]:8443/page" -> ("[::1]:8443", "https")

    Args:
        target: URL, hostname, or IP address

    Returns:
        Tuple of (hostname_with_port, scheme_or_none)
    """
    # Check if it looks like a URL (has scheme)
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path.split("/")[0]
        return host, parsed.scheme
    # No scheme - return as-is
    return target, None


def check_device_connectivity(target: str, timeout: int = 5) -> tuple[bool, str, str | None]:
    """Check if target is reachable.

    Requires a URL with an explicit scheme (http:// or https://).

    Args:
        target: URL with scheme (e.g., "http://192.168.1.1", "https://example.com")
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (reachable, scheme, error_message)
        - reachable: True if target responded
        - scheme: "http" or "https"
        - error_message: None if reachable, otherwise describes the problem
    """
    # Parse target to extract hostname and scheme
    host, provided_scheme = _parse_target(target)

    if provided_scheme not in ("http", "https"):
        return (
            False,
            "",
            f"Missing scheme for '{target}'. Use http:// or https:// (e.g., http://{target})",
        )

    scheme = provided_scheme
    url = f"{scheme}://{host}/"
    try:
        _urlopen_with_ssl(url, timeout=timeout)
        return True, scheme, None
    except urllib.error.HTTPError:
        # HTTP error means target is reachable (might need auth, that's fine)
        return True, scheme, None
    except urllib.error.URLError as e:
        return False, scheme, f"Cannot connect to {host}: {e.reason}"
    except Exception as e:
        return False, scheme, f"Cannot connect to {host}: {e}"


def check_basic_auth(url: str, timeout: int = 5) -> tuple[bool, str | None]:
    """Check if URL requires HTTP Basic Authentication.

    Args:
        url: URL to check
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (requires_basic_auth, realm_name)
    """
    try:
        _urlopen_with_ssl(url, timeout=timeout)
        return False, None  # No auth required
    except urllib.error.HTTPError as e:
        if e.code == 401:
            auth_header = e.headers.get("WWW-Authenticate", "")
            if auth_header.lower().startswith("basic"):
                # Extract realm if present
                realm = None
                if 'realm="' in auth_header:
                    realm = auth_header.split('realm="')[1].split('"')[0]
                elif "realm=" in auth_header:
                    realm = auth_header.split("realm=")[1].split()[0]
                return True, realm
        return False, None
    except Exception:
        return False, None


def check_session_contamination(url: str, timeout: int = 5) -> tuple[bool, str | None]:
    """Check if the target has a live session that would skip the login flow.

    Makes an unauthenticated GET and inspects the response.  If the device
    returns 200 with data content (no login-page indicators), it means a
    previous session is still active — the capture would miss the auth flow.

    Args:
        url: Target URL with scheme (e.g., ``http://192.168.100.1/``)
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (contaminated, message).
        *contaminated* is ``True`` when the device appears to have a live
        session.  *message* contains a human-readable warning.
    """
    try:
        resp = _urlopen_with_ssl(url, timeout=timeout)

        # Non-200 → auth challenge or redirect → clean state
        if resp.status != 200:
            return False, None

        body = resp.read(4096).lower()

        # If the body contains login-page indicators, the device is
        # presenting a login form → no live session.  Check keywords
        # before the size threshold so small JS-shell login pages
        # (e.g. <html><script src=/app.js></script>) are caught.
        for indicator in _LOGIN_PAGE_INDICATORS:
            if indicator in body:
                return False, None

        # Empty or tiny response → redirect stub or placeholder
        if len(body) < 100:
            return False, None

        # 200 with substantial content and no login indicators → live session
        return True, (
            "Browser has a live session \u2014 clear cookies or use a clean "
            "profile. The device returned data content without requiring login."
        )
    except urllib.error.HTTPError:
        # 401/403/etc. → auth required → clean state
        return False, None
    except Exception:
        # Network errors, timeouts → can't determine, don't block capture
        return False, None
