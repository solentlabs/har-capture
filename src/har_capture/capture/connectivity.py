"""Target connectivity checking utilities.

This module provides functions to check target reachability and authentication
requirements before launching the browser capture.
"""

from __future__ import annotations

import logging
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

_LOGGER = logging.getLogger(__name__)


def _parse_target(target: str) -> tuple[str, str | None]:
    """Parse a target string into hostname and optional scheme.

    Handles various input formats:
    - Full URL: "https://example.com" -> ("example.com", "https")
    - URL with path: "https://example.com/page" -> ("example.com", "https")
    - Hostname only: "example.com" -> ("example.com", None)
    - IP address: "192.168.1.1" -> ("192.168.1.1", None)
    - IP with port: "192.168.1.1:8080" -> ("192.168.1.1:8080", None)

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
    """Check if target is reachable and determine the correct URL scheme.

    Tries the provided scheme first (if any), otherwise tries HTTP then HTTPS.

    Args:
        target: URL, hostname, or IP address (e.g., "example.com", "https://example.com", "192.168.1.1")
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (reachable, scheme, error_message)
        - reachable: True if target responded
        - scheme: "http" or "https"
        - error_message: None if reachable, otherwise describes the problem
    """
    # Parse target to extract hostname and any provided scheme
    host, provided_scheme = _parse_target(target)

    # Determine which schemes to try
    if provided_scheme in ("http", "https"):
        schemes_to_try = [provided_scheme]
    else:
        schemes_to_try = ["http", "https"]

    last_error: str | None = None

    for scheme in schemes_to_try:
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, method="GET")
            if scheme == "https":
                # Allow self-signed certs
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                urllib.request.urlopen(req, timeout=timeout, context=ctx)
            else:
                urllib.request.urlopen(req, timeout=timeout)
            return True, scheme, None
        except urllib.error.HTTPError:
            # HTTP error means target is reachable (might need auth, that's fine)
            return True, scheme, None
        except urllib.error.URLError as e:
            # Connection refused, timeout, etc - try next scheme
            last_error = str(e.reason)
        except Exception as e:
            last_error = str(e)

    return False, schemes_to_try[0], f"Cannot connect to {host}: {last_error}"


def check_basic_auth(url: str, timeout: int = 5) -> tuple[bool, str | None]:
    """Check if URL requires HTTP Basic Authentication.

    Args:
        url: URL to check
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (requires_basic_auth, realm_name)
    """
    try:
        req = urllib.request.Request(url, method="GET")
        # Handle HTTPS with self-signed certs
        if url.startswith("https://"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            urllib.request.urlopen(req, timeout=timeout, context=ctx)
        else:
            urllib.request.urlopen(req, timeout=timeout)
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
