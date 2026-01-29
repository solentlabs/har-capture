"""Device connectivity checking utilities.

This module provides functions to check device reachability and authentication
requirements before launching the browser capture.
"""

from __future__ import annotations

import logging
import ssl
import urllib.error
import urllib.request

_LOGGER = logging.getLogger(__name__)


def check_device_connectivity(ip: str, timeout: int = 5) -> tuple[bool, str, str | None]:
    """Check if device is reachable and determine the correct URL scheme.

    Tries HTTP first, then HTTPS if HTTP fails.

    Args:
        ip: Device IP address
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (reachable, scheme, error_message)
        - reachable: True if device responded
        - scheme: "http" or "https"
        - error_message: None if reachable, otherwise describes the problem
    """
    for scheme in ["http", "https"]:
        url = f"{scheme}://{ip}/"
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
            # HTTP error means device is reachable (might need auth, that's fine)
            return True, scheme, None
        except urllib.error.URLError as e:
            # Connection refused, timeout, etc - try next scheme
            if scheme == "https":
                return False, "http", f"Cannot connect to device at {ip}: {e.reason}"
        except Exception as e:
            if scheme == "https":
                return False, "http", f"Cannot connect to device at {ip}: {e}"

    return False, "http", f"Cannot connect to device at {ip}"


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
