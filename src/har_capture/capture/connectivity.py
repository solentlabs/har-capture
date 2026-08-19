"""Target connectivity checking utilities.

This module provides functions to check target reachability and authentication
requirements before launching the browser capture.

Protocol detection (``detect_protocol`` and helpers) is adapted from
``cable_modem_monitor_core/connectivity.py`` — both projects are owned
by solentlabs; the code is duplicated rather than shared so har-capture
can keep its stdlib-only runtime (CMM Core depends on requests/urllib3,
and har-capture must not pull playwright into CMM).
"""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from har_capture.capture.probes import make_ssl_context

_LOGGER = logging.getLogger(__name__)

_DEFAULT_DETECT_TIMEOUT = 5.0

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

    Thin compatibility wrapper around :func:`_strip_protocol` for callers
    that want the ``(host, scheme)`` tuple shape (browser.py, workflow.py).
    New code in this module should call ``_strip_protocol`` directly to
    avoid the internal transposition. Recognizes only ``http``/``https``
    as schemes; other schemes (``ftp://`` etc.) are returned as the bare
    string with ``scheme=None`` since har-capture cannot capture them.

    Handles various input formats:
    - Full URL: "https://example.com" -> ("example.com", "https")
    - URL with path: "https://example.com/page" -> ("example.com", "https")
    - Hostname only: "example.com" -> ("example.com", None)
    - IP address: "192.168.1.1" -> ("192.168.1.1", None)
    - IP with port: "192.168.1.1:8080" -> ("192.168.1.1:8080", None)
    - IPv6 address: "[::1]" -> ("[::1]", None)
    - IPv6 URL: "https://[::1]:8443/page" -> ("[::1]:8443", "https")
    """
    scheme, host = _strip_protocol(target)
    return host, scheme


def target_path(target: str) -> str:
    """Return the path portion of a capture target, or ``""`` if none.

    Capture always starts at the device root — ``_strip_protocol`` drops
    any path from the target. This helper exists so the CLI can *tell*
    the user that happened instead of silently capturing the wrong page
    (a target of ``https://host/DocsisStatus.htm`` cost a wasted CM2500
    capture run on 2026-08-19). A bare trailing slash is not a path.
    """
    lower = target.lower()
    for prefix in ("http://", "https://"):
        if lower.startswith(prefix):
            target = target[len(prefix) :]
            break
    _, _, path = target.partition("/")
    return f"/{path}" if path else ""


# ---------------------------------------------------------------------------
# Protocol detection — adapted from cable_modem_monitor_core/connectivity.py
# ---------------------------------------------------------------------------

# Permissive cipher string for the probe handshake. ``SECLEVEL=0`` disables
# OpenSSL security-level checks, permitting legacy ciphers (3DES, RC4) and
# protocol versions (TLS 1.0/1.1) that older device firmware requires. The
# probe's job is to confirm HTTPS is reachable so the *browser* drives the
# session — har-capture cannot act on TLS-version classification (Chromium
# has its own stack), so we don't classify, we just complete.
_LEGACY_CIPHERS = "DEFAULT:@SECLEVEL=0"


@dataclass
class ProtocolDetectionResult:
    """Result of :func:`detect_protocol`.

    Attributes:
        success: True if the target responded on at least one transport.
        protocol: ``"http"`` or ``"https"`` — whichever was selected.
        working_url: Full URL that responded (e.g. ``https://192.168.100.1``).
        error: Human-readable message when ``success`` is False.
    """

    success: bool
    protocol: str | None = None
    working_url: str | None = None
    error: str | None = None


def _strip_protocol(host: str) -> tuple[str | None, str]:
    """Split an optional protocol prefix from a host string.

    Scheme matching is case-insensitive (``HTTPS://...`` is recognized
    same as ``https://...``) — RFC 3986 makes the scheme component
    case-insensitive, and capture targets pasted from documentation
    should not silently fall through to bare-hostname auto-detection.

    Returns ``(protocol, bare_host)``. ``protocol`` is ``"http"`` or
    ``"https"`` if the input had a prefix, else None. ``bare_host``
    may still include a ``:port`` suffix and preserves the original
    case of the host portion.
    """
    lower = host.lower()
    for prefix, name in (("http://", "http"), ("https://", "https")):
        if lower.startswith(prefix):
            bare = host[len(prefix) :].split("/", 1)[0]
            return (name, bare)
    return (None, host.split("/", 1)[0])


def _split_host_port(host: str) -> tuple[str, int | None]:
    """Split ``host:port`` into ``(hostname, port)``.

    Returns ``(host, None)`` when the input has no port suffix.
    Bracketed IPv6 literals (``[::1]:8080``) are handled — the bracket
    form is the only safe way to disambiguate IPv6 from a bare
    ``host:port`` colon.
    """
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            return (host, None)
        hostname = host[1:end]
        tail = host[end + 1 :]
        if tail.startswith(":") and tail[1:].isdigit():
            return (hostname, int(tail[1:]))
        return (hostname, None)
    if ":" in host:
        head, _, tail = host.rpartition(":")
        if tail.isdigit():
            return (head, int(tail))
    return (host, None)


def _tcp_probe(
    host: str,
    port: int,
    timeout: float,
    *,
    address_family: int = socket.AF_INET,
) -> bool:
    """Return True if ``host:port`` accepts a TCP connection.

    Defaults to IPv4 — most consumer devices are IPv4-only on the LAN
    side, and a dual-stack ``getaddrinfo`` may otherwise return IPv6
    first and false-fail the probe before falling back to v4. The
    caller passes ``address_family=socket.AF_INET6`` when the input is
    explicit IPv6 (a bracketed literal like ``[::1]:8443``) so we don't
    silently drop captures of IPv6-only targets — capture-everything
    over false-fail.
    """
    try:
        infos = socket.getaddrinfo(host, port, family=address_family, type=socket.SOCK_STREAM)
    except OSError as exc:
        _LOGGER.debug("TCP probe %s:%d — address resolution failed: %s", host, port, exc)
        return False

    for family, socktype, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return True
        except (OSError, TimeoutError) as exc:
            _LOGGER.debug("TCP probe %s:%d failed: %s", host, port, exc)
        finally:
            sock.close()
    return False


def _tls_handshake(host: str, port: int, timeout: float) -> bool:
    """Open a TLS connection with broad ciphers and report whether it completed.

    Uses a ``SECLEVEL=0`` cipher context so the handshake succeeds against
    legacy devices (TLS 1.0/1.1, 3DES/RC4 ciphers). Without this tolerance,
    we'd fail the probe on old modems and incorrectly fall back to HTTP —
    the inverse of the CM1200 trap. The negotiated version is logged for
    diagnostics but not classified, since har-capture cannot act on it
    (Chromium runs its own TLS stack).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers(_LEGACY_CIPHERS)

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw_sock,
            context.wrap_socket(raw_sock, server_hostname=host) as tls_sock,
        ):
            _LOGGER.info(
                "TLS probe %s:%d — negotiated %s",
                host,
                port,
                tls_sock.version() or "unknown",
            )
            return True
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        _LOGGER.debug("TLS handshake to %s:%d failed: %s", host, port, exc)
        return False


def detect_protocol(
    host: str,
    *,
    timeout: float = _DEFAULT_DETECT_TIMEOUT,
) -> ProtocolDetectionResult:
    """Detect the working protocol for a target.

    Probes TCP ``:80`` and ``:443``. If ``:443`` accepts connections
    *and* completes a TLS handshake, prefers HTTPS — devices that
    expose both ports almost always intend HTTPS for authenticated
    traffic, and ``:80`` is typically a redirect or legacy stub.

    If *host* already includes a protocol prefix (``http://`` or
    ``https://``), only that transport is probed — the user has
    explicitly chosen.

    Args:
        host: IP address, hostname, or full URL.
        timeout: Per-probe timeout in seconds (applied to each TCP
            probe and the TLS handshake separately).

    Returns:
        :class:`ProtocolDetectionResult` describing the chosen transport.
    """
    explicit_protocol, bare_host = _strip_protocol(host)
    # Bracketed input (``[::1]``, ``[fe80::1]:8443``) is the user's explicit
    # IPv6 signal — keep the IPv4 pin for everything else so dual-stack
    # ``getaddrinfo`` doesn't false-fail on consumer LAN devices that only
    # answer on v4. ``socket.create_connection`` inside ``_tls_handshake``
    # already handles both families via its default unspecified resolution.
    address_family = socket.AF_INET6 if bare_host.startswith("[") else socket.AF_INET
    hostname, port_override = _split_host_port(bare_host)
    http_port = port_override or 80
    https_port = port_override or 443
    url_host = bare_host  # preserves any user-supplied :port

    _LOGGER.info(
        "Protocol detection: probing %s%s",
        url_host,
        f" (user-specified {explicit_protocol})" if explicit_protocol else "",
    )

    http_open = False
    if explicit_protocol in (None, "http"):
        http_open = _tcp_probe(hostname, http_port, timeout, address_family=address_family)

    https_open = False
    if explicit_protocol in (None, "https") and _tcp_probe(
        hostname, https_port, timeout, address_family=address_family
    ):
        https_open = _tls_handshake(hostname, https_port, timeout)

    if https_open:
        url = f"https://{url_host}"
        _LOGGER.info("Protocol detection: HTTPS reachable — using %s", url)
        return ProtocolDetectionResult(
            success=True,
            protocol="https",
            working_url=url,
        )
    if http_open:
        url = f"http://{url_host}"
        _LOGGER.info("Protocol detection: HTTP reachable — using %s", url)
        return ProtocolDetectionResult(
            success=True,
            protocol="http",
            working_url=url,
        )

    tried = (
        f"TCP {hostname}:{http_port}"
        if explicit_protocol == "http"
        else (
            f"TCP {hostname}:{https_port} (TLS handshake)"
            if explicit_protocol == "https"
            else f"TCP {hostname}:{http_port} and {hostname}:{https_port}"
        )
    )
    return ProtocolDetectionResult(
        success=False,
        error=f"Cannot connect to {url_host}. Tried: {tried}.",
    )


def check_device_connectivity(target: str, timeout: int = 5) -> tuple[bool, str, str | None]:
    """Check if target is reachable.

    Accepts a URL with an explicit scheme (``http://``/``https://``) or a
    bare hostname/IP. When the scheme is omitted, runs :func:`detect_protocol`
    to choose between HTTP and HTTPS by probing TCP :80 and :443 — preferring
    HTTPS when its TLS handshake completes. This closes the contributor trap
    where guessing HTTP misses an HTTPS-only auth challenge.

    Args:
        target: URL with scheme, bare hostname/IP, or ``host:port``.
        timeout: Connection timeout in seconds.

    Returns:
        Tuple of (reachable, scheme, error_message)
        - reachable: True if target responded
        - scheme: "http" or "https" (empty string when unreachable and unknown)
        - error_message: None if reachable, otherwise describes the problem
    """
    host, provided_scheme = _parse_target(target)

    if provided_scheme not in ("http", "https"):
        # No scheme — auto-detect via TCP/TLS probes.
        detection = detect_protocol(target, timeout=float(timeout))
        if not detection.success:
            return False, "", detection.error
        scheme = detection.protocol or ""
        # detect_protocol guarantees working_url is set when success=True.
        # Fall through to the HTTP-level reachability confirmation so
        # callers continue to see HTTPError-as-reachable behavior.
        working_url = detection.working_url or ""
        host = working_url.removeprefix("https://").removeprefix("http://")
    else:
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
