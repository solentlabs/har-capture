"""Consolidated redaction checking logic.

This module provides a single source of truth for determining if a value
has been redacted or sanitized. It combines pattern matching from both
configuration files and code-based patterns.

Also provides shared detection helpers used by both sanitization and
validation modules.
"""

from __future__ import annotations

import base64
import logging
import re
import urllib.parse
from typing import Any, NamedTuple

from .loader import load_allowlist

_LOGGER = logging.getLogger(__name__)


def _check_patterns(value: str, allowlist: dict[str, Any]) -> bool:
    """Check if a value matches any pattern in the allowlist.

    Args:
        value: Value to check
        allowlist: Allowlist configuration data

    Returns:
        True if value matches any pattern
    """
    # Check static placeholders (exact matches)
    static = allowlist.get("static_placeholders", {})
    if value in static.get("values", []):
        return True

    # Check hash prefixes (e.g., DEVICE_xxxxxxxx)
    prefixes = allowlist.get("hash_prefixes", {})
    for prefix in prefixes.get("values", []):
        if value.startswith(prefix):
            return True

    # Check format-preserving patterns (e.g., 02:xx:xx:xx:xx:xx MACs)
    format_patterns = allowlist.get("format_preserving_patterns", {})
    for pattern_def in format_patterns.values():
        if isinstance(pattern_def, dict) and "pattern" in pattern_def:
            try:
                if re.match(pattern_def["pattern"], value, re.IGNORECASE):
                    return True
            except re.error:
                _LOGGER.warning("Skipping invalid format-preserving regex pattern")

    # Check additional redaction patterns (skip invalid patterns gracefully)
    redacted_patterns = allowlist.get("redaction_patterns", {})
    for pattern in redacted_patterns.get("values", []):
        try:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        except re.error:  # noqa: PERF203 - must check each pattern individually
            _LOGGER.warning("Skipping invalid regex pattern in allowlist")
    return False


def is_redacted(value: str, custom_patterns: str | dict[str, Any] | None = None) -> bool:
    """Check if a value appears to be properly redacted.

    This function checks if a value matches:
    1. Standard redaction patterns (from allowlist.json)
    2. Format-preserving hash patterns (from allowlist.json)
    3. Hash prefix patterns (from allowlist.json)
    4. Static placeholder values (from allowlist.json)

    Args:
        value: Value to check
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if value appears to be redacted

    Examples:
        >>> is_redacted("[REDACTED]")
        True
        >>> is_redacted("DEVICE_a1b2c3d4")
        True
        >>> is_redacted("my_password")
        False
    """
    allowlist = load_allowlist(custom_patterns)
    return _check_patterns(value, allowlist)


# A redaction placeholder is one opaque token: alphanumerics plus the punctuation
# the placeholder formats actually use (`PASS_a1b2c3d4`, `XX:XX:XX:XX:XX:XX`,
# `user_x@redacted.invalid`, `***SERIAL***`, `[REDACTED]`, `2001:db8::1`).
# Structural punctuation — braces, quotes, semicolons, equals — means the string
# is a document, not a placeholder.
_PLACEHOLDER_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-.:@\[\]*/]+")


def is_fully_redacted(value: str, custom_patterns: str | dict[str, Any] | None = None) -> bool:
    """Check if a string is *entirely* a redaction placeholder.

    :func:`is_redacted` answers "does this value look redacted", and the
    allowlist families backing it are matched with :func:`re.search` — correct
    for a single field value, wrong for a whole document. A minified CSS body
    carrying ``#000000``, a JSON body with ``"ver":"0.000000"``, or any body
    containing the literal ``XXX`` would otherwise report as fully redacted and
    skip every check the caller meant to run.

    This predicate requires the whole string to be one placeholder token: no
    whitespace, no markup, no structural punctuation, and a match that accounts
    for the entire token rather than appearing somewhere inside it.

    Args:
        value: String to check
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if the whole string is a redaction placeholder

    Examples:
        >>> is_fully_redacted("[REDACTED]")
        True
        >>> is_fully_redacted("body{color:#000000}")
        False
        >>> is_fully_redacted("<p>hunter2</p>")
        False
    """
    stripped = value.strip()
    if not stripped or "<" in stripped or not _PLACEHOLDER_TOKEN_RE.fullmatch(stripped):
        return False

    allowlist = load_allowlist(custom_patterns)

    if stripped in allowlist.get("static_placeholders", {}).get("values", []):
        return True

    # A hash prefix must account for the whole token, not just start it —
    # `PASS_a1b2c3d4somethingelse` is not a placeholder.
    for prefix in allowlist.get("hash_prefixes", {}).get("values", []):
        if re.fullmatch(re.escape(prefix) + r"\w+", stripped):
            return True

    # Format-preserving patterns describe single-value formats and are
    # deliberately one-sided (an IPv6 documentation *prefix*, an email
    # *suffix*), so neither end can be anchored here. The token-class guard
    # above is what stops a document from reaching this point.
    format_patterns = allowlist.get("format_preserving_patterns", {})
    for pattern_def in format_patterns.values():
        if isinstance(pattern_def, dict) and "pattern" in pattern_def:
            try:
                if re.search(pattern_def["pattern"], stripped, re.IGNORECASE):
                    return True
            except re.error:
                _LOGGER.warning("Skipping invalid format-preserving regex pattern")

    # These are the unanchored ones (`XXX+`, `0{6,}`, `REDACTED`) — they must
    # consume the entire token here, not merely appear within it.
    for pattern in allowlist.get("redaction_patterns", {}).get("values", []):
        try:
            if re.fullmatch(pattern, stripped, re.IGNORECASE):
                return True
        except re.error:  # noqa: PERF203 - must check each pattern individually
            _LOGGER.warning("Skipping invalid regex pattern in allowlist")

    return False


def is_allowlisted(value: str, allowlist: dict[str, Any] | None = None) -> bool:
    """Check if a value is in the allowlist.

    This is a wrapper around is_redacted() that accepts a pre-loaded allowlist.
    Maintained for backward compatibility.

    Args:
        value: Value to check
        allowlist: Allowlist data (loads default if None)

    Returns:
        True if the value should be ignored
    """
    if allowlist is None:
        return is_redacted(value)

    return _check_patterns(value, allowlist)


# ── Shared detection helpers ─────────────────────────────────────────────────

# Base64 charset pattern for quick pre-filtering
_BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# Reserved Set-Cookie attribute names (RFC 6265 sec. 4.1.1, plus the deployed
# Partitioned/Priority extensions). In the attribute position of a Set-Cookie
# header these words scope the cookie — they are not cookie data, and their
# values (a path, a domain, a date) carry no secret. Matching is
# case-insensitive per RFC 6265 sec. 5.2.
COOKIE_ATTRIBUTE_NAMES = (
    "HttpOnly",
    "Secure",
    "SameSite",
    "Path",
    "Domain",
    "Max-Age",
    "Expires",
    "Partitioned",
    "Priority",
)
_COOKIE_ATTRIBUTE_NAMES_LOWER = frozenset(name.lower() for name in COOKIE_ATTRIBUTE_NAMES)
_COOKIE_ATTR_ALTERNATION = "|".join(COOKIE_ATTRIBUTE_NAMES)

# Cookie attribute metadata pattern (e.g., "HttpOnly: true, Secure: true")
_COOKIE_ATTR_METADATA_RE = re.compile(
    rf"^({_COOKIE_ATTR_ALTERNATION})"
    r"(\s*[:=]\s*\S+)?"
    rf"(\s*[,;]\s*({_COOKIE_ATTR_ALTERNATION})(\s*[:=]\s*\S+)?)*\s*$",
    re.IGNORECASE,
)


def _decode_base64_text(value: str) -> str | None:
    """Strictly decode a value as base64 to UTF-8 text.

    Args:
        value: String to decode

    Returns:
        The decoded text, or None if the value is not valid base64 or does
        not decode to valid UTF-8
    """
    if not value or len(value) < 4:
        return None

    # Quick pre-filter: must be valid base64 characters
    if not _BASE64_CHARS_RE.match(value):
        return None

    # Canonical padding only. Python 3.10's b64decode(validate=True) accepts
    # excess padding that 3.11+ rejects; recognition must not depend on the
    # interpreter.
    stripped = value.rstrip("=")
    if len(stripped) < 4 or len(value) - len(stripped) != -len(stripped) % 4:
        return None

    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return None


def is_base64_credential(value: str) -> bool:
    """Check if a value is a base64-encoded user:pass credential.

    Detects URL token authentication patterns where base64(username:password)
    is passed as a bare query parameter or parameter value.

    Args:
        value: String to check

    Returns:
        True if value decodes to a user:pass pattern

    Examples:
        >>> is_base64_credential("YWRtaW46cGFzc3dvcmQ=")  # admin:password
        True
        >>> is_base64_credential("aGVsbG8gd29ybGQ=")  # hello world (no colon)
        False
        >>> is_base64_credential("not-base64!")
        False
    """
    decoded = _decode_base64_text(value)
    if decoded is None:
        return False

    # Check for user:pass pattern — at least one char on each side of colon
    if ":" not in decoded:
        return False

    parts = decoded.split(":", 1)
    return len(parts) == 2 and len(parts[0]) >= 1 and len(parts[1]) >= 1


class QueryCredential(NamedTuple):
    """A base64(user:pass) credential located inside one URL query segment.

    The segment reads ``prefix`` followed by the credential. ``prefix`` is kept
    verbatim when redacting: ``""`` for a bare segment, ``"key="`` for a keyed
    one, or a marker such as ``"login_"``. ``credential`` is the base64 text as
    the client produced it, with any URL transport encoding undone.
    """

    prefix: str
    credential: str
    keyed: bool


# URL-token firmware can glue a short marker onto the bare token
# (``?login_<base64>``). '_' is outside the standard base64 alphabet, so the
# marker boundary is unambiguous.
_QUERY_CREDENTIAL_MARKER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*_)(.+)$")

# The shape Hasher.hash_generic writes: an uppercase prefix, '_', lowercase hex.
_HASH_PLACEHOLDER_RE = re.compile(r"[A-Z][A-Z0-9_]*_[0-9a-f]{8,}")

# A credential whose padding was stripped is only accepted from this many
# characters up — the unpadded length of base64("admin:pw"). Below it, short
# hex and alphanumeric tokens (cache-busters, short commit SHAs) decode to a
# colon-bearing string by chance often enough to matter.
_MIN_UNPADDED_CREDENTIAL_LENGTH = 11

# Decoded text that is a URL (scheme://) or opens a JSON object/array: it has
# a colon, but it is a payload, not user:pass.
_STRUCTURED_TEXT_RE = re.compile(r"^\s*(?:[A-Za-z][A-Za-z0-9+.-]*://|[{\[])")

# Headers whose value is a URL (RFC 9110). A credential or sensitive
# parameter in the request URL is repeated in the next request's Referer and
# can appear in a redirect's Location, so these get the same query treatment
# as the request URL itself.
URL_VALUED_HEADERS: frozenset[str] = frozenset({"referer", "location", "content-location"})


def _as_base64_credential(raw: str) -> str | None:
    """Return ``raw`` as a base64 credential, undoing what URL transport did to it.

    A query value can arrive percent-encoded (``%3D`` padding, ``%2B``), with
    '+' decoded to a space (URLSearchParams, and so Playwright's
    ``queryString`` array), or with its padding stripped or miscounted.
    ``unquote`` is used rather than ``unquote_plus``: a raw '+' in a query is
    a base64 character far more often than an encoded space.
    """
    verbatim = list(dict.fromkeys([raw, urllib.parse.unquote(raw), raw.replace(" ", "+")]))
    for candidate in verbatim:
        if is_base64_credential(candidate):
            return candidate
    # Restoring padding reaches values the verbatim check never has, so it
    # only accepts a decoded value that could be nothing but user:pass: long
    # enough, printable, and not a URL or JSON payload that merely contains a
    # colon. The verbatim check above keeps its long-standing behavior.
    for candidate in verbatim:
        unpadded = candidate.rstrip("=")
        if len(unpadded) < _MIN_UNPADDED_CREDENTIAL_LENGTH:
            continue
        padded = unpadded + "=" * (-len(unpadded) % 4)
        decoded = _decode_base64_text(padded)
        if (
            decoded is not None
            and decoded.isprintable()
            and not _STRUCTURED_TEXT_RE.match(decoded)
            and is_base64_credential(padded)
        ):
            return padded
    return None


def is_blank_query_value(value: str) -> bool:
    """True for a query value with nothing in it to redact.

    Empty, or only '=' — the padding remnant a query parser leaves in
    ``value`` when it splits a bare token at its first '='.

    Args:
        value: Decoded query parameter value

    Returns:
        True if the value carries no content
    """
    return not value.strip("=")


def query_param_segment(param: dict[str, Any]) -> str:
    """Rejoin a HAR ``queryString`` entry into the query segment it was parsed from.

    The parser splits at the first '=', so a bare credential's base64 padding
    lands in ``value``. Rejoining lets one segment reader serve both the URL
    string and the parsed array.

    Args:
        param: One ``{"name": ..., "value": ...}`` entry

    Returns:
        ``name=value``, or ``name`` when the value is empty
    """
    name = str(param.get("name", ""))
    value = str(param.get("value", ""))
    return f"{name}={value}" if value else name


def find_query_credential(segment: str) -> QueryCredential | None:
    """Locate a base64(user:pass) credential in one raw URL query segment.

    The single definition of "URL credential" for the sanitizer, the
    validator and the credential annotation, so the three cannot disagree
    about which query shapes carry one. Recognized shapes: a bare segment
    (``?<b64>``), a keyed value (``?auth=<b64>``), and a marker-prefixed
    segment (``?login_<b64>``).

    Args:
        segment: One ``&``-separated query segment, undecoded

    Returns:
        The located credential, or None
    """
    # A hash placeholder the sanitizer wrote (``AUTH_d2c6b8e4``) is itself
    # marker-shaped, and 8 hex characters sometimes decode to a colon.
    if not segment or _HASH_PLACEHOLDER_RE.fullmatch(segment):
        return None
    # A doubled separator (``/a??<b64>``, ``k==<b64>``) is kept in the prefix
    # rather than read as part of the credential.
    body = segment.lstrip("?")
    lead = segment[: len(segment) - len(body)]
    credential = _as_base64_credential(body)
    if credential:
        return QueryCredential(prefix=lead, credential=credential, keyed=False)
    key, sep, value = body.partition("=")
    stripped = value.lstrip("=")
    if sep and stripped:
        credential = _as_base64_credential(stripped)
        if credential:
            separator = value[: len(value) - len(stripped)]
            return QueryCredential(prefix=f"{lead}{key}={separator}", credential=credential, keyed=True)
    marker = _QUERY_CREDENTIAL_MARKER_RE.match(body)
    if marker:
        credential = _as_base64_credential(marker.group(2))
        if credential:
            return QueryCredential(prefix=lead + marker.group(1), credential=credential, keyed=False)
    return None


def is_base64_decodable_text(value: str) -> bool:
    """Check if a value is base64 that decodes to printable text.

    Weaker signal than :func:`is_base64_credential` (no user:pass shape
    required) — callers must supply the credential context, e.g. a
    login-shaped form POST. Exists because vendor firmware base64-encodes
    bare passwords with no recognizable shape of their own.

    Args:
        value: String to check

    Returns:
        True if value decodes to printable UTF-8 text of plausible
        credential length

    Examples:
        >>> is_base64_decodable_text("ZXhhbXBsZS1ub3QtcmVhbA==")  # example-not-real
        True
        >>> is_base64_decodable_text("admin")  # not valid base64 length
        False
    """
    decoded = _decode_base64_text(value)
    if decoded is None or len(decoded) < 4:
        return False
    return decoded.isprintable()


def is_cookie_attribute_metadata(value: str) -> bool:
    """Check if a value is cookie attribute metadata rather than cookie data.

    Detects values like ``"HttpOnly: true, Secure: true"`` that are
    serialized cookie attributes incorrectly placed where a cookie
    name=value string should be.

    Args:
        value: String to check

    Returns:
        True if the value consists only of cookie attribute names/values

    Examples:
        >>> is_cookie_attribute_metadata("HttpOnly: true, Secure: true")
        True
        >>> is_cookie_attribute_metadata("session=abc123")
        False
    """
    if not value or not value.strip():
        return False
    return bool(_COOKIE_ATTR_METADATA_RE.match(value))


def is_cookie_attribute_name(name: str) -> bool:
    """Check if a Set-Cookie segment key is a reserved attribute name.

    A Set-Cookie header is one ``name=value`` cookie pair followed by
    ``;``-separated attributes (RFC 6265 sec. 4.1.1). Only the pair is cookie
    data; a segment keyed by one of these reserved names describes the
    cookie's scope and must survive sanitization intact.

    Args:
        name: The key half of one ``;``-separated Set-Cookie segment
            (surrounding whitespace is ignored)

    Returns:
        True if the key is a reserved cookie attribute name

    Examples:
        >>> is_cookie_attribute_name(" Path")
        True
        >>> is_cookie_attribute_name("httponly")
        True
        >>> is_cookie_attribute_name("csrfp_token")
        False
    """
    return name.strip().lower() in _COOKIE_ATTRIBUTE_NAMES_LOWER
