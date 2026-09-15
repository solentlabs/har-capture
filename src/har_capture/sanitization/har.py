"""HAR file sanitization utilities.

This module provides functions to sanitize HAR (HTTP Archive) files by removing
sensitive information while preserving the structure needed for debugging device
authentication and parsing issues.

Reuses PII patterns from html.py for consistency.
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import copy
import functools
import json
import logging
import re
import urllib.parse
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from har_capture.patterns import (
    CERTIFICATE_NAME_FIELDS,
    EMAIL_RE,
    IPV6_RE,
    JSON_MAX_DEPTH,
    KNOWN_AUTH_SCHEMES,
    MAC_RE,
    PRIVATE_IP_RE,
    PUBLIC_IP_RE,
    SET_COOKIE_HEADERS,
    URL_VALUED_HEADERS,
    Hasher,
    JsonObjectWithDuplicates,
    QueryCredential,
    QueryPayload,
    annotated_url_credential_entries,
    certificate_name_macs,
    classify_identity_field,
    cookie_segment_actions,
    credential_value_action,
    decode_base64_payload,
    decode_transport_body,
    find_query_credential,
    find_query_payload,
    is_allowlisted,
    is_base64_credential,
    is_base64_decodable_text,
    is_blank_query_value,
    is_constant_mac,
    is_fully_redacted,
    is_ipv6_host_address,
    is_mac_placeholder,
    is_redacted,
    is_ssid_key,
    iter_json_strings,
    iter_url_credentials,
    json_members,
    load_allowlist,
    load_pii_patterns,
    load_sensitive_patterns,
    mime_kind,
    parse_json_container,
    parse_xml,
    query_param_segment,
    route_body,
    split_url_password,
    split_url_query,
)
from har_capture.patterns.loader import compile_safe_value_patterns
from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.html import (
    SERIAL_LABEL_HINT_RE,
    is_private_ip_in_range,
    is_valid_ip_address,
    pattern_file_patterns,
    redact_labeled_serials,
    redact_pattern_file_matches,
    redact_structural_credentials,
    redact_vendor_serials,
    sanitize_html,
)
from har_capture.sanitization.report import ConfidenceLevel, ReviewOutcome

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from har_capture.sanitization.report import HeuristicMode, SanitizationReport
else:
    from har_capture.sanitization.report import HeuristicMode

_LOGGER = logging.getLogger(__name__)

# Maximum recursion depth for JSON sanitization to prevent stack overflow
_MAX_RECURSION_DEPTH = JSON_MAX_DEPTH

# Default maximum HAR file size (100 MB)
DEFAULT_MAX_HAR_SIZE = 100 * 1024 * 1024


class HarSizeError(ValueError):
    """Raised when HAR file exceeds size limit."""

    def __init__(self, size: int, max_size: int) -> None:
        self.size = size
        self.max_size = max_size
        super().__init__(
            f"HAR file size ({size:,} bytes) exceeds limit ({max_size:,} bytes). "
            f"Use max_size parameter to increase or set to None to disable."
        )


class HarValidationError(ValueError):
    """Raised when HAR structure is invalid."""

    def __init__(self, message: str, path: str = "") -> None:
        self.path = path
        full_message = f"Invalid HAR structure: {message}"
        if path:
            full_message += f" (at {path})"
        super().__init__(full_message)


def validate_har_structure(har_data: dict[str, Any], *, strict: bool = False) -> list[str]:
    """Validate HAR structure against HAR 1.2 spec.

    Args:
        har_data: Parsed HAR data
        strict: If True, require all HAR 1.2 fields. If False, only require minimal structure.

    Returns:
        List of validation warnings (empty if valid)

    Raises:
        HarValidationError: If structure is fundamentally invalid (missing log or entries)

    Example:
        >>> warnings = validate_har_structure({"log": {"entries": []}})
        >>> # warnings may contain "Missing log.version", "Missing log.creator", etc.
    """
    warnings: list[str] = []

    # Required: root must have "log" key
    if "log" not in har_data:
        raise HarValidationError("Missing required 'log' key", "root")

    log = har_data["log"]
    if not isinstance(log, dict):
        raise HarValidationError("'log' must be an object", "log")

    # Required: log must have "entries" array
    if "entries" not in log:
        raise HarValidationError("Missing required 'entries' key", "log")

    entries = log["entries"]
    if not isinstance(entries, list):
        raise HarValidationError("'entries' must be an array", "log.entries")

    # Recommended fields (warnings only)
    if "version" not in log:
        warnings.append("Missing log.version (recommended)")
    if "creator" not in log:
        warnings.append("Missing log.creator (recommended)")

    if strict:
        # Strict mode: validate each entry
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                warnings.append(f"Entry {i} is not an object")
                continue

            if "request" not in entry:
                warnings.append(f"Entry {i} missing 'request'")
            elif isinstance(entry["request"], dict):
                req = entry["request"]
                if "method" not in req:
                    warnings.append(f"Entry {i} request missing 'method'")
                if "url" not in req:
                    warnings.append(f"Entry {i} request missing 'url'")

            if "response" not in entry:
                warnings.append(f"Entry {i} missing 'response'")
            elif isinstance(entry["response"], dict):
                resp = entry["response"]
                if "status" not in resp:
                    warnings.append(f"Entry {i} response missing 'status'")

    return warnings


def _load_sensitive_headers() -> tuple[set[str], set[str], set[str]]:
    """Load sensitive header names from patterns.

    Returns:
        Tuple of (full_redact_headers, cookie_redact_headers, scheme_redact_headers)
    """
    sensitive = load_sensitive_patterns()
    headers = sensitive.get("headers", {})
    full_redact = set(h.lower() for h in headers.get("full_redact", []))
    cookie_redact = set(h.lower() for h in headers.get("cookie_redact", []))
    scheme_redact = set(h.lower() for h in headers.get("scheme_redact", []))
    return full_redact, cookie_redact, scheme_redact


def _compile_sensitive_field_patterns(
    sensitive_data: dict[str, Any],
) -> tuple[re.Pattern[str], re.Pattern[str] | None]:
    """Compile (auto_redact, flag) regexes from a loaded sensitive-patterns dict.

    Returns:
        Tuple of (auto_redact_pattern, flag_pattern) compiled regexes.
        flag_pattern is None if no flag patterns are defined.
    """
    fields = sensitive_data.get("fields", {})
    auto_patterns = fields.get("auto_redact_patterns", [])
    flag_patterns = fields.get("flag_patterns", [])

    auto_re = re.compile("|".join(auto_patterns), re.IGNORECASE)
    flag_re = re.compile("|".join(flag_patterns), re.IGNORECASE) if flag_patterns else None
    return auto_re, flag_re


def _load_sensitive_field_patterns() -> tuple[re.Pattern[str], re.Pattern[str] | None]:
    """Load and compile sensitive field patterns from the built-in patterns file."""
    return _compile_sensitive_field_patterns(load_sensitive_patterns())


# Load patterns at module level for efficiency
_FULL_REDACT_HEADERS, _COOKIE_REDACT_HEADERS, _SCHEME_REDACT_HEADERS = _load_sensitive_headers()
_SENSITIVE_FIELD_RE, _SENSITIVE_FLAG_FIELD_RE = _load_sensitive_field_patterns()


@dataclass(frozen=True)
class _FieldPatternSet:
    """Resolved auto-redact and flag regexes used for one sanitization call.

    ``flag_re`` is None when no flag patterns are configured — that is a
    legitimate state, distinct from "use the default pattern set", which is
    expressed by passing ``None`` in place of an entire ``_FieldPatternSet``.
    """

    field_re: re.Pattern[str]
    flag_re: re.Pattern[str] | None

    def matches_sensitive(self, field_name: str) -> bool:
        return bool(self.field_re.search(field_name))

    def matches_flaggable(self, field_name: str) -> bool:
        if self.flag_re is None:
            return False
        return bool(self.flag_re.search(field_name))


_DEFAULT_FIELD_PATTERNS = _FieldPatternSet(_SENSITIVE_FIELD_RE, _SENSITIVE_FLAG_FIELD_RE)

# Per-call field-pattern override. ContextVar because (a) overrides must be
# scoped to a single sanitize call without leaking to concurrent work, and
# (b) ContextVar is the stdlib-native primitive for thread- and asyncio-safe
# dynamic scope — no manual locking required.
_FIELD_PATTERNS_CTX: contextvars.ContextVar[_FieldPatternSet] = contextvars.ContextVar(
    "har_capture_field_patterns", default=_DEFAULT_FIELD_PATTERNS
)


@dataclass(frozen=True)
class _CallPatterns:
    """What the JSON walker and string patterns need from a call's ``custom_patterns``.

    Resolved once when the call's scope is entered, so the per-string work
    reads these instead of loading the pattern files again.
    """

    custom_patterns: str | dict[str, Any] | None
    preserved_ips: frozenset[str]
    allowlist: dict[str, Any]
    serial_detectors: tuple[Any, ...]
    pattern_file: tuple[tuple[str, re.Pattern[str], str], ...]
    safe_values: tuple[re.Pattern[str], ...]


def _resolve_call_patterns(custom_patterns: str | dict[str, Any] | None) -> _CallPatterns:
    return _CallPatterns(
        custom_patterns,
        frozenset(load_pii_patterns(custom_patterns).get("preserved_gateway_ips", [])),
        load_allowlist(custom_patterns),
        tuple(_resolve_serial_detectors(custom_patterns)),
        tuple(pattern_file_patterns(custom_patterns)),
        tuple(compile_safe_value_patterns(load_sensitive_patterns(custom_patterns))),
    )


# The active call's patterns for helpers with no custom_patterns parameter
# (the string patterns' address passes, the JSON walker), so a caller's
# preserved gateway addresses, allowlist and vendor serial formats hold on
# every route, as they do in the HTML engine. None: the built-in patterns.
_CALL_PATTERNS_CTX: contextvars.ContextVar[_CallPatterns | None] = contextvars.ContextVar(
    "har_capture_call_patterns", default=None
)

# The credentials the capture being sanitized submits (_scan_submitted_credentials):
# a response echoing one under a credential-named key is redacted, whatever its
# shape. Empty outside sanitize_har.
_SUBMITTED_CREDENTIALS_CTX: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "har_capture_submitted_credentials", default=frozenset()
)


@functools.lru_cache(maxsize=1)
def _default_call_patterns() -> _CallPatterns:
    return _resolve_call_patterns(None)


def _active_call_patterns() -> _CallPatterns:
    """The active call's resolved patterns, or the built-in ones outside any call."""
    active = _CALL_PATTERNS_CTX.get()
    return active if active is not None else _default_call_patterns()


@contextmanager
def _call_patterns_scope(custom_patterns: str | dict[str, Any] | None) -> Iterator[None]:
    """Make ``custom_patterns`` the active call's patterns for this scope.

    A scope already active for the same patterns object is kept, so a
    ``sanitize_har`` call resolves them once rather than once per entry.
    """
    active = _CALL_PATTERNS_CTX.get()
    if custom_patterns is not None and active is not None and active.custom_patterns is custom_patterns:
        yield
        return
    token = _CALL_PATTERNS_CTX.set(
        None if custom_patterns is None else _resolve_call_patterns(custom_patterns)
    )
    try:
        yield
    finally:
        _CALL_PATTERNS_CTX.reset(token)


@contextmanager
def _field_patterns_scope(custom_patterns: str | dict[str, Any] | None) -> Iterator[None]:
    """Apply ``custom_patterns`` as the active field-pattern set for this scope.

    Restores the previous set on exit even if an exception escapes. Designed
    to be called at public entry points (``sanitize_post_data``, ``sanitize_html``);
    inner helpers simply call ``is_sensitive_field`` / ``is_flaggable_field`` and
    pick up the active set automatically.
    """
    token = _FIELD_PATTERNS_CTX.set(_resolve_field_patterns(custom_patterns))
    try:
        yield
    finally:
        _FIELD_PATTERNS_CTX.reset(token)


# Per-call regex cache for custom_patterns extensions. Keyed by a canonical
# representation of the custom_patterns argument. Module globals above are
# never mutated — each entry here is an independent compiled pair.
_CUSTOM_FIELD_RE_CACHE_MAX = 32
_CUSTOM_FIELD_RE_CACHE: OrderedDict[str, _FieldPatternSet] = OrderedDict()


def _custom_patterns_cache_key(custom_patterns: str | dict[str, Any]) -> str | None:
    """Derive a stable cache key for a custom_patterns argument.

    Returns None if the argument is not hashable in a stable way (in which
    case the caller should skip the cache and compile fresh).
    """
    if isinstance(custom_patterns, dict):
        try:
            return "dict:" + json.dumps(custom_patterns, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return None
    return "path:" + str(Path(custom_patterns).resolve())


def _resolve_field_patterns(
    custom_patterns: str | dict[str, Any] | None,
) -> _FieldPatternSet:
    """Resolve the auto-redact + flag regex pair for this call.

    ``custom_patterns=None`` returns the shared default set (today's behavior,
    zero-cost). Otherwise the custom patterns are merged with built-ins via
    the loader and the compiled result is cached per canonical key so repeat
    calls don't recompile.
    """
    if custom_patterns is None:
        return _DEFAULT_FIELD_PATTERNS

    key = _custom_patterns_cache_key(custom_patterns)
    if key is not None:
        cached = _CUSTOM_FIELD_RE_CACHE.get(key)
        if cached is not None:
            _CUSTOM_FIELD_RE_CACHE.move_to_end(key)
            return cached

    field_re, flag_re = _compile_sensitive_field_patterns(load_sensitive_patterns(custom_patterns))
    resolved = _FieldPatternSet(field_re, flag_re)

    if key is not None:
        _CUSTOM_FIELD_RE_CACHE[key] = resolved
        while len(_CUSTOM_FIELD_RE_CACHE) > _CUSTOM_FIELD_RE_CACHE_MAX:
            _CUSTOM_FIELD_RE_CACHE.popitem(last=False)
    return resolved


# --- Header-set per-call override --------------------------------------------
#
# Parallel to _FieldPatternSet but for HTTP header names, which are matched by
# lowercase exact-match against two sets (full_redact, cookie_redact) rather
# than compiled regex. Same ContextVar / resolver / cache shape so the two
# subsystems evolve together.


@dataclass(frozen=True)
class _HeaderSets:
    """Resolved header-name sets used for one sanitization call.

    All sets are frozen and case-normalized to lowercase so callers can do
    ``name.lower() in sets.full_redact`` without repeated normalization.
    ``scheme_redact`` is the third bucket alongside ``full_redact`` and
    ``cookie_redact``; see ``sanitize_header_value`` for the routing.
    """

    full_redact: frozenset[str]
    cookie_redact: frozenset[str]
    scheme_redact: frozenset[str]


def _compile_header_sets(sensitive_data: dict[str, Any]) -> _HeaderSets:
    """Build header-name frozensets from a loaded sensitive-patterns dict."""
    headers = sensitive_data.get("headers", {})
    full = frozenset(h.lower() for h in headers.get("full_redact", []))
    cookie = frozenset(h.lower() for h in headers.get("cookie_redact", []))
    scheme = frozenset(h.lower() for h in headers.get("scheme_redact", []))
    return _HeaderSets(full, cookie, scheme)


_DEFAULT_HEADER_SETS = _HeaderSets(
    frozenset(_FULL_REDACT_HEADERS),
    frozenset(_COOKIE_REDACT_HEADERS),
    frozenset(_SCHEME_REDACT_HEADERS),
)

_HEADER_SETS_CTX: contextvars.ContextVar[_HeaderSets] = contextvars.ContextVar(
    "har_capture_header_sets", default=_DEFAULT_HEADER_SETS
)

_CUSTOM_HEADER_SETS_CACHE: OrderedDict[str, _HeaderSets] = OrderedDict()


def _resolve_header_sets(
    custom_patterns: str | dict[str, Any] | None,
) -> _HeaderSets:
    """Resolve the (full_redact, cookie_redact) header sets for this call.

    ``custom_patterns=None`` returns the shared default set (zero-cost).
    Otherwise the custom patterns are merged with built-ins via the loader
    and the compiled result is cached per canonical key.
    """
    if custom_patterns is None:
        return _DEFAULT_HEADER_SETS

    key = _custom_patterns_cache_key(custom_patterns)
    if key is not None:
        cached = _CUSTOM_HEADER_SETS_CACHE.get(key)
        if cached is not None:
            _CUSTOM_HEADER_SETS_CACHE.move_to_end(key)
            return cached

    resolved = _compile_header_sets(load_sensitive_patterns(custom_patterns))

    if key is not None:
        _CUSTOM_HEADER_SETS_CACHE[key] = resolved
        while len(_CUSTOM_HEADER_SETS_CACHE) > _CUSTOM_FIELD_RE_CACHE_MAX:
            _CUSTOM_HEADER_SETS_CACHE.popitem(last=False)
    return resolved


@contextmanager
def _header_sets_scope(custom_patterns: str | dict[str, Any] | None) -> Iterator[None]:
    """Apply ``custom_patterns`` as the active header-set for this scope.

    Parallel to ``_field_patterns_scope``; public entry points that want
    header-name extensions to take effect for the call must enter this scope.
    """
    token = _HEADER_SETS_CTX.set(_resolve_header_sets(custom_patterns))
    try:
        yield
    finally:
        _HEADER_SETS_CTX.reset(token)


# --- Vendor-serial detector per-call resolver ---------------------------------
#
# Same resolver/cache shape as the field-pattern and header-set subsystems.
# Only the high-confidence serial_number detectors are kept — they are the
# deterministic vendor serial formats that redact_vendor_serials applies to
# non-HTML text content (the HTML engine compiles its own detector list).

_CUSTOM_SERIAL_DETECTORS_CACHE: OrderedDict[str, list[Any]] = OrderedDict()


def _resolve_serial_detectors(
    custom_patterns: str | dict[str, Any] | None,
) -> list[Any]:
    """Resolve the high-confidence serial_number detectors for this call.

    ``custom_patterns=None`` resolves against the built-in sensitive.json,
    which declares no detectors — vendor serial formats are domain knowledge
    and arrive via ``--patterns``. Cached per canonical key like the other
    per-call resolvers.
    """
    from har_capture.patterns.loader import compile_detectors, high_confidence_serial_detectors

    if custom_patterns is None:
        return []

    key = _custom_patterns_cache_key(custom_patterns)
    if key is not None:
        cached = _CUSTOM_SERIAL_DETECTORS_CACHE.get(key)
        if cached is not None:
            _CUSTOM_SERIAL_DETECTORS_CACHE.move_to_end(key)
            return cached

    resolved = high_confidence_serial_detectors(compile_detectors(load_sensitive_patterns(custom_patterns)))

    if key is not None:
        _CUSTOM_SERIAL_DETECTORS_CACHE[key] = resolved
        while len(_CUSTOM_SERIAL_DETECTORS_CACHE) > _CUSTOM_FIELD_RE_CACHE_MAX:
            _CUSTOM_SERIAL_DETECTORS_CACHE.popitem(last=False)
    return resolved


# Redaction placeholder - single source of truth
REDACTED = "[REDACTED]"


def _redact_value(
    value: str,
    hasher: Hasher | None,
    category: str = "FIELD",
    collector: RedactionCollector | None = None,
) -> str:
    """Redact a value, using hasher for correlation-preserving hashes if available.

    Args:
        value: The sensitive value to redact
        hasher: Optional hasher for correlation-preserving redaction
        category: Hash category (FIELD, AUTH, COOKIE) for hasher
        collector: Optional collector to record the redaction

    Returns:
        Hashed value if hasher provided, otherwise REDACTED placeholder;
        an empty value comes back empty
    """
    if value == "":
        # Nothing to hide, and a placeholder would invent a value the capture
        # never sent (an empty default password), as the JSON route never has.
        return value
    if collector:
        collector.record_auto_redaction(category.lower())
    placeholder = hasher.hash_generic(value, category) if hasher else REDACTED
    if collector:
        # Feeds the Pass 1b propagation sweep in sanitize_har. Recorded for every
        # redaction; eligibility is decided at sweep time by _is_propagation_eligible.
        collector.record_redacted_value(value, placeholder)
    return placeholder


def is_sensitive_field(field_name: str) -> bool:
    """Check if a form field name matches auto-redact patterns (100% confidence).

    Reads the active field-pattern set from the ``_field_patterns_scope``
    context manager when one is entered; otherwise uses the module-wide
    defaults from ``sensitive.json``.

    Args:
        field_name: Name of the form field

    Returns:
        True if the field matches high-confidence sensitive patterns

    Example:
        >>> is_sensitive_field("loginPassword")
        True
        >>> is_sensitive_field("username")
        False
        >>> is_sensitive_field("channel_id")
        False
    """
    return _FIELD_PATTERNS_CTX.get().matches_sensitive(field_name)


def is_flaggable_field(field_name: str) -> bool:
    """Check if a form field name matches flag-for-review patterns.

    These are fields that may contain sensitive data but are not certain
    enough for auto-redaction. They are flagged for interactive user review.
    Honors an active ``_field_patterns_scope`` override.

    Args:
        field_name: Name of the form field

    Returns:
        True if the field should be flagged for review

    Example:
        >>> is_flaggable_field("username")
        True
        >>> is_flaggable_field("password")
        False
        >>> is_flaggable_field("channel_id")
        False
    """
    return _FIELD_PATTERNS_CTX.get().matches_flaggable(field_name)


def _sanitize_cookie_header(
    value: str,
    hasher: Hasher | None,
    collector: RedactionCollector | None,
    *,
    set_cookie: bool,
) -> str:
    """Redact the cookie data in a Cookie or Set-Cookie value, keeping names and attributes.

    ``cookie_segment_actions`` (shared with validate) decides, one
    ``;``-separated segment at a time, what is cookie data: a pair's value,
    or a valueless segment that is a nameless cookie. Names, reserved
    Set-Cookie attributes (RFC 6265 sec. 4.1.1: they scope the cookie and are
    not secrets) and spacing survive, so a reassembled header keeps its shape.

    Args:
        value: Raw header value
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
        set_cookie: The header is a Set-Cookie

    Returns:
        Sanitized header value

    Example:
        >>> _sanitize_cookie_header(
        ...     "sid=secret; Path=/isp; HttpOnly", None, None, set_cookie=True
        ... )
        'sid=[REDACTED]; Path=/isp; HttpOnly'
    """
    segments = value.split(";")
    for index, action in enumerate(cookie_segment_actions(value, set_cookie=set_cookie)):
        segment = segments[index]
        if action == "value":
            name, _, data = segment.partition("=")
            if data.strip():
                segments[index] = f"{name}={_redact_value(data, hasher, 'COOKIE', collector)}"
        elif action == "token":
            token = segment.strip()
            lead = segment[: len(segment) - len(segment.lstrip())]
            trail = segment[len(segment.rstrip()) :]
            segments[index] = f"{lead}{_redact_value(token, hasher, 'COOKIE', collector)}{trail}"
    return ";".join(segments)


def sanitize_header_value(
    name: str,
    value: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Sanitize a header value if it's sensitive.

    Reads the active header-name set from ``_header_sets_scope`` when one is
    entered (top-level entry points like ``sanitize_entry`` set it from
    ``custom_patterns``); otherwise uses the module-wide defaults from
    ``sensitive.json``.

    Args:
        name: Header name
        value: Header value
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        Sanitized value or original if not sensitive

    Example:
        >>> sanitize_header_value("Authorization", "Bearer abc123")
        'Bearer [REDACTED]'
        >>> sanitize_header_value("Content-Type", "text/html")
        'text/html'
    """
    name_lower = name.lower()
    sets = _HEADER_SETS_CTX.get()

    if name_lower in sets.full_redact:
        return _redact_value(value, hasher, "AUTH", collector)

    if name_lower in sets.scheme_redact:
        # RFC 7235: header value is "Scheme credentials". The scheme token is
        # structural protocol metadata (a closed set of identifiers); the
        # credential after it is the secret. Preserve a recognized scheme so
        # downstream consumers can classify the auth mechanism without seeing
        # the secret. Unknown scheme → fall through to full redaction so a
        # non-standard format can't leak its leading token.
        stripped = value.lstrip()
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in KNOWN_AUTH_SCHEMES:
            scheme, credential = parts
            hashed = _redact_value(credential, hasher, "AUTH", collector)
            return f"{scheme} {hashed}"
        return _redact_value(value, hasher, "AUTH", collector)

    if name_lower in sets.cookie_redact:
        return _sanitize_cookie_header(value, hasher, collector, set_cookie=name_lower in SET_COOKIE_HEADERS)

    return value


def _sanitize_form_urlencoded(
    text: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Sanitize form-urlencoded text by redacting sensitive fields.

    Args:
        text: Form-urlencoded text to sanitize
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        Sanitized text with sensitive field values redacted
    """
    # A name is judged decoded, as validate judges it: `user%5Bpass%5D` is
    # the field `user[pass]`.
    names = [urllib.parse.unquote_plus(pair.split("=", 1)[0]) for pair in text.split("&") if "=" in pair]
    login_shaped = any(is_sensitive_field(name) or is_flaggable_field(name) for name in names)

    pairs = []
    for pair in text.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            name = urllib.parse.unquote_plus(key)
            # Hash the percent-decoded value so the placeholder matches the
            # params copy (HAR stores params decoded).
            decoded_value = urllib.parse.unquote_plus(value)
            # Same order as the params copy and the query tree.
            if is_sensitive_field(name):
                value = _redact_value(decoded_value, hasher, "FIELD", collector)
            elif is_base64_credential(value) or is_base64_credential(decoded_value):
                # base64(user:pass) — check the raw and percent-decoded forms.
                value = _redact_value(decoded_value, hasher, "AUTH", collector)
            elif (payload := _sanitize_payload_field(value, hasher, collector)) is not None:
                value = payload
            elif is_flaggable_field(name) and collector and value:
                collector.flag_value(
                    decoded_value,
                    "field",
                    ConfidenceLevel.MEDIUM,
                    f"form field '{name}'",
                    f"Flaggable field name '{name}' in form data",
                )
            elif login_shaped and collector and is_base64_decodable_text(decoded_value):
                # Likely a vendor-encoded credential (Sercomm/Hitron style).
                # Flag, never auto-redact: base64-decodable alone is not a
                # 100%-confidence signal.
                collector.flag_value(
                    decoded_value,
                    "credential",
                    ConfidenceLevel.MEDIUM,
                    f"form field '{name}'",
                    f"Base64-decodable value in unrecognized field '{name}' of a login-shaped form POST",
                )
            pairs.append(f"{key}={value}")
        else:
            pairs.append(pair)
    return "&".join(pairs)


def _rewrite_json(
    text: str,
    data: dict[str, Any] | list[Any],
    hasher: Hasher | None,
    collector: RedactionCollector | None,
    *,
    served: bool = False,
) -> str:
    """Sanitize parsed JSON and write it back as its text was written.

    Text with nothing to redact comes back byte-identical — a repeated key
    included, when none of its earlier values has anything to redact either.
    Otherwise it is re-serialized in the original's layout where
    ``json.dumps`` can reproduce it (``_dump_json_like``). A repeated key
    then keeps only its last value, as every JSON parser reads it, so a
    shadowed secret never passes through; text that repeats a key cannot be
    reproduced, so such a body takes the default layout.
    """
    cleaned = _sanitize_json_recursive(data, hasher, collector, served=served)
    if cleaned == data and not _shadowed_values_change(data, hasher, served=served):
        return text
    return _dump_json_like(cleaned, data, text)


def _shadowed_values_change(data: Any, hasher: Hasher | None, *, served: bool = False) -> bool:
    """True when a repeated key's earlier value would be redacted or offered for review.

    Probed with a throwaway collector: the shadowed members are dropped from
    the output, so nothing is counted or offered for review twice. A value
    the review would be offered must be dropped too — kept, it would pass
    through with no review item while validate reports it.
    """
    probe = RedactionCollector(hasher=hasher if hasher is not None else Hasher(salt=None))
    stack: list[Any] = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, JsonObjectWithDuplicates):
            for key, value in node.shadowed:
                member = {key: value}
                if _sanitize_json_recursive(member, hasher, probe, served=served) != member or probe.flagged:
                    return True
                if isinstance(value, dict | list):
                    stack.append(value)
        children = node.values() if isinstance(node, dict) else node  # only objects and arrays are stacked
        stack.extend(child for child in children if isinstance(child, dict | list))
    return False


def sanitize_post_data(
    post_data: dict[str, Any] | None,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    *,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> dict[str, Any] | None:
    """Sanitize POST data while preserving field names.

    Args:
        post_data: HAR postData object
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
        custom_patterns: Optional additive custom patterns (file path or dict
            matching the ``load_sensitive_patterns`` schema, e.g.
            ``{"fields": {"auto_redact_patterns": ["vendorpw"]}}``). Extends — not
            replaces — the built-in auto-redact and flag patterns for THIS
            CALL ONLY via a ``ContextVar``-scoped override. Module-global
            state is never mutated, and independent threads / asyncio tasks
            receive their own copy of the context.
        heuristics: Heuristic mode for content engine

    Returns:
        Sanitized postData object
    """
    if not post_data:
        return post_data

    result = copy.deepcopy(post_data)

    with (
        _field_patterns_scope(custom_patterns),
        _header_sets_scope(custom_patterns),
        _call_patterns_scope(custom_patterns),
    ):
        # Sanitize params array
        if "params" in result and isinstance(result["params"], list):
            login_shaped = any(
                isinstance(p, dict)
                and "name" in p
                and (is_sensitive_field(p["name"]) or is_flaggable_field(p["name"]))
                for p in result["params"]
            )
            for param in result["params"]:
                if isinstance(param, dict) and "name" in param:
                    # The query tree's order (_classify_query_param): a
                    # credential or payload value decides before an
                    # identity-style name, so `user=<b64(user:pass)>` is a
                    # credential here as it is in a URL.
                    if is_sensitive_field(param["name"]):
                        param["value"] = _redact_value(param.get("value", ""), hasher, "FIELD", collector)
                    elif is_base64_credential(param.get("value", "")):
                        param["value"] = _redact_value(param["value"], hasher, "AUTH", collector)
                    elif (
                        payload := _sanitize_payload_field(str(param.get("value", "")), hasher, collector)
                    ) is not None:
                        param["value"] = payload
                    elif is_flaggable_field(param["name"]) and collector and param.get("value"):
                        collector.flag_value(
                            param["value"],
                            "field",
                            ConfidenceLevel.MEDIUM,
                            f"POST param '{param['name']}'",
                            f"Flaggable field name '{param['name']}' in POST params",
                        )
                    elif login_shaped and collector and is_base64_decodable_text(param.get("value", "")):
                        # Mirrors the form-text login-shaped heuristic.
                        collector.flag_value(
                            param["value"],
                            "credential",
                            ConfidenceLevel.MEDIUM,
                            f"POST param '{param['name']}'",
                            f"Base64-decodable value in unrecognized field '{param['name']}' "
                            "of a login-shaped form POST",
                        )

        # Sanitize raw text (form-urlencoded, JSON, or XML)
        if result.get("text"):
            text = result["text"]
            mime_type = result.get("mimeType", "")

            # JSON by content first, whatever the type: validate reads a POST
            # body as JSON whenever it parses (text/plain XHR bodies, and
            # jQuery's form-urlencoded default around JSON.stringify).
            data = parse_json_container(text)
            if data is not None:
                result["text"] = _rewrite_json(text, data, hasher, collector)
            elif "application/x-www-form-urlencoded" in mime_type:
                result["text"] = _sanitize_form_urlencoded(text, hasher, collector)
            elif mime_kind(mime_type) == "markup":
                text = _sanitize_xml_fields(text, hasher, collector)
                result["text"] = sanitize_html(
                    text,
                    collector=collector,
                    custom_patterns=custom_patterns,
                    heuristics=heuristics,
                )
            else:
                # Any other text: as a text response body is.
                result["text"] = _sanitize_body_string(
                    text, hasher, collector, custom_patterns, _resolve_serial_detectors(custom_patterns)
                )

    return result


def _sanitize_xml_fields(
    text: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Redact sensitive element values in XML text by tag name.

    Parses XML, checks each element's tag name against ``is_sensitive_field()``,
    and replaces matching text content with a hashed redaction. Returns the
    modified XML string, or the original text if parsing fails.

    Args:
        text: Raw XML text
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        XML text with sensitive element values redacted
    """
    import xml.etree.ElementTree as ET

    root = parse_xml(text)
    if root is None:
        return text

    modified = False
    for elem in root.iter():
        tag = elem.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        if elem.text and elem.text.strip() and is_sensitive_field(tag):
            elem.text = _redact_value(elem.text.strip(), hasher, "FIELD", collector)
            modified = True

        # Check attributes (e.g., <password value="secret"/>)
        for attr_name, attr_value in list(elem.attrib.items()):
            if attr_value and is_sensitive_field(attr_name):
                elem.set(attr_name, _redact_value(attr_value, hasher, "FIELD", collector))
                modified = True

    if not modified:
        return text

    return ET.tostring(root, encoding="unicode")


def _is_reviewable_ssid(key: str, value: object) -> bool:
    """True for a network name under an SSID-named key — offered for review, never redacted."""
    if not (isinstance(value, str) and value and is_ssid_key(key)):
        return False
    from har_capture.sanitization.heuristics import is_safe_value

    active = _active_call_patterns()
    return not is_allowlisted(value, active.allowlist) and not is_safe_value(value, list(active.safe_values))


# The placeholders _redact_value writes for a credential-named field:
# `FIELD_<hex>` with a salt, `***FIELD***` without one, `[REDACTED]` without
# a hasher.
_OWN_FIELD_PLACEHOLDER_RE = re.compile(r"FIELD_[0-9a-f]{8,}|\*\*\*FIELD\*\*\*|\[REDACTED\]")


def _is_own_placeholder(value: str) -> bool:
    """True for a value that is exactly the placeholder this sanitizer writes for a credential field.

    It must also be one ``validate`` accepts (``is_redacted``), so a value
    kept here is never reported there. A real value that merely looks
    redacted (``TP_LINK_20231105``, ``WIFI_Home2024``, ``00000000``) is
    replaced.
    """
    return _OWN_FIELD_PLACEHOLDER_RE.fullmatch(value) is not None and is_redacted(
        value, _active_call_patterns().custom_patterns
    )


def _sanitize_key(
    key: str, taken: dict[str, Any], hasher: Hasher | None, collector: RedactionCollector | None
) -> str:
    """Emit an object key through the text passes, never onto a key already emitted.

    A client table keyed by MAC or address carries PII in its keys, and
    validate reads keys as it reads values. Two keys can hash to one
    placeholder — the same MAC in two cases, or any two MACs in static mode —
    so a collision gets a ``~2``, ``~3`` suffix rather than silently
    dropping a member.
    """
    out_key = _sanitize_json_string(key, hasher, collector)
    if out_key in taken:
        suffix = 2
        while f"{out_key}~{suffix}" in taken:
            suffix += 1
        out_key = f"{out_key}~{suffix}"
    return out_key


def _sanitize_deep_strings(data: Any, hasher: Hasher | None, collector: RedactionCollector | None) -> Any:
    """Past the depth the key rules reach: the string patterns on every key and string.

    Iterative, so no nesting the parser accepted can exhaust the stack. The
    validator's field checks stop at the same depth; its text scans do not,
    and every address or MAC they would find here is rewritten.
    """
    root = [data]
    stack: list[tuple[Any, Any]] = [(root, 0)]
    while stack:
        parent, slot = stack.pop()
        node = parent[slot]
        if isinstance(node, dict):
            rebuilt: dict[str, Any] = {}
            for key, value in node.items():
                rebuilt[_sanitize_key(key, rebuilt, hasher, collector)] = value
            parent[slot] = rebuilt
            stack.extend((rebuilt, key) for key in rebuilt)
        elif isinstance(node, list):
            copied = list(node)
            parent[slot] = copied
            stack.extend((copied, index) for index in range(len(copied)))
        elif isinstance(node, str):
            parent[slot] = _sanitize_json_string(node, hasher, collector)
    return root[0]


def _offerable(text: str) -> bool:
    """False for a field value the text passes turned wholly into a placeholder: nothing is left to review.

    Offering it would also be harmful: in static mode every email becomes
    `x@x.invalid`, and redacting that in the review would rewrite them all.
    """
    return not is_fully_redacted(text, _active_call_patterns().custom_patterns)


def _sanitize_credential_value(
    key: str,
    value: str,
    hasher: Hasher | None,
    collector: RedactionCollector | None,
    depth: int,
    served: bool,
) -> str:
    """A non-empty value under a credential-named JSON key, not a placeholder of ours.

    Submitted, it is redacted. Served, it is judged by its shape
    (``credential_value_action``, shared with validate): a button word is
    kept, prose is offered for review with the string patterns still applied
    inside it, anything else is redacted — and so is prose where no review
    can reach it (no collector, or flags muted inside an encoded payload).
    """
    # A served value equal to a credential the capture submits is that
    # credential echoed back, whatever its shape, unless it is a status word
    # (`Yes`, `No`): those are kept wherever they are served.
    action = credential_value_action(value) if served else "redact"
    if action == "review" and value in _SUBMITTED_CREDENTIALS_CTX.get():
        action = "redact"
    reviewable = action == "review" and collector is not None and collector.accepts_flags
    if action != "keep" and not reviewable:
        return _redact_value(value, hasher, "FIELD", collector)
    mark = collector.flag_mark() if collector is not None else 0
    result: str = _sanitize_json_recursive(value, hasher, collector, depth + 1, served=served)
    if reviewable and collector is not None and _offerable(result):
        # The text as the output holds it, so the review can replace it. LOW:
        # every such value across the fleet is UI text, so the review shows
        # it without pre-selecting it for redaction.
        collector.flag_value(
            result,
            "credential",
            ConfidenceLevel.LOW,
            f"JSON key '{key}'",
            f"Text under credential-named key '{key}' in a response: a UI string, or a passphrase with spaces",
            supersede_since=mark,
        )
    return result


def _sanitize_json_recursive(
    data: Any,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    _depth: int = 0,
    *,
    served: bool = False,
) -> Any:
    """Recursively sanitize JSON data.

    Args:
        data: JSON data (dict, list, or primitive)
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
        _depth: Current recursion depth (internal use)
        served: The JSON is a response body: a value under a credential-named
            key is judged by its shape (``credential_value_action``). A
            submitted body's credential-named values are all redacted.

    Returns:
        Sanitized data
    """
    if _depth > _MAX_RECURSION_DEPTH:
        _LOGGER.warning("Max recursion depth exceeded in JSON sanitization; applying text patterns only")
        return _sanitize_deep_strings(data, hasher, collector)

    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for key, value in data.items():
            # Every rule reads the original key; the key itself is emitted
            # through the string patterns (_sanitize_key).
            out_key = _sanitize_key(key, result, hasher, collector)
            # A key naming a device identity, holding a value of that
            # identity's shape (classify_identity_field, shared with validate).
            identity = classify_identity_field(key, value)
            if is_sensitive_field(key) and isinstance(value, str):
                # An empty value, or a placeholder this sanitizer writes, holds
                # no secret: kept, so an HNAP "Password": "" stays empty and a
                # sanitized value is not hashed again.
                if not value or _is_own_placeholder(value):
                    result[out_key] = value
                else:
                    result[out_key] = _sanitize_credential_value(
                        key, value, hasher, collector, _depth, served
                    )
            elif identity == "mac_address" and not is_constant_mac(str(value)):
                if collector:
                    collector.record_auto_redaction("mac_address")
                result[out_key] = hasher.hash_mac(str(value)) if hasher else "***MAC***"
            elif identity == "serial_number":
                if collector:
                    collector.record_auto_redaction("serial_number")
                result[out_key] = hasher.hash_generic(str(value), "SERIAL") if hasher else "***SERIAL***"
            elif is_flaggable_field(key) and isinstance(value, str) and collector and value:
                # Flagged as the output holds it, so the review can replace it.
                mark = collector.flag_mark()
                result[out_key] = _sanitize_json_recursive(
                    value, hasher, collector, _depth + 1, served=served
                )
                if _offerable(result[out_key]):
                    collector.flag_value(
                        result[out_key],
                        "field",
                        ConfidenceLevel.MEDIUM,
                        f"JSON key '{key}'",
                        f"Flaggable field name '{key}' in JSON",
                        supersede_since=mark,
                    )
            elif collector and _is_reviewable_ssid(key, value):
                # Flagged as the output holds it, so the review can replace it.
                mark = collector.flag_mark()
                result[out_key] = _sanitize_json_recursive(
                    value, hasher, collector, _depth + 1, served=served
                )
                if _offerable(result[out_key]):
                    collector.flag_value(
                        result[out_key],
                        "wifi_ssid",
                        ConfidenceLevel.MEDIUM,
                        f"JSON key '{key}'",
                        f"Wi-Fi network name under SSID key '{key}' in JSON",
                        supersede_since=mark,
                    )
            else:
                result[out_key] = _sanitize_json_recursive(
                    value, hasher, collector, _depth + 1, served=served
                )
        return result
    if isinstance(data, list):
        return [_sanitize_json_recursive(item, hasher, collector, _depth + 1, served=served) for item in data]
    # Apply the text passes to string values
    if isinstance(data, str):
        return _sanitize_json_string(data, hasher, collector)
    return data


# Regex patterns for URL path segment sanitization
_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_API_KEY_PREFIX_PATTERN = re.compile(r"^(?:sk|pk|key)-[a-zA-Z0-9]{16,}$")
_LONG_TOKEN_PATTERN = re.compile(r"^(?=[a-zA-Z]*\d)(?=\d*[a-zA-Z])[a-zA-Z0-9]{32,}$")
_DEVICE_SERIAL_PATTERN = re.compile(r"^[A-Z]{2,6}-[A-Z0-9]{5,}$")

# Regex patterns for value-based sanitization. The IP, IPv6 and email
# regexes are the shared ones in patterns/redaction.py, so a value is
# redacted the same whether its body routes to the HTML engine or here.
_DIGIT_RUN_RE = re.compile(r"\d{3}")
_PHONE_PATTERN = re.compile(
    # At least one separator (or parens / leading +) is required. A bare
    # 10-11 digit run is far more often a constant, counter, or frequency
    # than a phone number — the CM2500 captures flagged the MD5 init
    # constants in the device's md5.js (e.g. 1732584193 = 0x67452301) as
    # phone numbers 31 times per review.
    r"(?<!\w)"  # Not preceded by a word character (prevents matching inside tokens like tok_123...)
    r"(?:"
    r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"  # +1 (555) 123-4567
    r"|"
    r"1[-.\s]\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"  # 1-555-123-4567
    r"|"
    r"\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}"  # (555) 123-4567
    r"|"
    r"\d{3}[-.\s]\d{3}[-.\s]\d{4}"  # 555-123-4567
    r")"
    r"(?!\w)"  # Not followed by a word character (prevents matching inside tokens)
)


def _redact_macs(value: str, hasher: Hasher | None, collector: RedactionCollector | None) -> str:
    """The string patterns' MAC pass (the HTML engine's pass 1): every MAC but a constant one."""

    def replace_mac(match: re.Match[str]) -> str:
        if is_constant_mac(match.group(0)):
            return match.group(0)
        if collector:
            collector.record_auto_redaction("mac_address")
        return hasher.hash_mac(match.group(0)) if hasher else "***MAC***"

    if ":" in value or "-" in value:
        value = MAC_RE.sub(replace_mac, value)
    return value


def _redact_ip_addresses(value: str, hasher: Hasher | None, collector: RedactionCollector | None) -> str:
    """The string patterns' address passes (the HTML engine's 6, 4 and 5): IPv6, private and public IPv4."""

    # IPv6 addresses, before IPv4 so an IPv4-mapped address (`::ffff:1.2.3.4`)
    # is one address. A candidate that is not a host address (a clock time,
    # `::`, `::1`) stays.
    def replace_ipv6(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if not is_ipv6_host_address(candidate):
            return candidate
        if collector:
            collector.record_auto_redaction("ipv6")
        return hasher.hash_ipv6(candidate) if hasher else "***IPV6***"

    if ":" in value:
        value = IPV6_RE.sub(replace_ipv6, value)

    # Private IPs (keep the gateway IPs pii.json and the call's patterns list)
    preserved_ips = _active_call_patterns().preserved_ips

    def replace_private_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if ip in preserved_ips or not is_private_ip_in_range(ip):
            return ip
        if collector:
            collector.record_auto_redaction("private_ip")
        return hasher.hash_ip(ip, is_private=True) if hasher else "***IP***"

    if "." in value:
        value = PRIVATE_IP_RE.sub(replace_private_ip, value)

    # Public IPs (non-private, non-localhost, non-reserved)
    def replace_public_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if not is_valid_ip_address(ip):
            return ip
        if collector:
            collector.record_auto_redaction("public_ip")
        return hasher.hash_ip(ip, is_private=False) if hasher else "***IP***"

    if "." in value:
        value = PUBLIC_IP_RE.sub(replace_public_ip, value)
    return value


def _redact_emails_and_flag_phones(
    value: str, hasher: Hasher | None, collector: RedactionCollector | None
) -> str:
    """The string patterns' email pass (the HTML engine's 11), then phone numbers offered for review.

    Card- and SSN-shaped numbers are the pattern-file pass's (``redact_pattern_file_matches``).
    """

    def replace_email(match: re.Match[str]) -> str:
        if collector:
            collector.record_auto_redaction("email")
        return hasher.hash_email(match.group(0)) if hasher else "***EMAIL***"

    if "@" in value:
        value = EMAIL_RE.sub(replace_email, value)

    # A phone number holds a run of three digits.
    if not _DIGIT_RUN_RE.search(value):
        return value

    # Phone numbers — flag for review instead of auto-redacting
    if collector:
        for match in _PHONE_PATTERN.finditer(value):
            collector.flag_value(
                match.group(0),
                "phone",
                ConfidenceLevel.LOW,
                value[max(0, match.start() - 20) : match.end() + 20],
                "Possible phone number pattern",
            )

    return value


def _sanitize_headers(
    headers: list[dict[str, Any]],
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> None:
    """Sanitize a list of headers in-place.

    Args:
        headers: List of header dicts with 'name' and 'value' keys
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
    """
    for header in headers:
        if isinstance(header, dict) and "name" in header and "value" in header:
            value = header["value"]
            if isinstance(value, str) and str(header["name"]).lower() in URL_VALUED_HEADERS:
                value = _sanitize_url(value, hasher, collector)
            header["value"] = sanitize_header_value(header["name"], value, hasher, collector)


def _url_path(url: str) -> str:
    """Return a URL's path, split by hand like its query (see ``split_url_query``)."""
    head = split_url_query(url)[0].removesuffix("?").partition("#")[0]
    _, scheme_sep, rest = head.partition("://")
    return "/" + rest.partition("/")[2] if scheme_sep else head


def _sanitize_url_path(
    url: str,
    hasher: Hasher | None = None,  # noqa: ARG001
    collector: RedactionCollector | None = None,
) -> str:
    """Flag suspicious path segments in a URL for interactive review.

    Detects UUIDs, API key prefixes (sk-/pk-/key-), and long mixed tokens
    in URL path segments and flags them via the collector. The URL is
    returned unchanged — redaction happens in Pass 2 if the user confirms.

    Args:
        url: Full URL string
        hasher: Optional hasher (unused, kept for call-site consistency)
        collector: Optional collector to record flagged values

    Returns:
        The original URL, unchanged
    """
    path = _url_path(url)
    if not path or path == "/":
        return url

    # Flag suspicious path segments for review instead of auto-redacting
    if collector:
        for segment in path.split("/"):
            if not segment:
                continue
            if _UUID_PATTERN.match(segment):
                collector.flag_value(
                    segment,
                    "uuid",
                    ConfidenceLevel.LOW,
                    url,
                    "UUID in URL path segment",
                )
            elif _API_KEY_PREFIX_PATTERN.match(segment):
                collector.flag_value(
                    segment,
                    "api_key",
                    ConfidenceLevel.HIGH,
                    url,
                    "API key prefix pattern in URL path segment",
                )
            elif _DEVICE_SERIAL_PATTERN.match(segment):
                collector.flag_value(
                    segment,
                    "device_serial",
                    ConfidenceLevel.MEDIUM,
                    url,
                    "Device/serial number pattern in URL path segment",
                )
            elif _LONG_TOKEN_PATTERN.match(segment):
                collector.flag_value(
                    segment,
                    "token",
                    ConfidenceLevel.MEDIUM,
                    url,
                    "Long mixed-case token in URL path segment",
                )

    return url


def _classify_query_param(
    name: str,
    value: str,
    found: QueryCredential | None,
    payload: QueryPayload | None,
) -> str:
    """Decide what happens to one query parameter.

    The single decision tree for the URL string and the parsed ``queryString``
    array, so the two representations of a query always get the same answer.

    Args:
        name: Decoded parameter name
        value: Decoded parameter value
        found: ``find_query_credential`` on the parameter's raw segment
        payload: ``find_query_payload`` on the parameter's raw segment

    Returns:
        ``"auth"``, ``"field"``, ``"payload"``, ``"flag"`` or ``"keep"``
    """
    # A bare or marker-prefixed credential or payload has no field name: any
    # '=' in it is base64 padding, so the name rules must not read it as
    # key=value.
    if found is not None and not found.keyed:
        return "auth"
    if payload is not None and not payload.prefix.rstrip("?"):
        return "payload"
    if is_blank_query_value(value):
        return "keep"
    if is_sensitive_field(name):
        return "field"
    if found is not None:
        return "auth"
    if payload is not None:
        return "payload"
    if is_flaggable_field(name):
        return "flag"
    return "keep"


def _flags_muted(collector: RedactionCollector | None) -> contextlib.AbstractContextManager[None]:
    """Scope inside a base64 payload: redactions recorded, review flags discarded."""
    return collector.flags_muted() if collector is not None else contextlib.nullcontext()


def _dump_json_like(data: Any, original_data: Any, original_text: str) -> str:
    r"""Serialize sanitized JSON the way its original text was written.

    Compact, default spacing, or a 2- or 4-space indent, with non-ASCII
    escaped or written as-is and '/' escaped as PHP writes it (``\/``) —
    whichever reproduces the original exactly — inside the original's
    surrounding whitespace. What ``json.dumps`` cannot reproduce (another
    indent, number spellings like ``1.50``) falls back to default spacing
    with non-ASCII as written.
    """
    body = original_text.strip()
    lead = original_text[: len(original_text) - len(original_text.lstrip())]
    trail = original_text[len(original_text.rstrip()) :]
    slashes_escaped = "\\/" in body and "/" not in body.replace("\\/", "")

    def render(obj: Any, **options: Any) -> str:
        text = json.dumps(obj, **options)
        return text.replace("/", "\\/") if slashes_escaped else text

    layouts: tuple[dict[str, Any], ...] = (
        {"separators": (",", ":")},
        {"separators": (", ", ": ")},
        {"indent": 2},
        {"indent": 4},
    )
    for layout in layouts:
        for ensure_ascii in (False, True):
            if render(original_data, ensure_ascii=ensure_ascii, **layout) == body:
                return lead + render(data, ensure_ascii=ensure_ascii, **layout) + trail
    return lead + render(data, ensure_ascii=False) + trail


def _rewrap_payload(original: str, text: str, *, quoted: bool) -> str:
    """Base64-encode sanitized payload text in the original's transport form.

    Unpadded only if the original visibly stripped its padding — no '=' where
    its length needed one; a full quantum gives no evidence and gets standard
    base64. Percent-encoded if the original was, so a query parser still
    reads it.
    """
    encoded = base64.b64encode(text.encode("utf-8", "surrogatepass")).decode("ascii")
    if not original.endswith("=") and len(original) % 4:
        encoded = encoded.rstrip("=")
    return urllib.parse.quote(encoded, safe="") if quoted else encoded


def _sanitize_base64_payload(
    payload: QueryPayload,
    hasher: Hasher | None,
    collector: RedactionCollector | None,
) -> str | None:
    """Sanitize inside a base64-wrapped JSON or URL query payload and wrap it again.

    A JSON payload gets the JSON rules, a URL payload the query rules — the
    checks ``validate`` runs inside one. Nothing is rewritten when nothing
    inside needed redacting, so an ordinary payload survives byte-for-byte.
    Pass 1 is final inside a payload: its values are stored encoded, beyond
    the reach of Pass 1b and Pass 2's find-and-replace, so none is offered
    for review.

    Args:
        payload: The located payload
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        The re-encoded payload, or None when it is unchanged
    """
    data = parse_json_container(payload.text)
    with _flags_muted(collector):
        if data is not None:
            rewritten_json = _rewrite_json(payload.text, data, hasher, collector)
            sanitized = None if rewritten_json == payload.text else rewritten_json
        else:
            rewritten = _sanitize_url(payload.text, hasher, collector)
            sanitized = None if rewritten == payload.text else rewritten
    return None if sanitized is None else _rewrap_payload(payload.encoded, sanitized, quoted=payload.quoted)


def _sanitize_payload_field(
    value: str,
    hasher: Hasher | None,
    collector: RedactionCollector | None,
) -> str | None:
    """Sanitize a POST field whose whole value is a base64 JSON or URL payload.

    The same rule as a query payload (``_sanitize_base64_payload``): a payload
    is never a credential, and what is inside is sanitized in place.

    Args:
        value: The field's value (raw or decoded — URL transport encoding is undone)
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        The rewritten value, or None when the value is not a payload or is unchanged
    """
    payload = find_query_payload(value)
    if payload is None or payload.prefix.strip("?"):
        return None
    sanitized = _sanitize_base64_payload(payload, hasher, collector)
    return None if sanitized is None else payload.prefix + sanitized


def _flag_query_value(collector: RedactionCollector, name: str, value: str, where: str) -> None:
    """Flag a query parameter value whose name is identity-adjacent."""
    collector.flag_value(
        value,
        "field",
        ConfidenceLevel.MEDIUM,
        f"{where} param '{name}'",
        f"Flaggable field name '{name}' in {where}",
    )


def _sanitize_url(
    url: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Sanitize the credentials a URL carries: its userinfo password and its query.

    Args:
        url: Full URL string
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        URL with the userinfo password and sensitive query values redacted
    """
    userinfo = split_url_password(url)
    if userinfo is not None:
        before_password, password, after_password = userinfo
        url = before_password + _redact_value(password, hasher, "AUTH", collector) + after_password

    # Only the query changes: everything around it (scheme case, an empty
    # ';' or '#', a relative Location) comes back byte-identical. Raw
    # segments, not parse_qsl, which would read base64 padding as a key/value
    # separator.
    before, query, after = split_url_query(url)
    if not query:
        return url

    rebuilt_segments = []
    changed = False
    for segment in query.split("&"):
        found = find_query_credential(segment)
        payload = find_query_payload(segment) if found is None else None
        key, sep, raw_value = segment.partition("=")
        name = urllib.parse.unquote_plus(key)
        value = urllib.parse.unquote_plus(raw_value) if sep else ""
        action = _classify_query_param(name, value, found, payload)
        rebuilt = segment
        if action == "auth" and found is not None:
            rebuilt = found.prefix + _redact_value(found.credential, hasher, "AUTH", collector)
            changed = True
        elif action == "payload" and payload is not None:
            sanitized = _sanitize_base64_payload(payload, hasher, collector)
            if sanitized is not None:
                rebuilt = payload.prefix + sanitized
                changed = True
        elif action == "field":
            rebuilt = f"{key}={_redact_value(value, hasher, 'FIELD', collector)}"
            changed = True
        elif action == "flag" and collector:
            _flag_query_value(collector, name, value, "URL query")
        rebuilt_segments.append(rebuilt)

    if not changed:
        return url

    return before + "&".join(rebuilt_segments) + after


def _sanitize_query_string_array(
    params: list[Any],
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> None:
    """Sanitize a HAR ``queryString`` array in-place, matching the URL string.

    Args:
        params: HAR ``queryString`` entries (already decoded by the query parser)
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
    """
    for param in params:
        if not isinstance(param, dict) or "name" not in param:
            continue
        name = str(param["name"])
        value = str(param.get("value", ""))
        segment = query_param_segment(param)
        found = find_query_credential(segment)
        payload = find_query_payload(segment) if found is None else None
        action = _classify_query_param(name, value, found, payload)
        if action == "payload" and payload is not None:
            sanitized = _sanitize_base64_payload(payload, hasher, collector)
            if sanitized is not None:
                # Re-split the rewritten segment the way the query parser did.
                new_name, _, new_value = (payload.prefix + sanitized).partition("=")
                param["name"], param["value"] = new_name, new_value
        elif action == "auth" and found is not None:
            if found.keyed:
                param["value"] = _redact_value(found.credential, hasher, "AUTH", collector)
            else:
                # The parser may have split the credential at its padding, so
                # the rejoined segment is rewritten whole into the name.
                param["name"] = found.prefix + _redact_value(found.credential, hasher, "AUTH", collector)
                param["value"] = ""
        elif action == "field":
            param["value"] = _redact_value(value, hasher, "FIELD", collector)
        elif action == "flag" and collector:
            _flag_query_value(collector, name, value, "queryString")


def _sanitize_request(
    req: dict[str, Any],
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> None:
    """Sanitize a HAR request object in-place.

    Args:
        req: HAR request object containing headers, postData, and queryString
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
        custom_patterns: Optional custom patterns (file path or dict)
        heuristics: Heuristic mode for content engine
    """
    # Sanitize headers
    if "headers" in req and isinstance(req["headers"], list):
        _sanitize_headers(req["headers"], hasher, collector)

    # Sanitize cookie objects (Playwright parses cookies into structured objects)
    if "cookies" in req and isinstance(req["cookies"], list):
        for cookie in req["cookies"]:
            if isinstance(cookie, dict) and "value" in cookie:
                cookie["value"] = _redact_value(cookie["value"], hasher, "COOKIE", collector)

    # Sanitize POST data
    if "postData" in req:
        req["postData"] = sanitize_post_data(
            req["postData"],
            hasher,
            collector,
            custom_patterns=custom_patterns,
            heuristics=heuristics,
        )

    # Sanitize query string params (in case password is in URL)
    if "queryString" in req and isinstance(req["queryString"], list):
        _sanitize_query_string_array(req["queryString"], hasher, collector)

    # Sanitize the URL string itself (query params and path segments)
    if "url" in req and isinstance(req["url"], str):
        req["url"] = _sanitize_url(req["url"], hasher, collector)
        req["url"] = _sanitize_url_path(req["url"], hasher, collector)


def _sanitize_body_string(
    text: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    serial_detectors: Sequence[Any] = (),
    pattern_file: Sequence[tuple[str, re.Pattern[str], str]] | None = None,
) -> str:
    """Sanitize a text outside the HTML engine in that engine's pass order.

    A text body, or one decoded JSON string — the unit validate checks — so an
    escape hides nothing and no match crosses from one JSON string into the
    next. Besides the string patterns it takes the HTML engine's positional
    passes: labeled serials (pass 2), vendor-format serials (2e) and
    structurally-located credentials (7c), since a device label block in a
    script, or a serial in a JSON string, must not be reported by validate and
    left by sanitize (ADR-13, ADR-14). The order is the HTML engine's — MAC
    (1), serials (2, 2e), IPv6 and IPv4 (6, 4, 5), structural credentials
    (7c), email (11) — so a value two passes could claim (a MAC after a serial
    label, an address in a password's element) gets the same placeholder on
    every route.

    Args:
        text: The text
        hasher: Hasher for the string patterns (None: static placeholders)
        collector: Collector for redaction counts and review flags (None: the
            passes hash with ``hasher``, or static placeholders without one)
        custom_patterns: Optional custom patterns for the allowlist checks
        serial_detectors: Compiled high-confidence vendor serial detectors
        pattern_file: ``pattern_file_patterns()`` resolved for the call (None:
            resolved here from ``custom_patterns``)

    Returns:
        The sanitized text
    """
    if not text:
        return text
    # With no collector the passes that need one hash with the caller's
    # hasher (static placeholders without one), and review flags are discarded.
    passes = collector if collector is not None else RedactionCollector(hasher=hasher or Hasher(salt=None))
    if pattern_file is None:
        pattern_file = pattern_file_patterns(custom_patterns)
    text = redact_pattern_file_matches(text, passes.hasher, passes, pattern_file)
    text = _redact_macs(text, hasher, collector)
    if SERIAL_LABEL_HINT_RE.search(text):
        text = redact_labeled_serials(text, passes.hasher, passes, custom_patterns)
    if serial_detectors:
        text = redact_vendor_serials(text, list(serial_detectors), passes.hasher, passes)
    text = _redact_ip_addresses(text, hasher, collector)
    if "<" in text:
        text = redact_structural_credentials(text, passes.hasher, passes, custom_patterns)
    return _redact_emails_and_flag_phones(text, hasher, collector)


def _sanitize_json_string(value: str, hasher: Hasher | None, collector: RedactionCollector | None) -> str:
    """A decoded JSON string (value or key), as any text outside the HTML engine."""
    active = _active_call_patterns()
    return _sanitize_body_string(
        value, hasher, collector, active.custom_patterns, active.serial_detectors, active.pattern_file
    )


def _sanitize_response_content(
    content: dict[str, Any],
    collector: RedactionCollector | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    url_credential: str | None = None,
) -> None:
    """Sanitize response content in-place.

    The body is decoded first (``decode_transport_body``): HAR's ``encoding:
    base64`` is how the recorder stored the bytes, not what the server sent,
    so a transport-encoded body is sanitized as the text it carries and
    written back as that text, ``encoding`` dropped. Binary stays as
    recorded.

    Args:
        content: HAR response content object with 'text' and 'mimeType' keys
        collector: Optional collector with hasher for redaction
        custom_patterns: Optional custom patterns (file path or dict)
        heuristics: Heuristic mode for pipe-delimited value detection
        url_credential: Base64 credential from the request URL (if any). When
            provided, a response body that looks like a base64 credential is
            only redacted if it echoes that credential — opaque server-issued
            session tokens are preserved for replay fidelity.
    """
    text = decode_transport_body(content)
    if text is None:
        # An earlier release wiped some transport-encoded bodies to an AUTH_
        # placeholder under `encoding: base64`, which no decoder accepts. The
        # placeholder is text; the marker is what makes the body invalid.
        raw = content.get("text")
        if content.get("encoding") == "base64" and isinstance(raw, str) and is_fully_redacted(raw):
            del content["encoding"]
        return
    if content.get("encoding") == "base64":
        del content["encoding"]
    content["text"] = _sanitize_body_text(
        text, str(content.get("mimeType") or ""), collector, custom_patterns, heuristics, url_credential
    )


def _sanitize_body_text(
    text: str,
    mime_type: str,
    collector: RedactionCollector | None,
    custom_patterns: str | dict[str, Any] | None,
    heuristics: HeuristicMode,
    url_credential: str | None,
) -> str:
    """Sanitize a response body's text: the one dispatch for every body.

    In order: a body that is itself base64 of a JSON object or URL is
    sanitized as the text it wraps — the whole dispatch, so every check
    ``validate`` runs on it has a remedy — and wrapped again; a bare base64
    credential is redacted whole unless it is a server token (see
    ``_is_echoed_credential``); anything else goes to the engine
    ``route_body`` picks.

    Args:
        text: The body's text, transport encoding already undone
        mime_type: The body's declared mime type
        collector: Optional collector with hasher for redaction
        custom_patterns: Optional custom patterns (file path or dict)
        heuristics: Heuristic mode for pipe-delimited value detection
        url_credential: Base64 credential from the request URL (if any)

    Returns:
        The sanitized text
    """
    hasher = collector.hasher if collector else None
    stripped = text.strip()

    payload_text = decode_base64_payload(stripped)
    if payload_text is not None:
        with _flags_muted(collector):
            inner = payload_text
            if parse_json_container(inner) is None:
                inner = _sanitize_url(inner, hasher, collector)
            inner = _sanitize_body_text(inner, "", collector, custom_patterns, heuristics, url_credential)
        if inner == payload_text:
            return text
        return _rewrap_payload(stripped, inner, quoted=False)

    if is_base64_credential(stripped) and (
        url_credential is None or _is_echoed_credential(stripped, url_credential)
    ):
        return _redact_value(stripped, hasher, "AUTH", collector)

    route, data = route_body(mime_type, text)
    if route == "html":
        return sanitize_html(
            text, collector=collector, custom_patterns=custom_patterns, heuristics=heuristics
        )

    if route == "json" and data is not None:
        return _rewrite_json(text, data, hasher, collector, served=True)

    return _sanitize_body_string(
        text, hasher, collector, custom_patterns, _resolve_serial_detectors(custom_patterns)
    )


def _sanitize_response(
    resp: dict[str, Any],
    collector: RedactionCollector | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    url_credential: str | None = None,
) -> None:
    """Sanitize a HAR response object in-place.

    Args:
        resp: HAR response object containing headers and content
        collector: Optional collector with hasher for redaction
        custom_patterns: Optional custom patterns (file path or dict)
        heuristics: Heuristic mode for pipe-delimited value detection
        url_credential: Base64 credential from the paired request URL (if any).
            Forwarded to ``_sanitize_response_content`` for the server-token
            preservation heuristic.
    """
    hasher = collector.hasher if collector else None

    # Sanitize headers
    if "headers" in resp and isinstance(resp["headers"], list):
        _sanitize_headers(resp["headers"], hasher, collector)

    # HAR's copy of the Location header
    if isinstance(resp.get("redirectURL"), str):
        resp["redirectURL"] = _sanitize_url(resp["redirectURL"], hasher, collector)

    # Sanitize cookie objects (Playwright parses Set-Cookie into structured objects)
    if "cookies" in resp and isinstance(resp["cookies"], list):
        for cookie in resp["cookies"]:
            if isinstance(cookie, dict) and "value" in cookie:
                cookie["value"] = _redact_value(cookie["value"], hasher, "COOKIE", collector)

    # Sanitize response content
    if "content" in resp and isinstance(resp["content"], dict):
        _sanitize_response_content(resp["content"], collector, custom_patterns, heuristics, url_credential)


def sanitize_entry(
    entry: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    collector: RedactionCollector | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    _skip_copy: bool = False,
    _url_credential: str | None = None,
) -> dict[str, Any]:
    """Sanitize a single HAR entry (request/response pair).

    Args:
        entry: HAR entry object
        salt: Salt for hashed redaction (ignored if collector provided)
        custom_patterns: Optional additive custom patterns (file path or dict
            matching the ``load_sensitive_patterns`` schema). Extends the
            built-in ``pii.patterns``, allowlist, sensitive-field sets
            (``fields.auto_redact_patterns`` / ``fields.flag_patterns``), and
            header sets (``headers.full_redact`` / ``headers.cookie_redact``)
            for this call only. Both the field-pattern and header-set scopes
            are entered at this level, so every downstream detection site —
            request/response headers, cookies, ``queryString`` params, URL
            query params, POST bodies (form / JSON / XML), and inline-script
            scanners — sees the extensions. Module-global state is never
            mutated. See ``sanitize_post_data`` for the full contract.
        collector: Optional collector for tracking redactions
        heuristics: Heuristic mode for pipe-delimited value detection
        _skip_copy: If True, skip deep copy (caller already copied). Internal use only.

    Returns:
        Sanitized entry
    """
    result = entry if _skip_copy else copy.deepcopy(entry)

    # Use collector's hasher if provided, otherwise create one
    if collector is None and salt:
        hasher = Hasher.create(salt)
        collector = RedactionCollector(hasher=hasher)
    elif collector is None:
        # No salt and no collector - create collector with no hashing
        collector = RedactionCollector(hasher=Hasher.create(None))

    with (
        _field_patterns_scope(custom_patterns),
        _header_sets_scope(custom_patterns),
        _call_patterns_scope(custom_patterns),
    ):
        if "request" in result:
            _sanitize_request(result["request"], collector.hasher, collector, custom_patterns, heuristics)

        if "response" in result:
            _sanitize_response(result["response"], collector, custom_patterns, heuristics, _url_credential)

        _sanitize_security_details(result, collector)

    return result


# Names a self-signed certificate is issued to by default, not by an owner.
_LOOPBACK_CERTIFICATE_NAMES = frozenset({"localhost", "localhost.localdomain"})


def _sanitize_security_details(entry: dict[str, Any], collector: RedactionCollector) -> None:
    """Redact the device identities in an entry's TLS certificate names (ADR-17).

    A MAC in ``_securityDetails.subjectName`` or ``issuer`` is hashed in
    place, in its own layout, so it correlates with the same MAC elsewhere
    (``certificate_name_macs``, shared with validate). A self-signed name with
    no MAC — a model name, a vendor hostname, or a name its owner set — is
    offered for review. ``protocol``, ``validFrom`` and ``validTo`` are kept.
    """
    details = entry.get("_securityDetails")
    if not isinstance(details, dict):
        return
    subject, issuer = details.get("subjectName"), details.get("issuer")
    for field in CERTIFICATE_NAME_FIELDS:
        name = details.get(field)
        if not isinstance(name, str):
            continue
        for mac in dict.fromkeys(certificate_name_macs(name)):
            if not is_mac_placeholder(mac):
                collector.record_auto_redaction("mac_address")
                name = name.replace(mac, collector.hasher.hash_mac(mac))
        details[field] = name
    if (
        isinstance(subject, str)
        and subject
        and subject == issuer
        and details["subjectName"] == subject
        and subject not in _LOOPBACK_CERTIFICATE_NAMES
        and not is_redacted(subject, _active_call_patterns().custom_patterns)
    ):
        collector.flag_value(
            subject,
            "device_name",
            ConfidenceLevel.LOW,
            "TLS certificate subject",
            "Self-signed certificate name: a model or vendor hostname, or a name the device's owner set",
        )


def _embed_sanitization_metadata(
    har_data: dict[str, Any],
    report: SanitizationReport,
    heuristics: HeuristicMode,
    salt: str | None,
) -> None:
    """Embed sanitization metadata into the HAR for self-describing output.

    Records tool version, timestamp, salt mode, heuristic mode, and redaction
    counts into ``log._har_capture.sanitization``. Does **not** leak the actual
    salt value.
    """
    from datetime import datetime, timezone

    from har_capture import __version__

    if salt in ("auto", "random"):
        salt_mode = "random"
    elif salt is None:
        salt_mode = "static"
    else:
        salt_mode = "provided"

    metadata = har_data.setdefault("log", {}).setdefault("_har_capture", {})
    metadata["sanitization"] = {
        "tool": "har-capture",
        "version": __version__,
        "sanitized_at": datetime.now(tz=timezone.utc).isoformat(),
        "salt_mode": salt_mode,
        "heuristics": heuristics.value,
        "auto_redacted": report.total_auto_redacted,
        "auto_redacted_counts": dict(report.auto_redacted_counts),
        "user_redacted": report.total_user_redacted,
        "user_skipped": report.total_user_skipped,
        "flagged_total": len(report.flagged),
        "warnings": list(report.warnings),
    }
    if not report.flagged:
        # Nothing to review, so the outcome is known now; any other outcome
        # is recorded by whoever runs the review (record_review).
        metadata["sanitization"]["review"] = ReviewOutcome.NONE_FLAGGED.value


def _parse_cookie_names(cookie_header_value: str) -> list[str]:
    """Parse cookie names from a Cookie request header value."""
    names = []
    for raw in cookie_header_value.split(";"):
        part = raw.strip()
        if "=" in part:
            name = part.split("=", 1)[0].strip()
            if name:
                names.append(name)
    return names


def _parse_set_cookie_name(set_cookie_value: str) -> str | None:
    """Parse the cookie name from a Set-Cookie response header value."""
    first = set_cookie_value.split(";", 1)[0].strip()
    if "=" in first:
        name = first.split("=", 1)[0].strip()
        return name or None
    return None


def _scan_submitted_credentials(entries: list[Any]) -> frozenset[str]:
    """Every value the capture's requests submit under a credential-named field.

    Every request's ``postData`` — its ``params``, and its text read as JSON
    members (to ``JSON_MAX_DEPTH``) when it parses as JSON, else as
    ``&``-separated form pairs when it holds ``=`` — and the ``queryString``
    array, judged by ``is_sensitive_field``. Read before
    sanitizing, so a response served before the request that submits the same
    value is matched too. Empty values and this sanitizer's own placeholders
    are not credentials. XML, multipart and base64-wrapped bodies are not
    parsed as such (one holding ``=`` is split as form pairs like any other
    text), and a URL query with no ``queryString`` array is not read: a served
    copy of a value submitted only there is judged by its shape alone, which
    offers prose for review (none of these occurs in the fleet's requests).
    """
    found: set[str] = set()
    for entry in entries:
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        post = request.get("postData")
        post = post if isinstance(post, dict) else {}
        pairs: list[tuple[str, Any]] = []
        for params in (request.get("queryString"), post.get("params")):
            for param in params if isinstance(params, list) else ():
                if isinstance(param, dict):
                    pairs.append((str(param.get("name", "")), param.get("value")))
        text = post.get("text")
        if isinstance(text, str) and text:
            data = parse_json_container(text)
            if data is not None:
                pairs.extend(_json_members_to_depth(data))
            elif "=" in text:
                for pair in text.split("&"):
                    key, _, value = pair.partition("=")
                    pairs.append((urllib.parse.unquote_plus(key), urllib.parse.unquote_plus(value)))
        found.update(
            value
            for key, value in pairs
            if isinstance(value, str) and value and not _is_own_placeholder(value) and is_sensitive_field(key)
        )
    return frozenset(found)


def _json_members_to_depth(data: Any) -> list[tuple[str, Any]]:
    """Every ``(key, value)`` member of a parsed JSON container, down to ``JSON_MAX_DEPTH``."""
    members: list[tuple[str, Any]] = []
    stack: list[tuple[Any, int]] = [(data, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > JSON_MAX_DEPTH:
            continue
        children = json_members(node) if isinstance(node, dict) else [("", item) for item in node]
        if isinstance(node, dict):
            members.extend(children)
        stack.extend((value, depth + 1) for _, value in children if isinstance(value, dict | list))
    return members


def _readable_text(har_data: dict[str, Any]) -> str:
    """Every string in a HAR, with each JSON body's decoded strings: what the review's find-and-replace can reach."""
    parts: list[str] = []
    stack: list[Any] = [har_data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            parts.append(node)
            parsed = parse_json_container(node)
            if parsed is not None:
                parts.extend(iter_json_strings(parsed))
    return "\n".join(parts)


def _scan_url_credentials(entries: list[Any]) -> dict[int, str]:
    """Map entry index to the URL credential its request carries.

    Must run on the original (pre-sanitization) entries: once the sanitizer
    writes ``AUTH_<hash>`` the credential is no longer recognizable. The keys
    become the ``_sanitized_credentials`` annotation; the values feed the
    server-token preservation guard.
    """
    credentials: dict[int, str] = {}
    for i, entry in enumerate(entries):
        request = entry.get("request") if isinstance(entry, dict) else None
        found = next(iter_url_credentials(request), None) if isinstance(request, dict) else None
        if found is not None:
            credentials[i] = found.credential
    return credentials


def _is_echoed_credential(body: str, url_credential: str) -> bool:
    """True if body echoes the URL credential or a decoded component of it.

    Returns True when body matches the credential exactly, or equals
    btoa(user), btoa(password), or btoa(user:password) derived from it.
    Returns False for opaque server-issued tokens.
    """
    if body == url_credential:
        return True
    try:
        padded = url_credential.rstrip("=")
        padded += "=" * (-len(padded) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
    except Exception:
        return False
    if ":" not in decoded:
        return False
    user, _, password = decoded.partition(":")
    return any(body == base64.b64encode(part.encode()).decode() for part in (user, password, decoded))


def _detect_client_side_cookies(entries: list[dict[str, Any]]) -> list[str]:
    """Return cookie names from request headers never set by any Set-Cookie response.

    Scans all entries for Set-Cookie response header names, then returns any
    cookie name found in a request Cookie header that never appeared in a
    Set-Cookie header across the entire capture. Order of first appearance in
    request headers is preserved; duplicates are suppressed.
    """
    set_cookie_names: set[str] = set()
    request_cookie_names: list[str] = []
    seen: set[str] = set()

    for entry in entries:
        for header in entry.get("response", {}).get("headers", []):
            if isinstance(header, dict) and header.get("name", "").lower() == "set-cookie":
                name = _parse_set_cookie_name(header.get("value", ""))
                if name:
                    set_cookie_names.add(name)

        for header in entry.get("request", {}).get("headers", []):
            if isinstance(header, dict) and header.get("name", "").lower() == "cookie":
                for name in _parse_cookie_names(header.get("value", "")):
                    if name not in seen:
                        seen.add(name)
                        request_cookie_names.append(name)

    return [n for n in request_cookie_names if n not in set_cookie_names]


# Pass 1b propagation eligibility. See SANITIZATION_SPEC "Pass 1b: Redacted-Value
# Propagation". These do not decide whether a value is a secret — Pass 1 already
# did. They decide whether a textual match elsewhere in the file is necessarily
# the same secret rather than a coincidence.
_PROPAGATION_MIN_LENGTH = 16
_PROPAGATION_CHARSET_RE = re.compile(r"^[A-Za-z0-9._~+/=:-]+$")
_PROPAGATION_DIGIT_RE = re.compile(r"\d")


def _is_propagation_eligible(value: str) -> bool:
    """Check whether a redacted value is safe to replace globally across the HAR.

    Failing this is not a leak — the value keeps the pre-existing behavior and
    stays flagged for interactive review. That is what lets the bar be strict.

    Args:
        value: The pre-redaction value

    Returns:
        True if every textual match of this value must be the same secret
    """
    from har_capture.sanitization.heuristics import is_safe_value

    if len(value) < _PROPAGATION_MIN_LENGTH:
        return False
    if not _PROPAGATION_CHARSET_RE.match(value):
        return False
    # Method names and config keys are alphabetic (GetDeviceInformation); opaque
    # tokens carry digits. This is the operative form of "must not be word-shaped".
    if not _PROPAGATION_DIGIT_RE.search(value):
        return False
    return not is_safe_value(value)


def _propagation_search_keys(registry: dict[str, str]) -> list[tuple[str, str]]:
    """Expand eligible redacted values into the needles to search for.

    Each value contributes its literal form plus its percent-encoded form, so a
    secret that had to be escaped to sit in a URL path is still matched. Both
    map to the same placeholder — an encoding difference must not break
    correlation, which is the same rule the form-urlencoded branch follows.

    Ordered longest first: when one value is a prefix of another (a token and a
    token-plus-suffix), replacing the shorter one first would substitute inside
    the longer one and emit a corrupted hybrid.

    Args:
        registry: Original value -> placeholder, from RedactionCollector

    Returns:
        (needle, placeholder) pairs, longest needle first
    """
    needles: dict[str, str] = {}
    for original, placeholder in registry.items():
        if not _is_propagation_eligible(original):
            continue
        needles.setdefault(original, placeholder)
        encoded = urllib.parse.quote(original, safe="")
        if encoded != original:
            needles.setdefault(encoded, placeholder)
    return sorted(needles.items(), key=lambda item: -len(item[0]))


def _propagate_redacted_values(har_data: dict[str, Any], registry: dict[str, str]) -> int:
    """Replace remaining verbatim occurrences of already-redacted values in-place.

    Substitution is one token for one token, so path segment count, query shape,
    and delimiters are preserved. Matching is exact and case-sensitive.

    Args:
        har_data: The sanitized HAR data (mutated in place)
        registry: Original value -> placeholder, from RedactionCollector

    Returns:
        Number of occurrences replaced
    """
    search_keys = _propagation_search_keys(registry)
    if not search_keys:
        return 0

    try:
        content = json.dumps(har_data)
    except (TypeError, ValueError) as e:
        _LOGGER.warning("Propagation skipped, HAR is not serializable: %s", e)
        return 0

    replacements = 0
    for needle, placeholder in search_keys:
        # Escape for JSON string context (quotes, backslashes, control chars),
        # mirroring apply_user_redactions.
        escaped_needle = json.dumps(needle)[1:-1]
        occurrences = content.count(escaped_needle)
        if occurrences:
            content = content.replace(escaped_needle, json.dumps(placeholder)[1:-1])
            replacements += occurrences

    if not replacements:
        return 0

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        _LOGGER.warning("Propagation reverted, HAR did not survive round-trip: %s", e)
        return 0

    har_data.clear()
    har_data.update(parsed)
    return replacements


def sanitize_har(
    har_data: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> tuple[dict[str, Any], SanitizationReport]:
    """Sanitize an entire HAR file.

    Args:
        har_data: Parsed HAR JSON data
        salt: Salt for hashed redaction. Options:
            - "auto" (default): Random salt, correlates within this call
            - None: Static placeholders (legacy behavior)
            - Any string: Consistent hashing across calls with same salt
        custom_patterns: Optional additive custom patterns (file path or dict
            matching the ``load_sensitive_patterns`` schema). Extends the
            built-in ``pii.patterns``, allowlist, and sensitive-field sets
            (``fields.auto_redact_patterns`` / ``fields.flag_patterns``) for
            this call only. Applies across every entry: request/response
            headers, POST params and bodies (form / JSON / XML), and any
            inline-script field matching inside HTML content. Module-global
            state is never mutated. See ``sanitize_post_data`` for the full
            contract.
        heuristics: Heuristic mode for pipe-delimited value detection

    Returns:
        Tuple of (sanitized HAR data, sanitization report)

    Note:
        This is a BREAKING CHANGE from the previous return type (dict only).
        Callers that only need the sanitized data can unpack with:
        result, _ = sanitize_har(...)

    Example:
        >>> import json
        >>> har = {"log": {"entries": []}}
        >>> sanitized, report = sanitize_har(har)
        >>> "log" in sanitized
        True
    """
    # Generate salt upfront so it can be stored in report
    actual_salt: str
    if salt in ("auto", "random"):
        actual_salt = Hasher.generate_salt()
    elif salt is None:
        actual_salt = ""
    else:
        actual_salt = salt

    # Create collector with the salt
    hasher = Hasher.create(actual_salt or None)
    collector = RedactionCollector(hasher=hasher)

    result = copy.deepcopy(har_data)

    if "log" not in result:
        _LOGGER.warning("HAR data missing 'log' key")
        report = collector.to_report("", "", actual_salt)
        return result, report

    log = result["log"]

    # Pre-scan the original entries: sanitization replaces the credentials it
    # is looking for.
    orig_entries = har_data.get("log", {}).get("entries", [])
    url_credentials = _scan_url_credentials(orig_entries) if isinstance(orig_entries, list) else {}
    with _field_patterns_scope(custom_patterns):
        submitted = (
            _scan_submitted_credentials(orig_entries) if isinstance(orig_entries, list) else frozenset()
        )

    # Sanitize all entries using the shared collector, the call's patterns
    # resolved once for all of them.
    if "entries" in log and isinstance(log["entries"], list):
        sanitized_entries = []
        submitted_token = _SUBMITTED_CREDENTIALS_CTX.set(submitted)
        try:
            with _call_patterns_scope(custom_patterns):
                for i, entry in enumerate(log["entries"]):
                    sanitized_entries.append(
                        sanitize_entry(
                            entry,
                            custom_patterns=custom_patterns,
                            collector=collector,
                            heuristics=heuristics,
                            _skip_copy=True,
                            _url_credential=url_credentials.get(i),
                        )
                    )
        finally:
            _SUBMITTED_CREDENTIALS_CTX.reset(submitted_token)
        log["entries"] = sanitized_entries

    # Sanitize pages (if present) using the shared collector
    if "pages" in log and isinstance(log["pages"], list):
        for page in log["pages"]:
            if isinstance(page, dict) and "title" in page:
                page["title"] = sanitize_html(
                    page["title"],
                    collector=collector,
                    custom_patterns=custom_patterns,
                    heuristics=heuristics,
                )

    # Sanitize browser_cookies in _har_capture metadata
    har_capture_meta = log.get("_har_capture", {})
    if isinstance(har_capture_meta.get("browser_cookies"), list):
        for cookie in har_capture_meta["browser_cookies"]:
            if isinstance(cookie, dict) and "value" in cookie:
                cookie["value"] = _redact_value(cookie["value"], hasher, "COOKIE", collector)

    # Sanitize web storage (localStorage + sessionStorage) in _har_capture metadata
    for storage_key in ("local_storage", "session_storage"):
        storage_list = har_capture_meta.get(storage_key)
        if isinstance(storage_list, list):
            for origin_entry in storage_list:
                if not isinstance(origin_entry, dict):
                    continue
                for item in origin_entry.get("items", []):
                    if isinstance(item, dict) and "value" in item:
                        item["value"] = _redact_value(item["value"], hasher, "STORAGE", collector)

    # Annotate cookies set client-side (via JavaScript, not Set-Cookie)
    if "entries" in log and isinstance(log["entries"], list):
        client_side = _detect_client_side_cookies(log["entries"])
        meta = log.setdefault("_har_capture", {})
        meta["_client_side_cookies"] = client_side
        # A file sanitized before keeps its annotation: this run cannot
        # recognize the AUTH_ placeholders the earlier one wrote.
        prior = {i for i in annotated_url_credential_entries(log) if 0 <= i < len(log["entries"])}
        meta["_sanitized_credentials"] = [
            {"entry_index": i, "location": "url_query_param"} for i in sorted(prior | url_credentials.keys())
        ]

    # Pass 1b: replace values already redacted elsewhere that survived verbatim on
    # surfaces with no field name to match (most commonly a URL path segment).
    propagated = _propagate_redacted_values(result, collector.redacted_values)
    if propagated:
        collector.auto_redacted_counts["propagated"] = propagated
        # A value with no surviving occurrence left would give the user a review
        # decision with no effect, so it leaves the review queue. One that
        # survives in a form the sweep does not match (`\/` in a PHP body, an
        # ASCII-escaped JSON string) stays offered.
        # Only a flagged value can leave the queue, so the flagged values are
        # the ones searched: searching every redacted value made this
        # quadratic in a capture whose session cookie rotates per request.
        readable = _readable_text(result)
        collector.drop_flagged(
            {
                v
                for v in (flagged.original_value for flagged in collector.flagged)
                if v in collector.redacted_values and _is_propagation_eligible(v) and v not in readable
            }
        )

    # Create report with all collected data
    report = collector.to_report("", "", actual_salt)

    _embed_sanitization_metadata(result, report, heuristics, salt)

    return result, report


def sanitize_har_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    max_size: int | None = DEFAULT_MAX_HAR_SIZE,
    validate: bool = True,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> tuple[str, SanitizationReport]:
    """Sanitize a HAR file and write to a new file.

    Args:
        input_path: Path to input HAR file
        output_path: Path to output file (default: input_path with .sanitized.har suffix)
        salt: Salt for hashed redaction
        custom_patterns: Optional additive custom patterns (file path or dict
            matching the ``load_sensitive_patterns`` schema). Extends the
            built-in ``pii.patterns``, allowlist, and sensitive-field sets
            (``fields.auto_redact_patterns`` / ``fields.flag_patterns``) for
            this call only. Applied consistently across every entry in the
            HAR — request/response headers, POST bodies, and inline-script
            scanners inside HTML content. Module-global state is never
            mutated. See ``sanitize_post_data`` for the full contract and
            ``docs/CUSTOM_PATTERNS.md`` for worked examples.
        max_size: Maximum file size in bytes (default: 100MB). Set to None to disable.
        validate: If True, validate HAR structure before processing (default: True)
        heuristics: Heuristic mode for pipe-delimited value detection

    Returns:
        Tuple of (output_path, sanitization report)

    Note:
        This is a BREAKING CHANGE from the previous return type (str only).
        Callers that only need the output path can unpack with:
        output_path, _ = sanitize_har_file(...)

    Raises:
        HarSizeError: If file exceeds max_size limit
        HarValidationError: If HAR structure is invalid (when validate=True)
        FileNotFoundError: If input file doesn't exist
        json.JSONDecodeError: If file is not valid JSON

    Example:
        >>> # output, report = sanitize_har_file("device.har")  # Creates device.sanitized.har
        >>> # output, report = sanitize_har_file("device.har", "clean.har")  # Creates clean.har
        >>> # output, report = sanitize_har_file("large.har", max_size=None)  # No size limit
        >>> # output, report = sanitize_har_file("file.har", validate=False)  # Skip validation
    """
    from pathlib import Path as PathlibPath

    input_path = PathlibPath(input_path)
    input_str = str(input_path)

    # Check file size before reading
    if max_size is not None:
        file_size = input_path.stat().st_size
        if file_size > max_size:
            raise HarSizeError(file_size, max_size)

    if output_path is None:
        if input_str.endswith(".har"):
            output_str = input_str[:-4] + ".sanitized.har"
        else:
            output_str = input_str + ".sanitized.har"
    else:
        output_str = str(output_path)

    with open(input_str, encoding="utf-8") as f:
        har_data = json.load(f)

    # Validate HAR structure
    if validate:
        warnings = validate_har_structure(har_data)
        for warning in warnings:
            _LOGGER.warning("HAR validation: %s", warning)

    sanitized, report = sanitize_har(
        har_data,
        salt=salt,
        custom_patterns=custom_patterns,
        heuristics=heuristics,
    )

    # Fill in file paths in report
    report.input_file = input_str
    report.output_file = output_str

    # newline="\n": the sanitized HAR is committed as evidence in downstream
    # repos that enforce LF. Text mode would translate to CRLF on Windows,
    # making the same capture byte-different per platform.
    with open(output_str, "w", encoding="utf-8", newline="\n") as f:
        json.dump(sanitized, f, indent=2)

    _LOGGER.info("Sanitized HAR written to: %s", output_str)
    return output_str, report


def _validate_har_for_redaction(har_data: dict[str, Any]) -> None:
    """Validate HAR structure before applying redactions.

    Args:
        har_data: The HAR data to validate

    Raises:
        HarValidationError: If structure is invalid
    """
    if not isinstance(har_data, dict):
        raise HarValidationError("har_data must be a dictionary")

    if "log" not in har_data:
        raise HarValidationError("Missing required 'log' key", "root")


def _user_redaction_forms(value: str) -> set[str]:
    r"""Every text a HAR string can hold ``value`` as.

    As written; percent-encoded, as a URL path (``/`` kept), a query value or a
    form body (``+`` for space) carries it; and escaped, as a JSON body inside
    the string carries it (``\"``, ``\u00e9``, PHP's ``\/``).
    """
    forms = {
        value,
        urllib.parse.quote(value),
        urllib.parse.quote(value, safe=""),
        urllib.parse.quote_plus(value),
    }
    for escaped in (json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]):
        forms.update((escaped, escaped.replace("/", "\\/")))
    return forms


def _replace_in_string_values(data: Any, replacements: dict[str, str]) -> None:
    """Replace each form with its placeholder inside every string value of ``data``, in place.

    Keys, numbers and every other JSON structure are left alone, so no value
    can corrupt the HAR (``200`` is not a status code's digits, ``name`` is
    not a key). One matcher per call, longest form first at each position, so
    a form is never matched inside a placeholder already written.
    """
    pattern = re.compile("|".join(re.escape(form) for form in sorted(replacements, key=len, reverse=True)))
    stack: list[Any] = [data]
    while stack:
        node = stack.pop()
        slots = list(node.items()) if isinstance(node, dict) else list(enumerate(node))
        for slot, child in slots:
            if isinstance(child, str):
                node[slot] = pattern.sub(lambda match: replacements[match.group(0)], child)
            elif isinstance(child, dict | list):
                stack.append(child)


def apply_user_redactions(
    har_data: dict[str, Any],
    report: SanitizationReport,
) -> dict[str, Any]:
    """Apply user redaction decisions via global find-replace.

    This is Pass 2 of the two-pass sanitization flow. For each value the user
    chose to redact, replace ALL occurrences in the HAR data.

    The hasher is recreated from report.salt to ensure consistent hashing
    with Pass 1.

    Args:
        har_data: The HAR data (already sanitized by Pass 1)
        report: The sanitization report with user decisions

    Returns:
        HAR data with user-selected redactions applied

    Raises:
        HarValidationError: If har_data is invalid or malformed

    Note:
        This function modifies the report in-place to set redacted_value
        for each user-redacted item.
    """
    from har_capture.sanitization.report import RedactionStatus

    # Validate input
    _validate_har_for_redaction(har_data)

    # Count redactions to apply
    redactions_to_apply = [item for item in report.flagged if item.status == RedactionStatus.USER_REDACTED]

    if not redactions_to_apply:
        _LOGGER.debug("No user redactions to apply")
        return har_data

    _LOGGER.debug("Applying %d user redaction(s)", len(redactions_to_apply))

    # Recreate hasher with same salt used in Pass 1
    hasher = Hasher.create(report.salt or None)

    # Work on a deep copy to avoid modifying original
    result = copy.deepcopy(har_data)

    try:
        # A HAR that cannot be serialized cannot be written back either.
        json.dumps(result)
    except (TypeError, ValueError) as e:
        raise HarValidationError(f"Failed to serialize HAR data: {e}") from e

    # Every form of every chosen value, mapped to its placeholder. A value
    # can contain another offered value (a username holding a phone number):
    # longest originals claim a shared form first, and the matcher tries
    # longest forms first, so the outer value is replaced whole.
    replacements: dict[str, str] = {}
    for item in sorted(redactions_to_apply, key=lambda flagged: len(flagged.original_value), reverse=True):
        try:
            # Generate redacted value via the category→prefix map, so
            # user redactions carry the same placeholder prefixes as
            # auto-redactions (CRED_, WIFI_, SERIAL_, ...). Building the
            # prefix from the raw category name produced placeholders
            # like CREDENTIAL_/SERIAL_NUMBER_ that the allowlist and
            # safe-value patterns did not all recognize as redacted.
            redacted = hasher.hash_sensitive_value(item.original_value, item.category)
            item.redacted_value = redacted
            for form in _user_redaction_forms(item.original_value):
                replacements.setdefault(form, redacted)
        except Exception as e:  # noqa: PERF203 - intentional: continue with other redactions on error
            _LOGGER.warning("Failed to redact flagged item (category=%s): %s", item.category, e)
            continue

    parsed = result
    if replacements:
        _replace_in_string_values(parsed, replacements)

    # Refresh the embedded metadata's user-decision counts. The metadata was
    # embedded at the end of Pass 1, before any review decision existed, so
    # without this a reviewed artifact reports user_redacted: 0 forever
    # (observed on the CM2500 contributor capture, 2026-08-19).
    sanitization_meta = parsed.get("log", {}).get("_har_capture", {}).get("sanitization")
    if isinstance(sanitization_meta, dict):
        sanitization_meta["user_redacted"] = report.total_user_redacted
        sanitization_meta["user_skipped"] = report.total_user_skipped

    return parsed


def appears_sanitized(har_data: dict[str, Any], threshold: int = 10) -> tuple[bool, int]:
    """Check if a HAR file appears to already be sanitized.

    Looks for redaction placeholders that indicate the file has been
    previously processed by the sanitizer.

    Args:
        har_data: Parsed HAR JSON data
        threshold: Minimum number of redaction patterns to consider file sanitized

    Returns:
        Tuple of (appears_sanitized, match_count)
    """
    content = json.dumps(har_data)

    # Patterns that indicate redacted values
    redaction_patterns = [
        r"MAC_[a-f0-9]{8}",  # Hashed MAC addresses
        r"PASS_[a-f0-9]{8}",  # Hashed passwords
        r"TOKEN_[a-f0-9]{8}",  # Hashed tokens
        r"SERIAL_[a-f0-9]{8}",  # Hashed serial numbers
        r"WIFI_[a-f0-9]{8}",  # Hashed WiFi credentials
        r"DEVICE_[a-f0-9]{8}",  # Hashed device names
        r"PRIV_IP_[a-f0-9]{8}",  # Hashed private IPs (old format)
        r"\*\*\*[A-Z]+\*\*\*",  # Static placeholders
        r"10\.255\.\d+\.\d+",  # Hashed private IPs
        r"192\.0\.2\.\d+",  # Hashed public IPs (TEST-NET-1)
        r"user_[a-f0-9]{8}@redacted\.invalid",  # Hashed emails
    ]

    # Hashed MACs: the MACs in the document that the allowlist calls placeholders
    total_matches = sum(1 for match in MAC_RE.finditer(content) if is_redacted(match.group(0)))
    for pattern in redaction_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        total_matches += len(matches)

    return total_matches >= threshold, total_matches


# Legacy exports for backwards compatibility
SENSITIVE_HEADERS: set[str] = _FULL_REDACT_HEADERS | _COOKIE_REDACT_HEADERS | _SCHEME_REDACT_HEADERS
_fields = load_sensitive_patterns().get("fields", {})
SENSITIVE_FIELD_PATTERNS: list[str] = _fields.get("auto_redact_patterns", []) + _fields.get(
    "flag_patterns", []
)
