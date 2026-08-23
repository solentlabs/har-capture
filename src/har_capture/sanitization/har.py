"""HAR file sanitization utilities.

This module provides functions to sanitize HAR (HTTP Archive) files by removing
sensitive information while preserving the structure needed for debugging device
authentication and parsing issues.

Reuses PII patterns from html.py for consistency.
"""

from __future__ import annotations

import base64
import contextvars
import copy
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
    Hasher,
    is_base64_credential,
    is_base64_decodable_text,
    is_cookie_attribute_metadata,
    load_sensitive_patterns,
)
from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.html import (
    is_valid_ip_address,
    redact_structural_credentials,
    redact_vendor_serials,
    sanitize_html,
)
from har_capture.sanitization.report import ConfidenceLevel

if TYPE_CHECKING:
    from collections.abc import Iterator

    from har_capture.sanitization.report import HeuristicMode, SanitizationReport
else:
    from har_capture.sanitization.report import HeuristicMode

_LOGGER = logging.getLogger(__name__)

# Maximum recursion depth for JSON sanitization to prevent stack overflow
_MAX_RECURSION_DEPTH = 50

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

    # Fallback for legacy format
    if not auto_patterns:
        legacy = fields.get("patterns", [])
        if legacy:
            auto_patterns = legacy
        else:
            auto_patterns = ["password", "secret", "token", "\\bkey\\b", "\\bauth\\b"]

    auto_re = re.compile("|".join(auto_patterns), re.IGNORECASE)
    flag_re = re.compile("|".join(flag_patterns), re.IGNORECASE) if flag_patterns else None
    return auto_re, flag_re


def _load_sensitive_field_patterns() -> tuple[re.Pattern[str], re.Pattern[str] | None]:
    """Load and compile sensitive field patterns from the built-in patterns file."""
    return _compile_sensitive_field_patterns(load_sensitive_patterns())


# Load patterns at module level for efficiency
_FULL_REDACT_HEADERS, _COOKIE_REDACT_HEADERS, _SCHEME_REDACT_HEADERS = _load_sensitive_headers()
_SENSITIVE_FIELD_RE, _SENSITIVE_FLAG_FIELD_RE = _load_sensitive_field_patterns()

# Auth schemes recognized by sanitize_header_value when redacting an
# Authorization-style header. Preserving the scheme token lets downstream
# tools (e.g. cable_modem_monitor's analyze_har) classify the auth mechanism
# from a single authenticated request, rather than waiting for a 401 +
# WWW-Authenticate exchange that may never appear when the browser sends
# cached credentials. The list is intentionally restricted to RFC-recognized
# schemes (IANA HTTP Authentication Scheme Registry) so an unrecognized
# leading token — which could be the start of a secret in a non-standard
# format — falls through to full redaction.
_KNOWN_AUTH_SCHEMES: frozenset[str] = frozenset(
    {
        "basic",
        "bearer",
        "digest",
        "ntlm",
        "negotiate",
        "oauth",
    }
)


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
        Hashed value if hasher provided, otherwise REDACTED placeholder
    """
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
        if len(parts) == 2 and parts[0].lower() in _KNOWN_AUTH_SCHEMES:
            scheme, credential = parts
            hashed = _redact_value(credential, hasher, "AUTH", collector)
            return f"{scheme} {hashed}"
        return _redact_value(value, hasher, "AUTH", collector)

    if name_lower in sets.cookie_redact:
        # Detect cookie attribute metadata (e.g., "HttpOnly: true, Secure: true")
        # that was incorrectly serialized as the header value
        if is_cookie_attribute_metadata(value):
            return _redact_value(value, hasher, "COOKIE", collector)

        # Preserve cookie names, redact values
        def redact_cookie(match: re.Match[str]) -> str:
            cookie_name = match.group(1)
            cookie_value = match.group(2)
            hashed = _redact_value(cookie_value, hasher, "COOKIE", collector)
            return f"{cookie_name}={hashed}"

        result = re.sub(r"([^=;\s]+)=([^;]*)", redact_cookie, value)

        # If regex matched nothing (no name=value pairs), redact the whole value
        if result == value and value.strip():
            return _redact_value(value, hasher, "COOKIE", collector)

        return result

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
    login_shaped = any(
        is_sensitive_field(pair.split("=", 1)[0]) or is_flaggable_field(pair.split("=", 1)[0])
        for pair in text.split("&")
        if "=" in pair
    )

    pairs = []
    for pair in text.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            # Hash the percent-decoded value so the placeholder matches the
            # params copy (HAR stores params decoded).
            decoded_value = urllib.parse.unquote_plus(value)
            if is_sensitive_field(key):
                value = _redact_value(decoded_value, hasher, "FIELD", collector)
            elif is_flaggable_field(key) and collector and value:
                collector.flag_value(
                    decoded_value,
                    "field",
                    ConfidenceLevel.MEDIUM,
                    f"form field '{key}'",
                    f"Flaggable field name '{key}' in form data",
                )
            elif is_base64_credential(value) or is_base64_credential(decoded_value):
                # base64(user:pass) value in an unrecognized field name —
                # check the raw and percent-decoded forms.
                value = _redact_value(decoded_value, hasher, "AUTH", collector)
            elif login_shaped and collector and is_base64_decodable_text(decoded_value):
                # Likely a vendor-encoded credential (Sercomm/Hitron style).
                # Flag, never auto-redact: base64-decodable alone is not a
                # 100%-confidence signal.
                collector.flag_value(
                    decoded_value,
                    "credential",
                    ConfidenceLevel.MEDIUM,
                    f"form field '{key}'",
                    f"Base64-decodable value in unrecognized field '{key}' of a login-shaped form POST",
                )
            pairs.append(f"{key}={value}")
        else:
            pairs.append(pair)
    return "&".join(pairs)


def _sanitize_json_text(
    text: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Sanitize JSON text by redacting sensitive fields.

    Args:
        text: JSON text to sanitize
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        Sanitized JSON text with sensitive field values redacted
    """
    try:
        data = json.loads(text)
        sanitized = _sanitize_json_recursive(data, hasher, collector)
        return json.dumps(sanitized)
    except json.JSONDecodeError:
        _LOGGER.debug("Non-JSON text encountered in response body, skipping JSON sanitization")
        return text


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
                    if is_sensitive_field(param["name"]):
                        param["value"] = _redact_value(param.get("value", ""), hasher, "FIELD", collector)
                    elif is_flaggable_field(param["name"]) and collector and param.get("value"):
                        collector.flag_value(
                            param["value"],
                            "field",
                            ConfidenceLevel.MEDIUM,
                            f"POST param '{param['name']}'",
                            f"Flaggable field name '{param['name']}' in POST params",
                        )
                    elif is_base64_credential(param.get("value", "")):
                        # base64(user:pass) value in an unrecognized field name
                        # — mirrors the queryString fallback.
                        param["value"] = _redact_value(param["value"], hasher, "AUTH", collector)
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

            if "application/x-www-form-urlencoded" in mime_type:
                result["text"] = _sanitize_form_urlencoded(text, hasher, collector)
            elif "application/json" in mime_type:
                result["text"] = _sanitize_json_text(text, hasher, collector)
            elif "text/xml" in mime_type or "application/xml" in mime_type:
                text = _sanitize_xml_fields(text, hasher, collector)
                result["text"] = sanitize_html(
                    text,
                    collector=collector,
                    custom_patterns=custom_patterns,
                    heuristics=heuristics,
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

    try:
        root = ET.fromstring(text)  # noqa: S314
    except ET.ParseError:
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


def _sanitize_json_recursive(
    data: Any,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    _depth: int = 0,
) -> Any:
    """Recursively sanitize JSON data.

    Args:
        data: JSON data (dict, list, or primitive)
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions
        _depth: Current recursion depth (internal use)

    Returns:
        Sanitized data
    """
    if _depth > _MAX_RECURSION_DEPTH:
        _LOGGER.warning("Max recursion depth exceeded in JSON sanitization")
        return data

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower()
            if is_sensitive_field(key) and isinstance(value, str):
                result[key] = _redact_value(value, hasher, "FIELD", collector)
            elif is_flaggable_field(key) and isinstance(value, str) and collector and value:
                collector.flag_value(
                    value,
                    "field",
                    ConfidenceLevel.MEDIUM,
                    f"JSON key '{key}'",
                    f"Flaggable field name '{key}' in JSON",
                )
                result[key] = _sanitize_json_recursive(value, hasher, collector, _depth + 1)
            elif key_lower in ("mac", "macaddress", "mac_address", "hwaddr", "hw_addr"):
                # Explicit MAC address field - always redact
                if isinstance(value, str) and value:
                    if collector:
                        collector.record_auto_redaction("mac_address")
                    result[key] = hasher.hash_mac(value) if hasher else "***MAC***"
                else:
                    result[key] = value
            elif key_lower in ("serial", "serial_number", "serialnumber", "serialnum", "sn"):
                # Explicit serial number field - always redact
                if isinstance(value, str) and value:
                    if collector:
                        collector.record_auto_redaction("serial_number")
                    result[key] = hasher.hash_generic(value, "SERIAL") if hasher else "***SERIAL***"
                else:
                    result[key] = value
            else:
                result[key] = _sanitize_json_recursive(value, hasher, collector, _depth + 1)
        return result
    if isinstance(data, list):
        return [_sanitize_json_recursive(item, hasher, collector, _depth + 1) for item in data]
    # Apply pattern matching to string values
    if isinstance(data, str):
        return _sanitize_string_patterns(data, hasher, collector)
    return data


# Regex patterns for URL path segment sanitization
_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_API_KEY_PREFIX_PATTERN = re.compile(r"^(?:sk|pk|key)-[a-zA-Z0-9]{16,}$")
_LONG_TOKEN_PATTERN = re.compile(r"^(?=[a-zA-Z]*\d)(?=\d*[a-zA-Z])[a-zA-Z0-9]{32,}$")
_DEVICE_SERIAL_PATTERN = re.compile(r"^[A-Z]{2,6}-[A-Z0-9]{5,}$")

# Regex patterns for value-based sanitization
_MAC_PATTERN = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_PRIVATE_IP_PATTERN = re.compile(r"\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b")
# Public IPs: any non-private, non-localhost, non-reserved first octet
_PUBLIC_IP_PATTERN = re.compile(
    r"\b(?!10\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)"
    r"(?!127\.)(?!0\.)(?!255\.)"
    r"(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
)
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_VISA_PATTERN = re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b")
_CC_MC_PATTERN = re.compile(r"\b5[1-5][0-9]{14}\b")
_CC_AMEX_PATTERN = re.compile(r"\b3[47][0-9]{13}\b")
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


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm.

    Args:
        number: Digit-only string to validate

    Returns:
        True if the number passes Luhn validation
    """
    digits = [int(c) for c in number]
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        value = digit * 2 if i % 2 == 1 else digit
        if value > 9:
            value -= 9
        checksum += value
    return checksum % 10 == 0


def _sanitize_string_patterns(
    value: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Apply pattern-based sanitization to a string value.

    Redacts MAC addresses, private IPs, and emails found in string values.

    Args:
        value: String value to sanitize
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        Sanitized string
    """
    if not value:
        return value
    # Perf guard only — must stay far above real firmware assets, or PII scans
    # silently skip them. At 10,000 chars this skipped the CM2500's 33 KB
    # utility.js, leaving MACs/IPs in any large non-HTML text body unscanned.
    if len(value) > 1_000_000:
        _LOGGER.debug("Skipping pattern sanitization for long string (length=%d)", len(value))
        return value

    # MAC addresses
    def replace_mac(match: re.Match[str]) -> str:
        if collector:
            collector.record_auto_redaction("mac_address")
        return hasher.hash_mac(match.group(0)) if hasher else "***MAC***"

    value = _MAC_PATTERN.sub(replace_mac, value)

    # Private IPs (keep common gateway IPs)
    preserved_ips = {"192.168.0.1", "192.168.1.1", "10.0.0.1", "192.168.100.1"}

    def replace_private_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if ip in preserved_ips:
            return ip
        if not is_valid_ip_address(ip):
            return ip
        if collector:
            collector.record_auto_redaction("private_ip")
        return hasher.hash_ip(ip, is_private=True) if hasher else "***IP***"

    value = _PRIVATE_IP_PATTERN.sub(replace_private_ip, value)

    # Public IPs (non-private, non-localhost, non-reserved)
    def replace_public_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if not is_valid_ip_address(ip):
            return ip
        if collector:
            collector.record_auto_redaction("public_ip")
        return hasher.hash_ip(ip, is_private=False) if hasher else "***IP***"

    value = _PUBLIC_IP_PATTERN.sub(replace_public_ip, value)

    # Email addresses
    def replace_email(match: re.Match[str]) -> str:
        if collector:
            collector.record_auto_redaction("email")
        return hasher.hash_email(match.group(0)) if hasher else "***EMAIL***"

    value = _EMAIL_PATTERN.sub(replace_email, value)

    # SSN — flag for review instead of auto-redacting
    if collector:
        for match in _SSN_PATTERN.finditer(value):
            collector.flag_value(
                match.group(0),
                "ssn",
                ConfidenceLevel.MEDIUM,
                value[max(0, match.start() - 20) : match.end() + 20],
                "Possible SSN pattern (###-##-####)",
            )

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

    # Credit cards (with Luhn validation to reduce false positives)
    def replace_cc(match: re.Match[str]) -> str:
        number = match.group(0)
        if not _luhn_check(number):
            return number
        if collector:
            collector.record_auto_redaction("credit_card")
        return _redact_value(number, hasher, "CC", None)

    value = _CC_VISA_PATTERN.sub(replace_cc, value)
    value = _CC_MC_PATTERN.sub(replace_cc, value)
    value = _CC_AMEX_PATTERN.sub(replace_cc, value)

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
            header["value"] = sanitize_header_value(header["name"], header["value"], hasher, collector)


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
    parsed = urllib.parse.urlparse(url)
    if not parsed.path or parsed.path == "/":
        return url

    # Flag suspicious path segments for review instead of auto-redacting
    if collector:
        for segment in parsed.path.split("/"):
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


def _sanitize_url_query_params(
    url: str,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
) -> str:
    """Sanitize sensitive query parameters in a URL string.

    Args:
        url: Full URL string
        hasher: Optional hasher for correlation-preserving redaction
        collector: Optional collector to record redactions

    Returns:
        URL with sensitive query parameter values redacted
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url

    # Process raw query segments instead of parse_qsl to preserve base64
    # padding ('=') which parse_qsl treats as key/value separator.
    # Untouched segments pass through verbatim, preserving original encoding.
    raw_segments = parsed.query.split("&")
    rebuilt_segments = []
    changed = False
    for segment in raw_segments:
        if is_base64_credential(segment):
            # Bare base64(user:pass) token (e.g., ?YWRtaW46cGFzcw==)
            rebuilt_segments.append(_redact_value(segment, hasher, "AUTH", collector))
            changed = True
        elif "=" in segment:
            key, _, val = segment.partition("=")
            decoded_key = urllib.parse.unquote_plus(key)
            decoded_val = urllib.parse.unquote_plus(val)
            if is_sensitive_field(decoded_key) and val:
                rebuilt_segments.append(f"{key}={_redact_value(decoded_val, hasher, 'FIELD', collector)}")
                changed = True
            elif is_flaggable_field(decoded_key) and collector and val:
                collector.flag_value(
                    decoded_val,
                    "field",
                    ConfidenceLevel.MEDIUM,
                    f"query param '{decoded_key}'",
                    f"Flaggable field name '{decoded_key}' in URL query",
                )
                rebuilt_segments.append(segment)
            elif is_base64_credential(decoded_val):
                # Base64 user:pass in parameter value (e.g., ?token=YWRtaW46cGFzcw==)
                rebuilt_segments.append(f"{key}={_redact_value(decoded_val, hasher, 'AUTH', collector)}")
                changed = True
            else:
                rebuilt_segments.append(segment)
        else:
            rebuilt_segments.append(segment)

    if not changed:
        return url

    new_query = "&".join(rebuilt_segments)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


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
        for param in req["queryString"]:
            if isinstance(param, dict) and "name" in param:
                if is_sensitive_field(param["name"]):
                    param["value"] = _redact_value(param.get("value", ""), hasher, "FIELD", collector)
                elif is_flaggable_field(param["name"]) and collector and param.get("value"):
                    collector.flag_value(
                        param["value"],
                        "field",
                        ConfidenceLevel.MEDIUM,
                        f"queryString param '{param['name']}'",
                        f"Flaggable field name '{param['name']}' in queryString",
                    )
                elif is_base64_credential(param.get("value", "")):
                    # Base64 user:pass in parameter value
                    param["value"] = _redact_value(param["value"], hasher, "AUTH", collector)
                elif is_base64_credential(param["name"]) or (
                    not param.get("value") and is_base64_credential(param["name"] + "=")
                ):
                    # Bare base64 token as query parameter name
                    # Also try with '=' appended since parse_qsl strips base64 padding
                    param["name"] = _redact_value(param["name"], hasher, "AUTH", collector)

    # Sanitize the URL string itself (query params and path segments)
    if "url" in req and isinstance(req["url"], str):
        req["url"] = _sanitize_url_query_params(req["url"], hasher, collector)
        req["url"] = _sanitize_url_path(req["url"], hasher, collector)


# A body made entirely of base64-alphabet characters is a candidate for
# base64-encoded-JSON decoding (see _decode_base64_json). Cheap pre-filter so
# HTML/JSON/text bodies bail before a full decode attempt.
_BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def _decode_base64_json(value: str) -> Any | None:
    """Decode a base64 body into a structured JSON payload, if it is one.

    Some devices return their data as raw base64-encoded JSON (often with an
    empty Content-Type). The decoded text is colon-bearing, so it would
    otherwise trip the opaque-credential heuristic and be collapsed to a single
    ``AUTH_`` token — destroying the field names and JSON shape, which are not
    PII. This discriminator answers "payload or secret?": it returns the parsed
    object only when ``value`` is valid base64 that decodes to UTF-8 parsing as
    a JSON object or array. Scalars, non-JSON, and non-base64 inputs return
    ``None`` so the caller falls back to opaque-token handling.

    Args:
        value: Candidate base64 string (already stripped).

    Returns:
        The parsed dict/list, or ``None`` when ``value`` is not base64-encoded
        JSON (object/array).
    """
    if not value or not _BASE64_BODY_RE.match(value):
        return None
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except ValueError:
        # binascii.Error (bad alphabet/padding) and UnicodeDecodeError are both
        # ValueError subclasses.
        return None
    try:
        parsed = json.loads(decoded)
    except ValueError:  # includes json.JSONDecodeError
        return None
    if isinstance(parsed, dict | list):
        return parsed
    return None


def _sanitize_response_content(
    content: dict[str, Any],
    collector: RedactionCollector | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    url_cred_raw: str | None = None,
) -> None:
    """Sanitize response content in-place.

    Args:
        content: HAR response content object with 'text' and 'mimeType' keys
        collector: Optional collector with hasher for redaction
        custom_patterns: Optional custom patterns (file path or dict)
        heuristics: Heuristic mode for pipe-delimited value detection
        url_cred_raw: Raw base64 credential from the request URL (if any). When
            provided, a response body that looks like a base64 credential is
            only redacted if it echoes that credential — opaque server-issued
            session tokens are preserved for replay fidelity.
    """
    if "text" not in content or not content["text"]:
        return

    mime_type = content.get("mimeType", "")
    hasher = collector.hasher if collector else None

    stripped = content["text"].strip()

    # Decode-first discriminator: a base64-encoded *structured* payload (JSON
    # object or array) must be sanitized value-by-value with its structure
    # intact — never collapsed to a single AUTH_ token. Devices like the Sercomm
    # DM1000 return data as raw base64 JSON (empty Content-Type), which decodes
    # to a colon-bearing string and would otherwise trip the opaque-credential
    # branch below. Re-encode to base64 on the way out, matching how it arrived.
    decoded_json = _decode_base64_json(stripped)
    if decoded_json is not None:
        sanitized = _sanitize_json_recursive(decoded_json, hasher, collector)
        content["text"] = base64.b64encode(json.dumps(sanitized).encode()).decode()
        return

    if is_base64_credential(stripped):
        if url_cred_raw is None or _is_echoed_credential(stripped, url_cred_raw):
            content["text"] = _redact_value(stripped, hasher, "AUTH", collector)
            return

    if "text/html" in mime_type or "text/xml" in mime_type or "application/xml" in mime_type:
        content["text"] = sanitize_html(
            content["text"],
            collector=collector,
            custom_patterns=custom_patterns,
            heuristics=heuristics,
        )
        return

    # Structurally-located credentials (HTML engine pass 7c) for every other
    # text-bearing body. `validate` checks *all* response bodies, so a device
    # label block embedded in a `.js` or `application/javascript` body would
    # otherwise be reported as an error that no sanitize run could clear —
    # sanitize and validate must agree on what they can each see (ADR-14).
    if hasher is not None and collector is not None and content.get("encoding") != "base64":
        content["text"] = redact_structural_credentials(content["text"], hasher, collector, custom_patterns)

    if "application/json" in mime_type:
        try:
            data = json.loads(content["text"])
            content["text"] = json.dumps(_sanitize_json_recursive(data, hasher, collector))
        except json.JSONDecodeError:
            _LOGGER.warning("Invalid JSON in response content, skipping sanitization")
    elif (mime_type.startswith("text/") or not mime_type) and content.get("encoding") != "base64":
        # Fallback: apply pattern-based sanitization to text content
        content["text"] = _sanitize_string_patterns(content["text"], hasher, collector)
        # Vendor-format serials (delimiter-aware, domain detectors) — runs
        # outside _sanitize_string_patterns so its perf length guard can
        # never cost serial coverage, however large the text body.
        if hasher is not None and collector is not None:
            serial_detectors = _resolve_serial_detectors(custom_patterns)
            if serial_detectors:
                content["text"] = redact_vendor_serials(content["text"], serial_detectors, hasher, collector)


def _sanitize_response(
    resp: dict[str, Any],
    collector: RedactionCollector | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    url_cred_raw: str | None = None,
) -> None:
    """Sanitize a HAR response object in-place.

    Args:
        resp: HAR response object containing headers and content
        collector: Optional collector with hasher for redaction
        custom_patterns: Optional custom patterns (file path or dict)
        heuristics: Heuristic mode for pipe-delimited value detection
        url_cred_raw: Raw base64 credential from the paired request URL (if any).
            Forwarded to ``_sanitize_response_content`` for the server-token
            preservation heuristic.
    """
    hasher = collector.hasher if collector else None

    # Sanitize headers
    if "headers" in resp and isinstance(resp["headers"], list):
        _sanitize_headers(resp["headers"], hasher, collector)

    # Sanitize cookie objects (Playwright parses Set-Cookie into structured objects)
    if "cookies" in resp and isinstance(resp["cookies"], list):
        for cookie in resp["cookies"]:
            if isinstance(cookie, dict) and "value" in cookie:
                cookie["value"] = _redact_value(cookie["value"], hasher, "COOKIE", collector)

    # Sanitize response content
    if "content" in resp and isinstance(resp["content"], dict):
        _sanitize_response_content(resp["content"], collector, custom_patterns, heuristics, url_cred_raw)


def sanitize_entry(
    entry: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    collector: RedactionCollector | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    _skip_copy: bool = False,
    _url_cred_raw: str | None = None,
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
    ):
        if "request" in result:
            _sanitize_request(result["request"], collector.hasher, collector, custom_patterns, heuristics)

        if "response" in result:
            _sanitize_response(result["response"], collector, custom_patterns, heuristics, _url_cred_raw)

    return result


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


def _detect_url_credential_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return annotations for entries whose URL query params contain bare base64 credentials.

    Must be called on the original (pre-sanitization) entries — placeholders written by
    the sanitizer no longer match the base64-alphabet regex the intake pipeline uses.
    Returns a list of ``{"entry_index": i, "location": "url_query_param"}`` dicts.
    """
    locations = []
    for i, entry in enumerate(entries):
        request = entry.get("request", {})
        found = False

        url = request.get("url", "")
        if url:
            parsed = urllib.parse.urlparse(url)
            for segment in parsed.query.split("&"):
                if not segment:
                    continue
                if is_base64_credential(segment):
                    found = True
                    break
                if "=" in segment:
                    _, _, val = segment.partition("=")
                    if is_base64_credential(urllib.parse.unquote_plus(val)):
                        found = True
                        break

        if not found:
            for param in request.get("queryString", []):
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                val = param.get("value", "")
                if (
                    is_base64_credential(val)
                    or is_base64_credential(name)
                    or (not val and is_base64_credential(name + "="))
                ):
                    found = True
                    break

        if found:
            locations.append({"entry_index": i, "location": "url_query_param"})

    return locations


def _extract_url_credential_raw(request: dict[str, Any]) -> str | None:
    """Return the raw base64 credential from a request's URL query params, or None.

    Checks the URL query string first, then the queryString array. Returns the
    first raw base64(user:pass) value found so the response-body guard can
    distinguish an echoed credential from a server-issued session token.
    """
    url = request.get("url", "")
    if not isinstance(url, str):
        url = ""
    if url:
        parsed = urllib.parse.urlparse(url)
        for segment in parsed.query.split("&"):
            seg: str = segment
            if not seg:
                continue
            if is_base64_credential(seg):
                return seg
            if "=" in seg:
                _, _, raw_val = seg.partition("=")
                decoded_val = urllib.parse.unquote_plus(raw_val)
                if is_base64_credential(decoded_val):
                    return decoded_val

    for param in request.get("queryString", []):
        if not isinstance(param, dict):
            continue
        p_name: str = str(param.get("name", ""))
        p_val: str = str(param.get("value", ""))
        if is_base64_credential(p_val):
            return p_val
        if is_base64_credential(p_name) or (not p_val and is_base64_credential(p_name + "=")):
            return p_name

    return None


def _is_echoed_credential(body: str, url_cred_raw: str) -> bool:
    """True if body echoes the URL credential or a decoded component of it.

    Returns True when body matches the raw credential exactly, or equals
    btoa(user), btoa(password), or btoa(user:password) derived from it.
    Returns False for opaque server-issued tokens.
    """
    if body == url_cred_raw:
        return True
    try:
        padded = url_cred_raw.rstrip("=")
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

    # Pre-scan original entries for URL credential locations before sanitization replaces them
    orig_entries = har_data.get("log", {}).get("entries", [])
    url_credential_locations = (
        _detect_url_credential_entries(orig_entries) if isinstance(orig_entries, list) else []
    )

    # Build an index of the raw credential string per entry index so that the
    # response-body sanitizer can apply the server-token preservation heuristic.
    # Iterate orig_entries directly rather than indexing through url_credential_locations
    # so that the `if raw is not None` branch is exercised by the common case (no cred).
    _url_cred_by_idx: dict[int, str] = {}
    if isinstance(orig_entries, list):
        for i, orig_entry in enumerate(orig_entries):
            raw = _extract_url_credential_raw(orig_entry.get("request", {}))
            if raw is not None:
                _url_cred_by_idx[i] = raw

    # Sanitize all entries using the shared collector
    if "entries" in log and isinstance(log["entries"], list):
        sanitized_entries = []
        for i, entry in enumerate(log["entries"]):
            sanitized_entries.append(
                sanitize_entry(
                    entry,
                    custom_patterns=custom_patterns,
                    collector=collector,
                    heuristics=heuristics,
                    _skip_copy=True,
                    _url_cred_raw=_url_cred_by_idx.get(i),
                )
            )
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
        meta["_sanitized_credentials"] = url_credential_locations

    # Pass 1b: replace values already redacted elsewhere that survived verbatim on
    # surfaces with no field name to match (most commonly a URL path segment).
    propagated = _propagate_redacted_values(result, collector.redacted_values)
    if propagated:
        collector.auto_redacted_counts["propagated"] = propagated
        # A propagated value has no surviving occurrence left, so asking the user
        # to review it is a decision with no effect. Drop it from the review queue.
        collector.drop_flagged({v for v in collector.redacted_values if _is_propagation_eligible(v)})

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

    with open(output_str, "w", encoding="utf-8") as f:
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
        # Serialize to string for global replacement
        content = json.dumps(result)
    except (TypeError, ValueError) as e:
        raise HarValidationError(f"Failed to serialize HAR data: {e}") from e

    # Apply each redaction
    for item in redactions_to_apply:
        try:
            # Generate redacted value via the category→prefix map, so
            # user redactions carry the same placeholder prefixes as
            # auto-redactions (CRED_, WIFI_, SERIAL_, ...). Building the
            # prefix from the raw category name produced placeholders
            # like CREDENTIAL_/SERIAL_NUMBER_ that the allowlist and
            # safe-value patterns did not all recognize as redacted.
            redacted = hasher.hash_sensitive_value(item.original_value, item.category)
            item.redacted_value = redacted

            # IMPORTANT: Escape values for JSON string context
            # This handles newlines, quotes, backslashes, etc.
            escaped_original = json.dumps(item.original_value)[1:-1]  # Strip quotes
            escaped_redacted = json.dumps(redacted)[1:-1]

            # Perform global replacement
            content = content.replace(escaped_original, escaped_redacted)

        except Exception as e:  # noqa: PERF203 - intentional: continue with other redactions on error
            _LOGGER.warning("Failed to redact flagged item (category=%s): %s", item.category, e)
            # Continue with other redactions
            continue

    try:
        # Parse back to dict — cast needed because json.loads returns Any
        parsed: dict[str, Any] = json.loads(content)
    except json.JSONDecodeError as e:
        raise HarValidationError(
            f"Failed to parse HAR after applying redactions: {e.msg} at position {e.pos}"
        ) from e

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
        r"02:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}",  # Hashed MACs
        r"10\.255\.\d+\.\d+",  # Hashed private IPs
        r"192\.0\.2\.\d+",  # Hashed public IPs (TEST-NET-1)
        r"user_[a-f0-9]{8}@redacted\.invalid",  # Hashed emails
    ]

    total_matches = 0
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
