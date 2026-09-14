"""Validate HAR files for potential secrets/PII before committing.

Scans HAR files for:
- Sensitive headers (Authorization, Cookie, Set-Cookie with real values)
- Sensitive form fields (password, token, credential, etc.)
- MAC addresses (non-anonymized)
- Serial numbers
- Real IP addresses (non-private)
- Vendor-format serial numbers in delimited content (shared detectors with
  the sanitizer, so the two tools agree on what counts as a serial)

This module has ZERO third-party dependencies (stdlib + har_capture only).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from har_capture.patterns import load_sensitive_patterns
from har_capture.patterns.loader import (
    VENDOR_SERIAL_TOKEN_RE,
    compile_detectors,
    high_confidence_serial_detectors,
    match_vendor_serial,
)
from har_capture.patterns.redaction import (
    JSON_MAX_DEPTH,
    MAC_RE,
    URL_VALUED_HEADERS,
    credential_value_action,
    decode_base64_payload,
    decode_transport_body,
    find_query_credential,
    find_query_payload,
    ipv6_host_spans,
    is_base64_credential,
    is_base64_decodable_text,
    is_blank_query_value,
    is_constant_mac,
    is_cookie_attribute_metadata,
    is_fully_redacted,
    iter_json_strings,
    json_members,
    mime_kind,
    parse_json_container,
    parse_xml,
    query_param_segment,
    split_url_password,
    unredacted_identity,
    url_query,
)
from har_capture.patterns.redaction import (
    is_redacted as check_if_redacted,
)
from har_capture.sanitization.html import (
    SERIAL_LABEL_HINT_RE,
    SERIAL_LABEL_RE,
    SIBLING_PASSWORD_RE,
    SIBLING_SSID_RE,
    SSID_ATTRIBUTE_RE,
    is_structural_value_sensitive,
    is_valid_ip_address,
    iter_ssid_option_values,
)
from har_capture.validation.completeness import load_har

# Cookie attribute-only values (not actual session data)
COOKIE_ATTRIBUTES_ONLY: list[str] = [
    r"^(Secure\s*;?\s*)+$",
    r"^(HttpOnly\s*;?\s*)+$",
    r"^(Secure|HttpOnly)(\s*;\s*(Secure|HttpOnly))*\s*;?\s*$",
    r"^$",
]

MAC_PATTERN = MAC_RE

# Labeled serials: the sanitizer's own pattern (pass 2), so every labeled
# serial reported here is one a sanitize run removes.
SERIAL_PATTERNS: list[re.Pattern[str]] = [SERIAL_LABEL_RE]

# Public IP pattern (not private ranges)
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Factory-default usernames shipped fixed on device families. These carry no
# identifying content — flagging them turns the validate gate red on every
# healthy capture of that family (CM2500: three [ERROR] on `loginName: admin`),
# training contributors to ignore the gate. Suppression applies ONLY to
# flag-tier (identity) field matches; a default string in a password-named
# field is still a real credential leak and stays an error.
KNOWN_DEFAULT_USERNAMES: frozenset[str] = frozenset({"admin"})


def _load_sensitive_headers(custom_patterns: str | dict[str, Any] | None = None) -> list[str]:
    """Load sensitive header names from patterns.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        List of sensitive header names
    """
    sensitive = load_sensitive_patterns(custom_patterns)
    headers = sensitive.get("headers", {})
    result = list(headers.get("full_redact", []))
    result.extend(headers.get("cookie_redact", []))
    result.extend(headers.get("scheme_redact", []))
    return result


def _load_sensitive_fields(custom_patterns: str | dict[str, Any] | None = None) -> list[str]:
    """Load sensitive field patterns from patterns file.

    Pre-commit validation should warn about ALL sensitive patterns
    (both auto-redact and flag), not just auto-redact ones.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        List of sensitive field regex patterns
    """
    sensitive = load_sensitive_patterns(custom_patterns)
    fields = sensitive.get("fields", {})
    # Combine both tiers for validation — pre-commit should catch all sensitive fields
    patterns: list[str] = fields.get("auto_redact_patterns", []) + fields.get("flag_patterns", [])
    return patterns


def _compile_serial_detectors(custom_patterns: str | dict[str, Any] | None = None) -> list[Any]:
    """Compile the high-confidence serial_number detectors for validation.

    These are the deterministic vendor serial formats (domain knowledge,
    loaded via ``--patterns``) that the sanitizer auto-redacts and validate
    reports as errors when found unredacted.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        Filtered CompiledDetector list (empty without domain patterns)
    """
    return high_confidence_serial_detectors(compile_detectors(load_sensitive_patterns(custom_patterns)))


def _compile_sensitive_fields(custom_patterns: str | dict[str, Any] | None = None) -> list[re.Pattern[str]]:
    """Compile sensitive field patterns for efficient matching.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        List of compiled regex patterns (case-insensitive)
    """
    return [re.compile(p, re.IGNORECASE) for p in _load_sensitive_fields(custom_patterns)]


@dataclass(frozen=True)
class _FieldTiers:
    """Compiled field-name patterns split by tier — severity differs by tier.

    ``auto_redact`` names (password, token, secret, ...) assert a credential
    with certainty: an unredacted value is an **error**. ``flag`` names
    (username, login, domain, ...) assert identity-adjacent content the
    sanitizer itself only flags for review: an unredacted value is a
    **warning**, and a factory-default username is suppressed entirely
    (see ``KNOWN_DEFAULT_USERNAMES``).
    """

    auto_redact: tuple[re.Pattern[str], ...]
    flag: tuple[re.Pattern[str], ...]

    def all_patterns(self) -> tuple[re.Pattern[str], ...]:
        return self.auto_redact + self.flag


def _compile_field_tiers(custom_patterns: str | dict[str, Any] | None = None) -> _FieldTiers:
    """Compile the auto-redact and flag field-name tiers separately.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        _FieldTiers with case-insensitive compiled patterns per tier
    """
    sensitive = load_sensitive_patterns(custom_patterns)
    fields = sensitive.get("fields", {})
    auto: list[str] = fields.get("auto_redact_patterns", [])
    flag: list[str] = fields.get("flag_patterns", [])
    return _FieldTiers(
        auto_redact=tuple(re.compile(p, re.IGNORECASE) for p in auto),
        flag=tuple(re.compile(p, re.IGNORECASE) for p in flag),
    )


@dataclass
class Finding:
    """A potential secret/PII finding.

    Attributes:
        severity: Finding severity ('error' or 'warning')
        location: Where in the HAR the finding was detected
        field: Name of the field containing the issue
        value: The suspicious value (truncated for display)
        reason: Human-readable explanation of why it was flagged
    """

    severity: str  # "error" or "warning"
    location: str  # Where in the HAR
    field: str  # Field name
    value: str  # The suspicious value (truncated)
    reason: str  # Why it's flagged


def is_redacted(value: str, custom_patterns: str | dict[str, Any] | None = None) -> bool:
    """Check if a value appears to be properly redacted.

    This function now delegates to the consolidated redaction module for
    consistent redaction checking across the codebase.

    Args:
        value: Value to check
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if value appears to be redacted
    """
    return check_if_redacted(value, custom_patterns)


def is_cookie_attributes_only(value: str) -> bool:
    """Check if a cookie value contains only attributes (no actual session data).

    When HARs are sanitized, cookie values may be stripped leaving just
    attributes like 'Secure; HttpOnly'. These are safe to commit.
    Also detects serialized attribute metadata like 'HttpOnly: true, Secure: true'.

    Args:
        value: Cookie value to check

    Returns:
        True if cookie contains only attributes
    """
    stripped = value.strip()
    if any(re.match(pattern, stripped, re.IGNORECASE) for pattern in COOKIE_ATTRIBUTES_ONLY):
        return True
    return is_cookie_attribute_metadata(stripped)


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range.

    Args:
        ip: IP address string

    Returns:
        True if IP is in a private range
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # Validate each octet is in valid range
    if not all(0 <= o <= 255 for o in octets):
        return False

    # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    # Also allow 0.0.0.0 (redacted)
    return all(o == 0 for o in octets)


def is_netmask(ip: str) -> bool:
    """Check if a dotted-quad value is a subnet mask, not a host address.

    Netmasks (255.255.255.0, 255.255.252.0, ...) appear throughout router
    status pages and carry no PII, but they pass the public-IP shape check.
    A valid netmask is a contiguous run of 1-bits followed by 0-bits.

    Args:
        ip: Dotted-quad string

    Returns:
        True if the value is a valid netmask (including 0.0.0.0 and
        255.255.255.255)
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    # 1...10...0 form: the complement must be a contiguous low-bit run
    inverted = value ^ 0xFFFFFFFF
    return (inverted & (inverted + 1)) == 0


def truncate(value: str, max_len: int = 40) -> str:
    """Truncate a value for display.

    Args:
        value: Value to truncate
        max_len: Maximum length

    Returns:
        Truncated value
    """
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _check_query_param(
    segment: str,
    name: str,
    value: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None,
    field_tiers: _FieldTiers,
    seen: set[tuple[str, str]],
) -> None:
    """Report one query parameter.

    A credential in any shape is an error — the sanitizer removes every one,
    whichever rule it uses — and is reported as a credential, the more specific
    reason. Otherwise the parameter name is judged by the field tiers.
    ``seen`` suppresses a repeat of the same finding: the URL string and the
    ``queryString`` array are one query recorded twice.
    """
    # The sanitizer's decision order (_classify_query_param): a credential,
    # then a credential-named parameter, then a base64 payload — checked inside,
    # never flagged by name — and only then an identity-named parameter.
    credential = find_query_credential(segment)
    classified = None
    if credential is None and not is_blank_query_value(value) and not is_redacted(value, custom_patterns):
        classified = _classify_field_finding(name, value, field_tiers)
    payload = None
    if credential is None and (classified is None or classified[0] != "error"):
        payload = find_query_payload(segment)
        if payload is not None:
            classified = None

    if credential is not None:
        key: tuple[str, str] = ("credential", credential.credential)
        field = f"query param '{name}'" if credential.keyed else "query string"
        shape = (
            "in URL query parameter" if credential.keyed else "as bare or marker-prefixed URL query segment"
        )
        finding = Finding(
            severity="error",
            location=location,
            field=field,
            value=truncate(value if credential.keyed else segment),
            reason=f"Base64-encoded credential (user:pass) {shape}",
        )
    elif classified is not None:
        severity, matched = classified
        key = ("field", f"{name}={value}")
        finding = Finding(
            severity=severity,
            location=location,
            field=f"query param '{name}'",
            value=truncate(value),
            reason=f"Sensitive query parameter matching '{matched.pattern}'",
        )
    elif payload is not None:
        _check_query_payload(payload.text, name, location, findings, custom_patterns, field_tiers, seen)
        return
    else:
        return
    if key not in seen:
        seen.add(key)
        findings.append(finding)


def _payload_findings(
    text: str,
    name: str,
    location: str,
    custom_patterns: str | dict[str, Any] | None,
    field_tiers: _FieldTiers,
) -> list[Finding]:
    """Check inside a base64 JSON or URL payload, as the sanitizer sanitizes inside it.

    A JSON payload is checked like a JSON body, a URL payload like any URL.
    Only errors are kept: inside a payload Pass 1 is final, so an
    identity-style field there is never offered for review, and a warning
    about it would have no remedy.
    """
    inner: list[Finding] = []
    data = parse_json_container(text)
    if data is not None:
        path = f"'{name}' payload" if name else "payload"
        check_json_fields(data, location, inner, path, custom_patterns, _field_tiers=field_tiers)
    else:
        check_url(text, location, inner, custom_patterns, field_tiers=field_tiers)
    return [finding for finding in inner if finding.severity == "error"]


def _check_query_payload(
    text: str,
    name: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None,
    field_tiers: _FieldTiers,
    seen: set[tuple[str, str]],
) -> None:
    """Report the findings inside a query payload once per query.

    Findings are keyed by field and value, so the URL string and the
    ``queryString`` array — one payload recorded twice — report it once.
    """
    for finding in _payload_findings(text, name, location, custom_patterns, field_tiers):
        key = ("payload", f"{finding.field}={finding.value}")
        if key not in seen:
            seen.add(key)
            findings.append(finding)


def check_url(
    url: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
    *,
    field_tiers: _FieldTiers | None = None,
    seen: set[tuple[str, str]] | None = None,
) -> None:
    """Check a URL's query for credentials and sensitive parameters.

    Credentials use the sanitizer's own definition (``find_query_credential``)
    and field names its tiers, so an error reported here is one a sanitize run
    removes.

    Args:
        url: Full URL string (a request URL, or a URL-valued header)
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
        field_tiers: Pre-compiled field tiers (compiled on demand if omitted)
        seen: Findings already reported for the same request, to skip repeats
    """
    userinfo = split_url_password(url)
    if userinfo is not None and not is_redacted(userinfo[1], custom_patterns):
        findings.append(
            Finding(
                severity="error",
                location=location,
                field="URL userinfo",
                value=truncate(userinfo[1]),
                reason="Password in URL userinfo",
            )
        )
    query = url_query(url)
    if not query:
        return
    tiers = field_tiers if field_tiers is not None else _compile_field_tiers(custom_patterns)
    reported = seen if seen is not None else set()
    # Raw segments, not parse_qsl: it treats '=' as a key/value separator and
    # would strip base64 padding.
    for segment in query.split("&"):
        key, sep, raw_value = segment.partition("=")
        name = urllib.parse.unquote_plus(key)
        value = urllib.parse.unquote_plus(raw_value) if sep else ""
        _check_query_param(segment, name, value, location, findings, custom_patterns, tiers, reported)


def check_query_string(
    params: Any,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
    *,
    field_tiers: _FieldTiers | None = None,
    seen: set[tuple[str, str]] | None = None,
) -> None:
    """Check a HAR ``queryString`` array the way ``check_url`` checks the URL.

    The sanitizer rewrites this array independently of the URL string, so a
    file cleaned in one place and not the other must still be caught.

    Args:
        params: HAR ``queryString`` entries (already decoded by the query parser)
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
        field_tiers: Pre-compiled field tiers (compiled on demand if omitted)
        seen: Findings already reported for the same request, to skip repeats
    """
    if not isinstance(params, list):
        return
    tiers = field_tiers if field_tiers is not None else _compile_field_tiers(custom_patterns)
    reported = seen if seen is not None else set()
    for param in params:
        if isinstance(param, dict) and "name" in param:
            name, value = str(param["name"]), str(param.get("value", ""))
            _check_query_param(
                query_param_segment(param), name, value, location, findings, custom_patterns, tiers, reported
            )


def check_headers(
    headers: list[dict[str, str]],
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
) -> None:
    """Check headers for sensitive values.

    Args:
        headers: List of header dicts
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
    """
    sensitive_headers = _load_sensitive_headers(custom_patterns)

    for header in headers:
        name = header.get("name", "").lower()
        value = header.get("value", "")

        if not value or is_redacted(value, custom_patterns):
            continue

        # Special handling for cookie headers - check if only attributes remain
        if "cookie" in name and is_cookie_attributes_only(value):
            continue

        for sensitive in sensitive_headers:
            if sensitive.lower() in name:
                findings.append(
                    Finding(
                        severity="error",
                        location=location,
                        field=header.get("name", ""),
                        value=truncate(value),
                        reason=f"Sensitive header '{sensitive}' with non-redacted value",
                    )
                )
                break


def _classify_field_finding(
    name: str,
    value: str,
    tiers: _FieldTiers,
) -> tuple[str, re.Pattern[str]] | None:
    """Classify a field name/value against the two field tiers.

    Returns ``(severity, matched_pattern)``, or ``None`` when no finding
    should be reported. Auto-redact-tier names are errors; flag-tier names
    are warnings; a flag-tier name whose value is a factory-default username
    is suppressed (see ``KNOWN_DEFAULT_USERNAMES``).
    """
    matched = next((p for p in tiers.auto_redact if p.search(name)), None)
    if matched:
        return ("error", matched)
    matched = next((p for p in tiers.flag if p.search(name)), None)
    if matched:
        if value.strip().lower() in KNOWN_DEFAULT_USERNAMES:
            return None
        return ("warning", matched)
    return None


def _check_form_params(
    pairs: list[tuple[str, str]],
    location: str,
    findings: list[Finding],
    field_tiers: _FieldTiers,
    custom_patterns: str | dict[str, Any] | None = None,
) -> None:
    """Check form name/value pairs for sensitive fields and encoded credentials.

    Credential-named fields (auto-redact tier) with unredacted values are
    errors; identity-named fields (flag tier) are warnings, with
    factory-default usernames suppressed. In a login-shaped form (any field
    name matches a sensitive pattern), a base64-decodable value in an
    unrecognized field is a warning — the backstop for vendor credential
    fields the patterns don't know yet (the Sercomm/Hitron ``pws`` class,
    cable_modem_monitor issue #92).

    Args:
        pairs: Form (name, value) pairs
        location: Location string for findings
        findings: List to append findings to
        field_tiers: Pre-compiled field patterns split by tier
        custom_patterns: Optional path to custom patterns file
    """
    all_patterns = field_tiers.all_patterns()
    login_shaped = any(any(p.search(name) for p in all_patterns) for name, _ in pairs)

    for name, value in pairs:
        if not value or is_redacted(value, custom_patterns):
            continue

        # The sanitizer's order: a credential-named field, then a base64
        # payload (checked inside), then an identity-named field.
        classified = _classify_field_finding(name, value, field_tiers)
        payload = find_query_payload(value) if classified is None or classified[0] != "error" else None
        if payload is not None and not payload.prefix.strip("?"):
            findings.extend(_payload_findings(payload.text, name, location, custom_patterns, field_tiers))
        elif classified is not None:
            severity, matched = classified
            findings.append(
                Finding(
                    severity=severity,
                    location=location,
                    field=name,
                    value=truncate(value),
                    reason=f"Sensitive form field matching '{matched.pattern}'",
                )
            )
        elif (
            not any(p.search(name) for p in all_patterns) and login_shaped and is_base64_decodable_text(value)
        ):
            findings.append(
                Finding(
                    severity="warning",
                    location=location,
                    field=name,
                    value=truncate(value),
                    reason="Base64-decodable value in unrecognized field of a login-shaped form POST",
                )
            )


def check_post_data(
    post_data: dict[str, Any] | None,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
) -> None:
    """Check POST data for sensitive fields.

    Args:
        post_data: POST data dict
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
    """
    if not post_data:
        return

    field_tiers = _compile_field_tiers(custom_patterns)

    # Check params (form data)
    params = post_data.get("params", [])
    pairs = [(param.get("name", ""), param.get("value", "")) for param in params]
    _check_form_params(pairs, location, findings, field_tiers, custom_patterns)

    # Check text (raw body — form-urlencoded, JSON, or XML)
    text = post_data.get("text", "")
    # The whole-string form: `is_redacted` matches its allowlist families
    # with `re.search`, so a `#000000` anywhere in a body would skip it.
    if text and not is_fully_redacted(text, custom_patterns):
        mime_type = post_data.get("mimeType", "")
        # JSON by content first, whatever the type, as the sanitizer reads it.
        json_data = parse_json_container(text)
        if json_data is not None:
            check_json_fields(json_data, location + " (body)", findings, custom_patterns=custom_patterns)
            return
        if "application/x-www-form-urlencoded" in mime_type:
            # The text copy is checked independently of params — a sanitizer
            # that redacts one copy but not the other must still be caught.
            # Manual splitting (not parse_qsl) preserves base64 '=' padding
            # in values.
            text_pairs = []
            for segment in text.split("&"):
                if "=" in segment:
                    name, _, val = segment.partition("=")
                    text_pairs.append((urllib.parse.unquote_plus(name), urllib.parse.unquote_plus(val)))
            _check_form_params(text_pairs, location + " (body)", findings, field_tiers, custom_patterns)
            return
        if mime_kind(mime_type) == "markup":
            _check_xml_fields(text, location + " (body)", findings, custom_patterns)


def _check_xml_fields(
    text: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
) -> None:
    """Check XML body for sensitive element names.

    Parses XML with stdlib ElementTree. Malformed XML is caught and skipped.

    Args:
        text: Raw XML text
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
    """
    field_tiers = _compile_field_tiers(custom_patterns)

    root = parse_xml(text)
    if root is None:
        return

    for elem in root.iter():
        tag = elem.tag
        # Strip namespace prefix if present: {http://ns}tagname -> tagname
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        value = (elem.text or "").strip()
        if value and not is_redacted(value, custom_patterns):
            classified = _classify_field_finding(tag, value, field_tiers)
            if classified is not None:
                severity, pattern = classified
                findings.append(
                    Finding(
                        severity=severity,
                        location=location,
                        field=tag,
                        value=truncate(value),
                        reason=f"Sensitive XML element matching '{pattern.pattern}'",
                    )
                )

        # Check attributes (e.g., <password value="secret"/>)
        for attr_name, attr_value in elem.attrib.items():
            if not attr_value or is_redacted(attr_value, custom_patterns):
                continue
            classified = _classify_field_finding(attr_name, attr_value, field_tiers)
            if classified is not None:
                severity, pattern = classified
                findings.append(
                    Finding(
                        severity=severity,
                        location=location,
                        field=attr_name,
                        value=truncate(attr_value),
                        reason=f"Sensitive XML attribute matching '{pattern.pattern}'",
                    )
                )


# A JSON field whose key names a device identity and whose value has that
# identity's shape (classify_identity_field, the sanitizer's own predicate) is
# an error: the key states what the value is (ADR-13 determinism).
_IDENTITY_REASONS = {
    "serial_number": "Device serial number in a JSON field",
    "mac_address": "MAC address in a JSON field",
}


def _identity_finding(key: str, value: str, custom_patterns: str | dict[str, Any] | None) -> str | None:
    """Return the reason to report an identity field, or None when it is clean (``unredacted_identity``)."""
    identity = unredacted_identity(key, value, custom_patterns)
    return None if identity is None else _IDENTITY_REASONS[identity]


def check_json_fields(
    data: dict[str, Any] | list[Any],
    location: str,
    findings: list[Finding],
    path: str = "",
    custom_patterns: str | dict[str, Any] | None = None,
    _field_tiers: _FieldTiers | None = None,
    _depth: int = 0,
    _served: bool = False,
) -> None:
    """Recursively check JSON for sensitive fields.

    Args:
        data: JSON data (dict or list)
        location: Location string for findings
        findings: List to append findings to
        path: Current path in the JSON structure
        custom_patterns: Optional path to custom patterns file
        _field_tiers: Pre-compiled field patterns split by tier. Internal use only.
        _depth: Current recursion depth. Internal use only.
        _served: The JSON is a response body, where a credential-named value
            the sanitizer keeps or offers for review (``credential_value_action``)
            is not reported. Internal use only.
    """
    if _depth > JSON_MAX_DEPTH:
        return

    if _field_tiers is None:
        _field_tiers = _compile_field_tiers(custom_patterns)

    if isinstance(data, dict):
        for key, value in json_members(data):
            current_path = f"{path}.{key}" if path else key

            identity_reason = (
                _identity_finding(key, value, custom_patterns) if isinstance(value, str) else None
            )
            if identity_reason is not None:
                findings.append(
                    Finding(
                        severity="error",
                        location=location,
                        field=current_path,
                        value=truncate(value),
                        reason=identity_reason,
                    )
                )
            # A sensitive name holding a value that is neither empty nor redacted
            # (the name is tested first: the allowlist check is the costly one)
            elif (
                isinstance(value, str)
                and value
                and (classified := _classify_field_finding(key, value, _field_tiers)) is not None
                and not is_redacted(value, custom_patterns)
                and not (_served and classified[0] == "error" and credential_value_action(value) != "redact")
            ):
                severity, pattern = classified
                findings.append(
                    Finding(
                        severity=severity,
                        location=location,
                        field=current_path,
                        value=truncate(value),
                        reason=f"Sensitive JSON field matching '{pattern.pattern}'",
                    )
                )

            # Recurse
            if isinstance(value, dict | list):
                check_json_fields(
                    value,
                    location,
                    findings,
                    current_path,
                    custom_patterns,
                    _field_tiers=_field_tiers,
                    _depth=_depth + 1,
                    _served=_served,
                )

    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict | list):
                check_json_fields(
                    item,
                    location,
                    findings,
                    f"{path}[{i}]",
                    custom_patterns,
                    _field_tiers=_field_tiers,
                    _depth=_depth + 1,
                    _served=_served,
                )


def check_content(
    content: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
    *,
    has_sanitized_url_credential: bool = False,
    serial_detectors: list[Any] | None = None,
    field_tiers: _FieldTiers | None = None,
) -> None:
    """Check response content for PII patterns.

    Args:
        content: Response content string
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
        has_sanitized_url_credential: When True, skip the bare base64 credential
            check for this entry's response body. Set by ``validate_har`` for
            entries listed in ``log._har_capture._sanitized_credentials`` —
            those entries' response bodies were already evaluated by the
            sanitizer's server-token preservation heuristic, so re-flagging
            them here would be a false positive.
        serial_detectors: High-confidence serial_number detectors (from
            ``high_confidence_serial_detectors``), applied delimiter-aware to
            candidate tokens. ``None`` compiles them from ``custom_patterns``;
            ``validate_har`` pre-compiles once per file.
        field_tiers: Pre-compiled field tiers (compiled on demand if omitted)
    """
    # `content` is a whole response body, so the whole-string form is required.
    # `is_redacted` matches its allowlist families with `re.search` — right for
    # a single field value, wrong for a document. A run of six or more zeros
    # (`0{6,}` — a separator-less zero MAC, a zeroed counter, a `#000000` in
    # minified CSS) or a literal `XXX` / `REDACTED` anywhere in the body was
    # enough to skip every content check for that entry. 209 of 750 committed
    # fleet entries were being skipped this way, including an XB10 page
    # carrying a plaintext default Wi-Fi password (issue #194).
    if not content or is_fully_redacted(content, custom_patterns):
        return

    stripped = content.strip()
    # A base64-wrapped JSON or URL payload is data, checked as the text it
    # wraps — the sanitizer sanitizes inside it rather than replacing it.
    payload = decode_base64_payload(stripped)
    if payload is not None:
        content = payload
    elif (
        not has_sanitized_url_credential
        and is_base64_credential(stripped)
        and not is_redacted(stripped, custom_patterns)
    ):
        findings.append(
            Finding(
                severity="error",
                location=location,
                field="content",
                value=truncate(stripped),
                reason="Bare base64 credential in response body",
            )
        )
        return

    # A body the sanitizer routes as JSON (route_body: it parses as a JSON
    # object or array, whatever its type) gets its field rules checked here:
    # identity keys and credential-named keys, the ones it redacts. Identity-
    # style names (username, login) are only flagged by the sanitizer and
    # are mostly translation-bundle keys in responses, so they are not
    # reported — a warning no sanitize run clears.
    field_macs: set[str] = set()
    data = parse_json_container(content)
    if data is not None:
        tiers = field_tiers if field_tiers is not None else _compile_field_tiers(custom_patterns)
        start = len(findings)
        check_json_fields(
            data, location, findings, "", custom_patterns, _field_tiers=replace(tiers, flag=()), _served=True
        )
        field_macs = {f.value for f in findings[start:] if f.reason == _IDENTITY_REASONS["mac_address"]}

    if serial_detectors is None:
        serial_detectors = _compile_serial_detectors(custom_patterns)
    # A JSON body is read one decoded string at a time — every value and key,
    # at any depth — as the sanitizer reads it: escapes (`\u003c`) hide no
    # markup, and no match runs from one string into the next.
    texts = iter_json_strings(data) if data is not None else (content,)
    seen_serials: set[str] = set()
    for text in texts:
        _scan_text(text, location, findings, custom_patterns, serial_detectors, field_macs, seen_serials)


def _scan_text(
    text: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None,
    serial_detectors: list[Any],
    field_macs: set[str],
    seen_serials: set[str],
) -> None:
    """Run the content text checks on one text: a whole body, or one decoded JSON string.

    Args:
        text: The text to scan
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional custom patterns
        serial_detectors: Compiled high-confidence vendor serial detectors
        field_macs: MACs already reported as identity fields of this body
        seen_serials: Vendor serials already reported for this body
    """
    # Each check first tests a character or word its pattern cannot match
    # without — most decoded JSON strings need none of the regexes.
    has_colon = ":" in text
    has_tag = "<" in text

    # Check for MAC addresses
    for match in MAC_PATTERN.finditer(text) if has_colon or "-" in text else ():
        mac = match.group(0)
        if mac in field_macs:
            continue
        # Documentation examples, and one byte repeated (broadcast, zero): the
        # sanitizer leaves the constants too, since scripts compare against them.
        if is_constant_mac(mac) or mac.upper() in ("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"):
            continue
        # Skip if it matches hash pattern
        if is_redacted(mac, custom_patterns):
            continue

        findings.append(
            Finding(
                severity="warning",
                location=location,
                field="content",
                value=mac,
                reason="Potential real MAC address",
            )
        )

    # Check for serial numbers
    for pattern in SERIAL_PATTERNS if SERIAL_LABEL_HINT_RE.search(text) else ():
        for match in pattern.finditer(text):
            value = match.group(match.lastindex or 0)
            if not is_redacted(value, custom_patterns):
                findings.append(
                    Finding(
                        severity="warning",
                        location=location,
                        field="content",
                        value=truncate(value),
                        reason="Potential serial number",
                    )
                )

    # Labeled default credentials in sibling-element label/value pairs
    # (Technicolor "Device Label Information" sticker block). The SAME compiled
    # patterns the sanitizer's pass 7c uses are imported here, so the two
    # cannot drift apart on what counts as a labeled default credential — the
    # 0.12.1 serial reconciliation fixed that for vendor serial tokens only,
    # leaving this layer divergent (validate had no label-anchored credential
    # check at all).
    #
    # Severity for the password is error, matching ADR-13's rule for
    # deterministic matches: the label states outright that the value is a
    # password, so an unredacted match is a known credential leak, not a maybe.
    # This is the gate that blessed a contributor's real Wi-Fi password on its
    # way to a public issue (issue #194). The SSID is a warning — it identifies
    # the network rather than authenticating to it.
    for sibling_pattern, sibling_severity, sibling_reason in (
        (
            (SIBLING_PASSWORD_RE, "error", "Plaintext password in a labeled field"),
            (SIBLING_SSID_RE, "warning", "Wi-Fi network name (SSID) in a labeled field"),
            (SSID_ATTRIBUTE_RE, "warning", "Wi-Fi network name (SSID) in an SSID-named element"),
        )
        if has_tag
        else ()
    ):
        for match in sibling_pattern.finditer(text):
            value = match.group(2)
            if is_structural_value_sensitive(value, custom_patterns):
                findings.append(
                    Finding(
                        severity=sibling_severity,
                        location=location,
                        field="content",
                        value=truncate(value),
                        reason=sibling_reason,
                    )
                )

    for option_value, _offset in iter_ssid_option_values(text, custom_patterns) if has_tag else ():
        findings.append(
            Finding(
                severity="warning",
                location=location,
                field="content",
                value=truncate(option_value),
                reason="Wi-Fi network name (SSID) in an SSID-named dropdown",
            )
        )

    # Vendor-format serials as standalone tokens — delimiter-aware. Mirrors
    # the sanitizer's redact_vendor_serials pass: the same high-confidence
    # serial_number detectors applied to the same token extraction, so what
    # the sanitizer auto-redacts, validate errors on when found unredacted.
    # (CM2500 round 1: the serial inside RouterStatus.htm's tagValueList had
    # no label for SERIAL_PATTERNS to anchor on, and validate blessed the
    # leak.) Severity is error: a vendor-format match is a known serial
    # layout, not a maybe.
    if serial_detectors:
        for token_match in VENDOR_SERIAL_TOKEN_RE.finditer(text):
            token = token_match.group(0)
            if token in seen_serials:
                continue
            reason = match_vendor_serial(token, serial_detectors)
            if reason is not None and not is_redacted(token, custom_patterns):
                seen_serials.add(token)
                findings.append(
                    Finding(
                        severity="error",
                        location=location,
                        field="content",
                        value=truncate(token),
                        reason=f"Vendor-format serial number ({reason})",
                    )
                )

    # Check for public IPs. Netmasks, reserved first octets (255.x broadcast
    # masks, 0.x), and version-string shapes (per is_valid_ip_address) match
    # the dotted-quad pattern but are not host addresses — the sanitizer
    # preserves all of them, so flagging them here puts cosmetic noise on
    # every healthy capture.
    ipv6_spans = ipv6_host_spans(text)
    for match in IP_PATTERN.finditer(text) if "." in text else ():
        ip = match.group(1)
        if any(start <= match.start() < end for start, end in ipv6_spans):
            continue  # the IPv4 tail of an IPv4-mapped IPv6 address, reported as IPv6
        if (
            not is_private_ip(ip)
            and not ip.startswith(("255.", "0."))
            and not is_netmask(ip)
            and is_valid_ip_address(ip)
            and not is_redacted(ip, custom_patterns)
        ):
            findings.append(
                Finding(
                    severity="warning",
                    location=location,
                    field="content",
                    value=ip,
                    reason="Potential public IP address",
                )
            )

    # IPv6 addresses: every one the sanitizer's IPv6 pass rewrites (the same
    # IPV6_RE candidates is_ipv6_host_address accepts), in every body route — a
    # link-local EUI-64 address embeds the device's MAC. Its placeholders
    # (the 2001:db8:: documentation prefix, the static "::") are allowlisted.
    for start, end in ipv6_spans:
        address = text[start:end]
        if not is_redacted(address, custom_patterns):
            findings.append(
                Finding(
                    severity="warning",
                    location=location,
                    field="content",
                    value=address,
                    reason="Potential IPv6 address",
                )
            )


def validate_har(
    har_path: Path | str,
    custom_patterns: str | dict[str, Any] | None = None,
) -> list[Finding]:
    """Validate a HAR file for secrets/PII.

    Args:
        har_path: Path to HAR file (.har or .har.gz)
        custom_patterns: Optional path to custom patterns JSON file

    Returns:
        List of findings (empty if clean)

    Example:
        >>> findings = validate_har("device.har")
        >>> if findings:
        ...     print(f"Found {len(findings)} issues")
    """
    har_path = Path(har_path)
    findings: list[Finding] = []

    # Compiled once per file and applied per entry.
    serial_detectors = _compile_serial_detectors(custom_patterns)
    field_tiers = _compile_field_tiers(custom_patterns)

    har_data = load_har(har_path)

    log = har_data.get("log", {})
    entries = log.get("entries", [])

    # Entries whose URL credentials were sanitized by har-capture — the sanitizer
    # already applied the server-token preservation heuristic to their response
    # bodies, so re-running the bare base64 check here would be a false positive.
    url_cred_entry_indices: set[int] = {
        loc["entry_index"]
        for loc in log.get("_har_capture", {}).get("_sanitized_credentials", [])
        if isinstance(loc, dict) and isinstance(loc.get("entry_index"), int)
    }

    for i, entry in enumerate(entries):
        request = entry.get("request", {})
        response = entry.get("response", {})

        url = request.get("url", "")
        location = f"Entry {i}: {truncate(url, 60)}"

        # The query as the URL string and as the parsed array: one query recorded
        # twice, so a finding in both is reported once.
        seen: set[tuple[str, str]] = set()
        check_url(url, f"{location} (url)", findings, custom_patterns, field_tiers=field_tiers, seen=seen)
        check_query_string(
            request.get("queryString"),
            f"{location} (queryString)",
            findings,
            custom_patterns,
            field_tiers=field_tiers,
            seen=seen,
        )

        # Check request headers
        check_headers(request.get("headers", []), f"{location} (request)", findings, custom_patterns)

        # Check response headers
        check_headers(response.get("headers", []), f"{location} (response)", findings, custom_patterns)

        # Referer / Location / Content-Location, and HAR's redirectURL copy of
        # Location, carry a URL whose query can repeat the request URL's
        # credential or sensitive parameters.
        redirect_url = response.get("redirectURL")
        if isinstance(redirect_url, str):
            check_url(
                redirect_url, f"{location} (redirectURL)", findings, custom_patterns, field_tiers=field_tiers
            )
        for side, headers in (("request", request.get("headers")), ("response", response.get("headers"))):
            for header in headers if isinstance(headers, list) else []:
                if (
                    isinstance(header, dict)
                    and str(header.get("name", "")).lower() in URL_VALUED_HEADERS
                    and isinstance(header.get("value"), str)
                ):
                    check_url(
                        header["value"],
                        f"{location} ({side} header {header['name']})",
                        findings,
                        custom_patterns,
                        field_tiers=field_tiers,
                    )

        # Check POST data
        check_post_data(request.get("postData"), f"{location} (request)", findings, custom_patterns)

        # Check response content
        content_data = response.get("content", {})

        # Handle $fixture references (skip - content is in separate file)
        if "$fixture" in content_data:
            continue

        # The sanitizer's own decoder: a transport-encoded body is checked as
        # the text it carries, and binary is left alone by both tools.
        text = decode_transport_body(content_data)
        if text is None:
            continue

        check_content(
            text,
            f"{location} (content)",
            findings,
            custom_patterns,
            has_sanitized_url_credential=(i in url_cred_entry_indices),
            serial_detectors=serial_detectors,
            field_tiers=field_tiers,
        )

    return findings


# Legacy exports for backwards compatibility
SENSITIVE_HEADERS: list[str] = _load_sensitive_headers()
SENSITIVE_FIELDS: list[str] = _load_sensitive_fields()
