"""Validate HAR files for potential secrets/PII before committing.

Scans HAR files for:
- Sensitive headers (Authorization, Cookie, Set-Cookie with real values)
- Sensitive form fields (password, token, credential, etc.)
- MAC addresses (non-anonymized)
- Serial numbers
- Real IP addresses (non-private)

This module has ZERO external dependencies (stdlib only).
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from har_capture.patterns import load_sensitive_patterns
from har_capture.patterns.redaction import (
    is_base64_credential,
    is_base64_decodable_text,
    is_cookie_attribute_metadata,
)
from har_capture.patterns.redaction import (
    is_redacted as check_if_redacted,
)
from har_capture.validation.completeness import load_har

# Cookie attribute-only values (not actual session data)
COOKIE_ATTRIBUTES_ONLY: list[str] = [
    r"^(Secure\s*;?\s*)+$",
    r"^(HttpOnly\s*;?\s*)+$",
    r"^(Secure|HttpOnly)(\s*;\s*(Secure|HttpOnly))*\s*;?\s*$",
    r"^$",
]

# MAC address pattern (not anonymized)
MAC_PATTERN = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

# Serial number patterns (manufacturer-specific)
# Tag chains `(?:<[^>]*>\s*)*` tolerate whitespace between tags so serials whose
# label and value sit in sibling elements (Technicolor .jst span pairs) are caught.
SERIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"serial[^:]*:\s*(?:<[^>]*>\s*)*[A-Z0-9]{8,}", re.IGNORECASE),
    re.compile(r"SN[:\s]+(?:<[^>]*>\s*)*[A-Z0-9]{8,}", re.IGNORECASE),
    # Serial numbers in HTML table cells (label in one td, value in next td)
    re.compile(
        r"(?:Serial\s*Number|SerialNum|SN|S/N)\s*(?:</\w+>\s*)*</td>\s*<td[^>]*>\s*(?:<[^>]*>\s*)*([A-Za-z0-9\-]{8,})",
        re.IGNORECASE,
    ),
]

# Public IP pattern (not private ranges)
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


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
    # Fallback for legacy format
    if not patterns:
        patterns = fields.get("patterns", [])
    return patterns


def _compile_sensitive_fields(custom_patterns: str | dict[str, Any] | None = None) -> list[re.Pattern[str]]:
    """Compile sensitive field patterns for efficient matching.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        List of compiled regex patterns (case-insensitive)
    """
    return [re.compile(p, re.IGNORECASE) for p in _load_sensitive_fields(custom_patterns)]


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


def check_url(
    url: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
) -> None:
    """Check URL query parameters for base64-encoded credentials.

    Detects URL token authentication patterns where base64(user:pass)
    is passed as a bare query parameter or parameter value.

    Args:
        url: Full URL string
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return

    # Single pass over raw segments. We avoid parse_qsl because it treats
    # '=' as a key/value separator, stripping base64 padding.
    for segment in parsed.query.split("&"):
        # First check the full segment (catches base64 tokens with '=' padding)
        if is_base64_credential(segment) and not is_redacted(segment, custom_patterns):
            findings.append(
                Finding(
                    severity="error",
                    location=location,
                    field="query string",
                    value=truncate(segment),
                    reason="Base64-encoded credential (user:pass) as bare URL query parameter",
                )
            )
        elif "=" in segment:
            _, _, val = segment.partition("=")
            if val and is_base64_credential(val) and not is_redacted(val, custom_patterns):
                key = segment.partition("=")[0]
                findings.append(
                    Finding(
                        severity="error",
                        location=location,
                        field=f"query param '{key}'",
                        value=truncate(val),
                        reason="Base64-encoded credential (user:pass) in URL query parameter",
                    )
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


def _check_form_params(
    pairs: list[tuple[str, str]],
    location: str,
    findings: list[Finding],
    sensitive_fields: list[re.Pattern[str]],
    custom_patterns: str | dict[str, Any] | None = None,
) -> None:
    """Check form name/value pairs for sensitive fields and encoded credentials.

    Sensitive-named fields with unredacted values are errors. In a
    login-shaped form (any field name matches a sensitive pattern), a
    base64-decodable value in an unrecognized field is a warning — the
    backstop for vendor credential fields the patterns don't know yet
    (the Sercomm/Hitron ``pws`` class, cable_modem_monitor issue #92).

    Args:
        pairs: Form (name, value) pairs
        location: Location string for findings
        findings: List to append findings to
        sensitive_fields: Pre-compiled sensitive field patterns
        custom_patterns: Optional path to custom patterns file
    """
    login_shaped = any(any(p.search(name) for p in sensitive_fields) for name, _ in pairs)

    for name, value in pairs:
        if not value or is_redacted(value, custom_patterns):
            continue

        matched = next((p for p in sensitive_fields if p.search(name)), None)
        if matched:
            findings.append(
                Finding(
                    severity="error",
                    location=location,
                    field=name,
                    value=truncate(value),
                    reason=f"Sensitive form field matching '{matched.pattern}'",
                )
            )
        elif login_shaped and is_base64_decodable_text(value):
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

    sensitive_fields = _compile_sensitive_fields(custom_patterns)

    # Check params (form data)
    params = post_data.get("params", [])
    pairs = [(param.get("name", ""), param.get("value", "")) for param in params]
    _check_form_params(pairs, location, findings, sensitive_fields, custom_patterns)

    # Check text (raw body — form-urlencoded, JSON, or XML)
    text = post_data.get("text", "")
    if text and not is_redacted(text, custom_patterns):
        mime_type = post_data.get("mimeType", "")
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
            _check_form_params(text_pairs, location + " (body)", findings, sensitive_fields, custom_patterns)
            return
        try:
            json_data = json.loads(text)
            check_json_fields(json_data, location + " (body)", findings, custom_patterns=custom_patterns)
        except json.JSONDecodeError:
            if "xml" in mime_type:
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
    import xml.etree.ElementTree as ET

    sensitive_fields = _compile_sensitive_fields(custom_patterns)

    try:
        root = ET.fromstring(text)  # noqa: S314
    except ET.ParseError:
        return

    for elem in root.iter():
        tag = elem.tag
        # Strip namespace prefix if present: {http://ns}tagname -> tagname
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        value = (elem.text or "").strip()
        if value and not is_redacted(value, custom_patterns):
            for pattern in sensitive_fields:
                if pattern.search(tag):
                    findings.append(
                        Finding(
                            severity="error",
                            location=location,
                            field=tag,
                            value=truncate(value),
                            reason=f"Sensitive XML element matching '{pattern.pattern}'",
                        )
                    )
                    break

        # Check attributes (e.g., <password value="secret"/>)
        for attr_name, attr_value in elem.attrib.items():
            if not attr_value or is_redacted(attr_value, custom_patterns):
                continue
            for pattern in sensitive_fields:
                if pattern.search(attr_name):
                    findings.append(
                        Finding(
                            severity="error",
                            location=location,
                            field=attr_name,
                            value=truncate(attr_value),
                            reason=f"Sensitive XML attribute matching '{pattern.pattern}'",
                        )
                    )
                    break


def check_json_fields(
    data: dict[str, Any] | list[Any],
    location: str,
    findings: list[Finding],
    path: str = "",
    custom_patterns: str | dict[str, Any] | None = None,
    _sensitive_fields: list[re.Pattern[str]] | None = None,
    _depth: int = 0,
) -> None:
    """Recursively check JSON for sensitive fields.

    Args:
        data: JSON data (dict or list)
        location: Location string for findings
        findings: List to append findings to
        path: Current path in the JSON structure
        custom_patterns: Optional path to custom patterns file
        _sensitive_fields: Pre-compiled sensitive field patterns. Internal use only.
        _depth: Current recursion depth. Internal use only.
    """
    if _depth > 50:
        return

    if _sensitive_fields is None:
        _sensitive_fields = _compile_sensitive_fields(custom_patterns)

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            # Skip empty or redacted values
            if isinstance(value, str) and value and not is_redacted(value, custom_patterns):
                for pattern in _sensitive_fields:
                    if pattern.search(key):
                        findings.append(
                            Finding(
                                severity="error",
                                location=location,
                                field=current_path,
                                value=truncate(value),
                                reason=f"Sensitive JSON field matching '{pattern.pattern}'",
                            )
                        )
                        break

            # Recurse
            if isinstance(value, dict | list):
                check_json_fields(
                    value,
                    location,
                    findings,
                    current_path,
                    custom_patterns,
                    _sensitive_fields=_sensitive_fields,
                    _depth=_depth + 1,
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
                    _sensitive_fields=_sensitive_fields,
                    _depth=_depth + 1,
                )


def check_content(
    content: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | dict[str, Any] | None = None,
    *,
    has_sanitized_url_credential: bool = False,
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
    """
    if not content or is_redacted(content, custom_patterns):
        return

    stripped = content.strip()
    if (
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

    # Check for MAC addresses
    for match in MAC_PATTERN.finditer(content):
        mac = match.group(0)
        # Skip if it looks anonymized
        if mac.upper() in ("00:00:00:00:00:00", "AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"):
            continue
        # Skip if all same byte (likely placeholder)
        parts = mac.upper().replace("-", ":").split(":")
        if len(set(parts)) == 1:
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
    for pattern in SERIAL_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(0)
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

    # Check for public IPs
    for match in IP_PATTERN.finditer(content):
        ip = match.group(1)
        if not is_private_ip(ip) and not is_redacted(ip, custom_patterns):
            findings.append(
                Finding(
                    severity="warning",
                    location=location,
                    field="content",
                    value=ip,
                    reason="Potential public IP address",
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

        # Check URL for base64-encoded credentials in query parameters
        check_url(url, f"{location} (url)", findings, custom_patterns)

        # Check request headers
        check_headers(request.get("headers", []), f"{location} (request)", findings, custom_patterns)

        # Check response headers
        check_headers(response.get("headers", []), f"{location} (response)", findings, custom_patterns)

        # Check POST data
        check_post_data(request.get("postData"), f"{location} (request)", findings, custom_patterns)

        # Check response content
        content_data = response.get("content", {})
        text = content_data.get("text", "")

        # Handle $fixture references (skip - content is in separate file)
        if "$fixture" in content_data:
            continue

        # Handle base64 encoded content
        if content_data.get("encoding") == "base64" and text:
            with contextlib.suppress(Exception):
                text = base64.b64decode(text).decode("utf-8", errors="replace")

        check_content(
            text,
            f"{location} (content)",
            findings,
            custom_patterns,
            has_sanitized_url_credential=(i in url_cred_entry_indices),
        )

    return findings


# Legacy exports for backwards compatibility
SENSITIVE_HEADERS: list[str] = _load_sensitive_headers()
SENSITIVE_FIELDS: list[str] = _load_sensitive_fields()
