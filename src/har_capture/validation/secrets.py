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
import gzip
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from har_capture.patterns import is_allowlisted, load_allowlist, load_sensitive_patterns

# Patterns that indicate a value is properly redacted (non-format-preserving)
# Format-preserving patterns are loaded from allowlist.json
REDACTED_PATTERNS: list[str] = [
    r"\[REDACTED\]",
    r"REDACTED",
    r"XXX+",
    r"0{6,}",  # All zeros (MAC, serial)
]

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
SERIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"serial[^:]*:\s*[A-Z0-9]{8,}", re.IGNORECASE),
    re.compile(r"SN[:\s]+[A-Z0-9]{8,}", re.IGNORECASE),
]

# Public IP pattern (not private ranges)
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _load_sensitive_headers(custom_patterns: str | None = None) -> list[str]:
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
    return result


def _load_sensitive_fields(custom_patterns: str | None = None) -> list[str]:
    """Load sensitive field patterns from patterns file.

    Args:
        custom_patterns: Optional path to custom patterns file

    Returns:
        List of sensitive field regex patterns
    """
    sensitive = load_sensitive_patterns(custom_patterns)
    patterns: list[str] = sensitive.get("fields", {}).get("patterns", [])
    return patterns


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


def is_redacted(value: str, custom_patterns: str | None = None) -> bool:
    """Check if a value appears to be properly redacted.

    Args:
        value: Value to check
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if value appears to be redacted
    """
    # Check standard redaction patterns
    if any(re.search(pattern, value, re.IGNORECASE) for pattern in REDACTED_PATTERNS):
        return True

    # Check allowlist
    allowlist = load_allowlist(custom_patterns)
    return is_allowlisted(value, allowlist)


def is_cookie_attributes_only(value: str) -> bool:
    """Check if a cookie value contains only attributes (no actual session data).

    When HARs are sanitized, cookie values may be stripped leaving just
    attributes like 'Secure; HttpOnly'. These are safe to commit.

    Args:
        value: Cookie value to check

    Returns:
        True if cookie contains only attributes
    """
    return any(re.match(pattern, value.strip(), re.IGNORECASE) for pattern in COOKIE_ATTRIBUTES_ONLY)


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


def check_headers(
    headers: list[dict[str, str]],
    location: str,
    findings: list[Finding],
    custom_patterns: str | None = None,
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


def check_post_data(
    post_data: dict[str, Any] | None,
    location: str,
    findings: list[Finding],
    custom_patterns: str | None = None,
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

    sensitive_fields = _load_sensitive_fields(custom_patterns)

    # Check params (form data)
    params = post_data.get("params", [])
    for param in params:
        name = param.get("name", "")
        value = param.get("value", "")

        if not value or is_redacted(value, custom_patterns):
            continue

        for pattern in sensitive_fields:
            if re.search(pattern, name, re.IGNORECASE):
                findings.append(
                    Finding(
                        severity="error",
                        location=location,
                        field=name,
                        value=truncate(value),
                        reason=f"Sensitive form field matching '{pattern}'",
                    )
                )
                break

    # Check text (raw body, might be JSON)
    text = post_data.get("text", "")
    if text and not is_redacted(text, custom_patterns):
        try:
            json_data = json.loads(text)
            check_json_fields(json_data, location + " (body)", findings, custom_patterns=custom_patterns)
        except json.JSONDecodeError:
            pass


def check_json_fields(
    data: dict[str, Any] | list[Any],
    location: str,
    findings: list[Finding],
    path: str = "",
    custom_patterns: str | None = None,
) -> None:
    """Recursively check JSON for sensitive fields.

    Args:
        data: JSON data (dict or list)
        location: Location string for findings
        findings: List to append findings to
        path: Current path in the JSON structure
        custom_patterns: Optional path to custom patterns file
    """
    sensitive_fields = _load_sensitive_fields(custom_patterns)

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            # Skip empty or redacted values
            if isinstance(value, str) and value and not is_redacted(value, custom_patterns):
                for pattern in sensitive_fields:
                    if re.search(pattern, key, re.IGNORECASE):
                        findings.append(
                            Finding(
                                severity="error",
                                location=location,
                                field=current_path,
                                value=truncate(value),
                                reason=f"Sensitive JSON field matching '{pattern}'",
                            )
                        )
                        break

            # Recurse
            if isinstance(value, dict | list):
                check_json_fields(value, location, findings, current_path, custom_patterns)

    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict | list):
                check_json_fields(item, location, findings, f"{path}[{i}]", custom_patterns)


def check_content(
    content: str,
    location: str,
    findings: list[Finding],
    custom_patterns: str | None = None,
) -> None:
    """Check response content for PII patterns.

    Args:
        content: Response content string
        location: Location string for findings
        findings: List to append findings to
        custom_patterns: Optional path to custom patterns file
    """
    if not content or is_redacted(content, custom_patterns):
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
    custom_patterns: str | None = None,
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

    # Load HAR
    if har_path.suffix == ".gz":
        with gzip.open(har_path, "rt", encoding="utf-8") as f:
            har_data = json.load(f)
    else:
        with open(har_path, encoding="utf-8") as f:
            har_data = json.load(f)

    entries = har_data.get("log", {}).get("entries", [])

    for i, entry in enumerate(entries):
        request = entry.get("request", {})
        response = entry.get("response", {})

        url = request.get("url", "")
        location = f"Entry {i}: {truncate(url, 60)}"

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

        check_content(text, f"{location} (content)", findings, custom_patterns)

    return findings


# Legacy exports for backwards compatibility
SENSITIVE_HEADERS: list[str] = _load_sensitive_headers()
SENSITIVE_FIELDS: list[str] = _load_sensitive_fields()
