"""HTML sanitization utilities.

This module provides PII removal from HTML content with ZERO external
dependencies (stdlib only). Designed for sanitizing device web interface
HTML before inclusion in diagnostics or fixture files.

PII Categories Removed:
    - MAC addresses (all formats)
    - Serial numbers
    - Account/Subscriber IDs
    - Private/Public IP addresses (except common gateway IPs)
    - IPv6 addresses
    - Passwords and passphrases
    - Session tokens and cookies
    - CSRF tokens
    - Email addresses
    - Config file paths (may contain ISP/customer info)
    - WiFi credentials in JavaScript variables
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

from har_capture.patterns import (
    Hasher,
    is_allowlisted,
    load_allowlist,
    load_pii_patterns,
    load_sensitive_patterns,
)

if TYPE_CHECKING:
    from typing import Any


def sanitize_html(
    html: str,
    *,
    salt: str | None = "auto",
    custom_patterns: str | None = None,
) -> str:
    """Remove sensitive information from HTML.

    This function sanitizes device HTML to remove PII before inclusion in
    diagnostics or fixture files. It's designed to be thorough while
    preserving data structure for debugging.

    Args:
        html: Raw HTML from device
        salt: Salt for hashed redaction. Options:
            - "auto" (default): Random salt, correlates within this call
            - None: Static placeholders (legacy behavior)
            - Any string: Consistent hashing across calls with same salt
        custom_patterns: Optional path to custom patterns JSON file

    Returns:
        Sanitized HTML with personal info removed

    Example:
        >>> sanitize_html("MAC: AA:BB:CC:DD:EE:FF")  # doctest: +SKIP
        'MAC: MAC_a1b2c3d4'
        >>> sanitize_html("MAC: AA:BB:CC:DD:EE:FF", salt=None)
        'MAC: ***MAC***'
    """
    hasher = Hasher.create(salt)
    pii = load_pii_patterns(custom_patterns)
    sensitive = load_sensitive_patterns(custom_patterns)

    # 1. MAC Addresses (various formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
    def replace_mac(match: re.Match[str]) -> str:
        return hasher.hash_mac(match.group(0))

    html = re.sub(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", replace_mac, html)

    # 2. Serial Numbers (various label formats)
    def replace_serial(match: re.Match[str]) -> str:
        label = match.group(1)
        serial = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
        hashed = hasher.hash_generic(serial, "SERIAL") if serial else "***SERIAL***"
        return f"{label}: {hashed}"

    html = re.sub(
        r"(Serial\s*Number|SerialNum|SN|S/N)\s*[:\s=]*(?:<[^>]*>)*\s*([a-zA-Z0-9\-]{5,})",
        replace_serial,
        html,
        flags=re.IGNORECASE,
    )

    # 3. Account/Subscriber IDs
    def replace_account(match: re.Match[str]) -> str:
        prefix = match.group(1)
        suffix = match.group(2)
        return f"{prefix} {suffix}: {hasher.hash_generic(match.group(0), 'ACCOUNT')}"

    html = re.sub(
        r"(Account|Subscriber|Customer|Device)\s*(ID|Number)\s*[:\s=]+\S+",
        replace_account,
        html,
        flags=re.IGNORECASE,
    )

    # 4. Private IP addresses (keep common gateway IPs for context)
    preserved_ips = set(pii.get("preserved_gateway_ips", []))

    def replace_private_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if ip in preserved_ips:
            return ip
        return hasher.hash_ip(ip, is_private=True)

    html = re.sub(
        r"\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b",
        replace_private_ip,
        html,
    )

    # 5. Public IP addresses (any non-private, non-localhost IP)
    def replace_public_ip(match: re.Match[str]) -> str:
        return hasher.hash_ip(match.group(0), is_private=False)

    html = re.sub(
        r"\b(?!10\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)"
        r"(?!127\.)(?!0\.)(?!255\.)"
        r"(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
        r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
        r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
        r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b",
        replace_public_ip,
        html,
    )

    # 6. IPv6 Addresses (full and compressed) - strict validation
    def replace_ipv6(match: re.Match[str]) -> str:
        text: str = match.group(0)
        # Skip if it looks like a MAC address (6 groups of 2 hex chars)
        if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", text, re.IGNORECASE):
            return text
        # Use strict validation via ipaddress module
        try:
            ipaddress.IPv6Address(text)
            return hasher.hash_ipv6(text)
        except ipaddress.AddressValueError:
            # Not a valid IPv6 address (e.g., time format "12:34:56")
            return text

    # Match potential IPv6 addresses including compressed forms like ::1
    # Use (?<![:\w]) instead of \b to handle addresses starting with ::
    html = re.sub(
        r"(?<![:\w])([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![:\w])",
        replace_ipv6,
        html,
        flags=re.IGNORECASE,
    )

    # 7. Passwords/Passphrases in HTML forms or text
    def replace_password(match: re.Match[str]) -> str:
        label = match.group(1)
        return f"{label}={hasher.hash_generic(match.group(2), 'PASS')}"

    html = re.sub(
        r'(password|passphrase|psk|key|wpa[0-9]*key)\s*[=:]\s*["\'\\]?([^"\'<>\s]+)',
        replace_password,
        html,
        flags=re.IGNORECASE,
    )

    # 8. Password input fields
    def replace_password_input(match: re.Match[str]) -> str:
        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}{hasher.hash_generic(match.group(2), 'PASS')}{suffix}"

    html = re.sub(
        r'(<input[^>]*type=["\'\\]?password["\'\\]?[^>]*value=["\'\\]?)([^"\'\\]+)(["\'\\]?)',
        replace_password_input,
        html,
        flags=re.IGNORECASE,
    )

    # 9. Session tokens/cookies (long alphanumeric strings)
    def replace_token(match: re.Match[str]) -> str:
        label = match.group(1)
        return f"{label}={hasher.hash_generic(match.group(2), 'TOKEN')}"

    html = re.sub(
        r'(session|token|auth|cookie)\s*[=:]\s*["\'\\]?([^"\'<>\s]{20,})',
        replace_token,
        html,
        flags=re.IGNORECASE,
    )

    # 10. CSRF tokens in meta tags
    def replace_csrf(match: re.Match[str]) -> str:
        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}{hasher.hash_generic(match.group(2), 'CSRF')}{suffix}"

    html = re.sub(
        r'(<meta[^>]*name=["\'\\]?csrf-token["\'\\]?[^>]*content=["\'\\]?)([^"\'\\]+)(["\'\\]?)',
        replace_csrf,
        html,
        flags=re.IGNORECASE,
    )

    # 11. Email addresses (RFC 5321 simplified)
    def replace_email(match: re.Match[str]) -> str:
        return hasher.hash_email(match.group(0))

    # Pattern supports: user@domain.tld, user.name+tag@sub.domain.co.uk
    html = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b",
        replace_email,
        html,
    )

    # 12. Config file paths (may contain ISP/customer identifiers)
    def replace_config(match: re.Match[str]) -> str:
        label = match.group(1)
        return f"{label}: {hasher.hash_generic(match.group(2), 'CONFIG')}"

    html = re.sub(
        r"(Config\s*File\s*Name|config\s*file)\s*[:\s=]+([^\s<>]+\.cfg)",
        replace_config,
        html,
        flags=re.IGNORECASE,
    )

    # 13. Motorola JavaScript password variables
    def replace_motorola_pw(match: re.Match[str]) -> str:
        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}{hasher.hash_generic(match.group(2), 'PASS')}{suffix}"

    html = re.sub(
        r"(var\s+Current(?:Pw|Password)[A-Za-z]*\s*=\s*['\"])([^'\"]+)(['\"])",
        replace_motorola_pw,
        html,
        flags=re.IGNORECASE,
    )

    # 14. WiFi credentials and device names in Netgear tagValueList
    safe_values = set(v.lower() for v in sensitive.get("tagValueList", {}).get("safe_values", []))

    def sanitize_tag_value_list(match: re.Match[str]) -> str:
        """Sanitize potential WiFi credentials and device names in tagValueList."""
        prefix = match.group(1)
        values_str = match.group(2)
        suffix = match.group(3)

        values = values_str.split("|")
        sanitized_values = []

        for i, val in enumerate(values):
            val_stripped = val.strip()
            val_lower = val_stripped.lower()

            # Check if next value is a placeholder (indicates this is a device name)
            next_val = values[i + 1].strip() if i + 1 < len(values) else ""
            is_before_placeholder = (
                next_val.startswith("***")
                or next_val.startswith("MAC_")
                or next_val.startswith("PRIV_IP_")
                or next_val == "XX:XX:XX:XX:XX:XX"
            )

            # Device name: appears before IP/MAC, contains letters, not a placeholder
            is_device_name = (
                is_before_placeholder
                and re.search(r"[a-zA-Z]", val_stripped)
                and val_stripped != "--"
                and not val_stripped.startswith("***")
                and not val_stripped.startswith("MAC_")
            )

            # WiFi credential: 8+ alphanumeric chars, not status values
            is_potential_credential = (
                len(val_stripped) >= 8
                and re.match(r"^[a-zA-Z0-9]+$", val_stripped)
                and val_lower not in safe_values
                and not re.match(r"^\d+$", val_stripped)
                and not val_stripped.startswith("***")
                and not re.match(r"^V\d", val_stripped)
                and not val_stripped.endswith("Hz")
                and not val_stripped.endswith("dB")
                and not val_stripped.endswith("dBmV")
                and "Ksym" not in val_stripped
            )

            if is_device_name:
                sanitized_values.append(hasher.hash_generic(val_stripped, "DEVICE"))
            elif is_potential_credential:
                sanitized_values.append(hasher.hash_generic(val_stripped, "WIFI"))
            else:
                sanitized_values.append(val)

        return prefix + "|".join(sanitized_values) + suffix

    html = re.sub(
        r"(var\s+tagValueList\s*=\s*['\"])([^'\"]+)(['\"])",
        sanitize_tag_value_list,
        html,
    )

    return html


def check_for_pii(
    content: str,
    filename: str = "",
    custom_patterns: str | None = None,
) -> list[dict[str, Any]]:
    """Check content for potential PII that should be sanitized.

    This function is intended for CI/PR validation to catch unsanitized
    fixtures before they are committed.

    Args:
        content: Text content to check (HTML, etc.)
        filename: Optional filename for context in warnings
        custom_patterns: Optional path to custom patterns JSON file

    Returns:
        List of dicts with 'pattern', 'match', 'line', and 'filename' for each PII found

    Example:
        >>> findings = check_for_pii("MAC: DE:AD:BE:EF:CA:FE")
        >>> findings[0]["pattern"]
        'mac_address'
    """
    pii = load_pii_patterns(custom_patterns)
    allowlist = load_allowlist(custom_patterns)
    findings: list[dict[str, Any]] = []

    for pattern_name, pattern_def in pii.get("patterns", {}).items():
        if not isinstance(pattern_def, dict) or "regex" not in pattern_def:
            continue

        regex = pattern_def["regex"]
        flags = 0
        if "flags" in pattern_def:
            for flag_name in pattern_def["flags"]:
                if flag_name == "IGNORECASE":
                    flags |= re.IGNORECASE

        matches = re.finditer(regex, content, flags)
        for match in matches:
            matched_text = match.group(0)

            # Skip if it's an allowlisted placeholder
            if is_allowlisted(matched_text, allowlist):
                continue

            # For IPv6 pattern, skip if it doesn't contain hex letters (a-f)
            if pattern_def.get("require_hex_letter") and not re.search(r"[a-f]", matched_text, re.IGNORECASE):
                continue

            # Find line number
            line_num = content.count("\n", 0, match.start()) + 1

            findings.append(
                {
                    "pattern": pattern_name,
                    "match": matched_text,
                    "line": line_num,
                    "filename": filename,
                }
            )

    return findings
