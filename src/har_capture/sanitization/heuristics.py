"""Heuristic detection of suspicious values.

This module provides functions to detect values that may be PII but don't
match auto-redaction patterns. These values are flagged for user review.
"""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from har_capture.sanitization.report import ConfidenceLevel

# Safe patterns - values matching these should NOT be flagged
SAFE_PATTERNS: list[re.Pattern[str]] = [
    # Status values
    re.compile(
        r"^(Good|Bad|OK|Error|Locked|Unlocked|Operational|Disabled|Enabled|Active|Inactive|Online|Offline|Up|Down|Connected|Disconnected)$",
        re.IGNORECASE,
    ),
    # Band indicators
    re.compile(r"^(2\.4g|5g|6g|2\.4GHz|5GHz|6GHz|2\.4\s*GHz|5\s*GHz)$", re.IGNORECASE),
    # Security types
    re.compile(r"^(WPA|WPA2|WPA3|WEP|NONE|Open|WPA2-PSK|WPA-PSK|WPA2-Enterprise|WPA3-SAE)$", re.IGNORECASE),
    # Channel/frequency numbers
    re.compile(r"^\d+$"),
    re.compile(r"^\d+\s*Hz$", re.IGNORECASE),
    re.compile(r"^-?\d+\s*dB(m|mV)?$", re.IGNORECASE),
    # Version strings
    re.compile(r"^[Vv]?\d+\.\d+(\.\d+)?([a-zA-Z])?$"),
    # Empty/placeholder
    re.compile(r"^(-{1,}|none|null|N/A|n/a|NA|---)$", re.IGNORECASE),
    # Common technical values
    re.compile(r"^(true|false|yes|no|on|off)$", re.IGNORECASE),
    # Time formats
    re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$"),
    # Date formats
    re.compile(r"^\d{1,4}[-/]\d{1,2}[-/]\d{1,4}$"),
    # Percentage
    re.compile(r"^\d+(\.\d+)?%$"),
    # Signal strength indicators
    re.compile(r"^(Excellent|Good|Fair|Poor|Weak|Strong)$", re.IGNORECASE),
    # Already redacted placeholders
    re.compile(r"^\*\*\*[A-Z]+\*\*\*$"),
    re.compile(r"^[A-Z]+_[a-f0-9]{8}$"),
    re.compile(r"^XX:XX:XX:XX:XX:XX$"),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^10\.255\.\d+\.\d+$"),
    re.compile(r"^192\.0\.2\.\d+$"),
    # Common protocol/interface names
    re.compile(r"^(eth\d*|wlan\d*|lo|br\d*|vlan\d*|lan|wan)$", re.IGNORECASE),
]

# =============================================================================
# Heuristic Detection Thresholds
# =============================================================================

# Security: Maximum SSID name length for regex check (prevents ReDoS)
# WiFi standard allows up to 32 chars, but this generous limit prevents
# catastrophic backtracking on malicious input while catching real SSIDs
_SSID_NAME_MAX_LENGTH = 100

# Entropy thresholds for password/token detection
_ENTROPY_THRESHOLD_DEFAULT = 2.8  # Higher threshold reduces false positives
_ENTROPY_THRESHOLD_MIXED = 2.0  # Lower threshold for 3+ character types
_MIN_ENTROPY_LENGTH = 8  # Minimum length to check entropy
_MAX_ENTROPY_LENGTH = 64  # Maximum length to check entropy

# SSID detection ranges (WiFi standard: 0-32 octets, but 1-32 practical)
_SSID_MIN_LENGTH = 3  # Too short to be real SSID
_SSID_MAX_LENGTH = 32  # WiFi standard maximum
_SSID_TYPICAL_MIN = 4  # Typical SSID range
_SSID_TYPICAL_MAX = 24  # Typical SSID range

# Device name detection ranges
_DEVICE_NAME_MIN_LENGTH = 3
_DEVICE_NAME_MAX_LENGTH = 64


def is_safe_value(value: str) -> bool:
    """Check if a value matches safe patterns.

    Args:
        value: The value to check

    Returns:
        True if the value is safe (should not be flagged)
    """
    value = value.strip()
    if not value:
        return True

    return any(pattern.match(value) for pattern in SAFE_PATTERNS)


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness (potential password/token).

    Args:
        s: The string to analyze

    Returns:
        Entropy value (0 = no randomness, higher = more random)
    """
    if not s:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    # Calculate entropy
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def is_ssid_like(value: str) -> tuple[bool, str]:
    """Check if a value looks like a WiFi SSID.

    SSIDs are typically:
    - 1-32 characters
    - Mix of letters, numbers, hyphens, underscores
    - Often have patterns like "Name-5G", "Name_Guest", etc.

    Args:
        value: The value to check

    Returns:
        Tuple of (is_ssid_like, reason)
    """
    value = value.strip()

    # Too short or too long
    if len(value) < _SSID_MIN_LENGTH or len(value) > _SSID_MAX_LENGTH:
        return False, ""

    # Must contain at least one letter
    if not re.search(r"[a-zA-Z]", value):
        return False, ""

    # Common SSID patterns
    ssid_patterns = [
        (r"[-_](2\.?4g?|5g|6g|guest|ext|plus)$", "ends with band/extension suffix"),
        (r"^(home|office|guest|wifi|network|net)[-_]", "starts with common prefix"),
        (r"[-_](home|office|guest|wifi|network|net)$", "ends with common suffix"),
        (r"^[A-Z][a-z]+[-_][A-Z][a-z]+", "CamelCase with separator (likely name)"),
        (r"^[A-Za-z]+[-_]\d+$", "name followed by number"),
    ]

    for pattern, reason in ssid_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True, f"SSID-like pattern: {reason}"

    # Check for typical SSID character composition
    # Letters + optional hyphens/underscores/spaces, no special chars
    # SECURITY: Length check prevents ReDoS on malicious input
    if len(value) <= _SSID_NAME_MAX_LENGTH and re.match(r"^[a-zA-Z0-9][-_\w\s]*[a-zA-Z0-9]$", value):
        # Has mix of letters and is reasonable length
        if _SSID_TYPICAL_MIN <= len(value) <= _SSID_TYPICAL_MAX and re.search(r"[a-zA-Z]", value):
            return True, "Alphanumeric string in typical SSID length range"

    return False, ""


def is_device_name_like(value: str) -> tuple[bool, str]:
    """Check if a value looks like a device name.

    Device names often contain:
    - Personal names ("John's iPhone")
    - Device types ("MacBook-Pro", "Galaxy-S21")
    - Location names ("Living-Room-TV")

    Args:
        value: The value to check

    Returns:
        Tuple of (is_device_name, reason)
    """
    value = value.strip()

    if len(value) < _DEVICE_NAME_MIN_LENGTH or len(value) > _DEVICE_NAME_MAX_LENGTH:
        return False, ""

    # Must contain letters
    if not re.search(r"[a-zA-Z]", value):
        return False, ""

    # Device name patterns
    device_patterns = [
        (r"'s[-\s]", "possessive pattern (someone's device)"),
        (r"(?i)(iphone|ipad|macbook|android|galaxy|pixel|surface|kindle)", "device brand/type"),
        (r"(?i)(laptop|desktop|phone|tablet|tv|speaker|printer|camera)", "device category"),
        (r"(?i)(living|bed|bath|kitchen|office|garage|basement)[-_\s]?room", "room name"),
    ]

    for pattern, reason in device_patterns:
        if re.search(pattern, value):
            return True, f"Device name pattern: {reason}"

    return False, ""


def is_high_entropy(value: str, threshold: float = _ENTROPY_THRESHOLD_DEFAULT) -> tuple[bool, str]:
    """Check if a value has high entropy (potential password/token).

    Shannon entropy maximum is log2(length), so short strings have lower max entropy:
    - 8 chars: max 3.0
    - 10 chars: max 3.32
    - 16 chars: max 4.0

    A threshold of 2.8 with mixed character types catches most real passwords
    while avoiding false positives on common words and technical strings.

    Args:
        value: The value to check
        threshold: Entropy threshold (default 2.8)

    Returns:
        Tuple of (is_high_entropy, reason)
    """
    value = value.strip()

    # Only check strings of reasonable length
    if len(value) < _MIN_ENTROPY_LENGTH or len(value) > _MAX_ENTROPY_LENGTH:
        return False, ""

    entropy = calculate_entropy(value)

    # Additional check: has mix of character types
    has_lower = bool(re.search(r"[a-z]", value))
    has_upper = bool(re.search(r"[A-Z]", value))
    has_digit = bool(re.search(r"\d", value))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", value))

    char_types = sum([has_lower, has_upper, has_digit, has_special])

    # Require both: entropy above threshold AND mixed character types
    # Higher threshold (2.8) reduces false positives on technical strings
    if entropy >= threshold and char_types >= 2:
        return True, f"High entropy ({entropy:.1f}) with mixed character types"

    # Also flag strings with 3+ character types even at slightly lower entropy
    # These are almost certainly passwords (e.g., "P@ssword" has special+upper+lower)
    if char_types >= 3 and entropy >= _ENTROPY_THRESHOLD_MIXED:
        return True, f"Mixed character types ({char_types}) with moderate entropy ({entropy:.1f})"

    return False, ""


def is_adjacent_to_redacted(
    values: list[str],
    index: int,
    redacted_prefixes: tuple[str, ...] = ("***", "MAC_", "PASS_", "PRIV_IP_", "TOKEN_"),
) -> tuple[bool, str]:
    """Check if a value is adjacent to an already-redacted value.

    Values next to redacted placeholders are more likely to be sensitive.

    Args:
        values: List of values (e.g., from pipe-delimited string)
        index: Index of the value to check
        redacted_prefixes: Prefixes that indicate redacted values

    Returns:
        Tuple of (is_adjacent, reason)
    """

    def is_redacted(v: str) -> bool:
        v = v.strip()
        if v == "XX:XX:XX:XX:XX:XX":
            return True
        if v == "0.0.0.0":  # noqa: S104 - comparing string value, not binding to interface
            return True
        return any(v.startswith(prefix) for prefix in redacted_prefixes)

    # Check previous value
    if index > 0 and is_redacted(values[index - 1]):
        return True, "Adjacent to redacted value (before)"

    # Check next value
    if index < len(values) - 1 and is_redacted(values[index + 1]):
        return True, "Adjacent to redacted value (after)"

    return False, ""


def get_confidence_for_value(
    value: str,  # noqa: ARG001 - kept for API consistency, may be used in future heuristics
    is_ssid: bool = False,
    is_device: bool = False,
    is_entropy: bool = False,
    is_adjacent: bool = False,
) -> ConfidenceLevel:
    """Determine confidence level for a flagged value.

    Args:
        value: The flagged value
        is_ssid: Whether it matches SSID patterns
        is_device: Whether it matches device name patterns
        is_entropy: Whether it has high entropy
        is_adjacent: Whether it's adjacent to redacted value

    Returns:
        Confidence level
    """
    from har_capture.sanitization.report import ConfidenceLevel

    # Adjacent to redacted + another indicator = HIGH
    if is_adjacent and (is_ssid or is_device or is_entropy):
        return ConfidenceLevel.HIGH

    # SSID-like or high entropy alone = MEDIUM
    if is_ssid or is_entropy:
        return ConfidenceLevel.MEDIUM

    # Device name alone = MEDIUM
    if is_device:
        return ConfidenceLevel.MEDIUM

    # Just adjacent = LOW
    if is_adjacent:
        return ConfidenceLevel.LOW

    # Default
    return ConfidenceLevel.LOW


def analyze_value(
    value: str,
    values_context: list[str] | None = None,
    value_index: int | None = None,
) -> tuple[bool, ConfidenceLevel, str, str]:
    """Analyze a value and determine if it should be flagged.

    Args:
        value: The value to analyze
        values_context: Optional list of surrounding values (for adjacency check)
        value_index: Index of value in values_context

    Returns:
        Tuple of (should_flag, confidence, category, reason)
    """
    from har_capture.sanitization.report import ConfidenceLevel

    value = value.strip()

    # Skip empty or safe values
    if not value or is_safe_value(value):
        return False, ConfidenceLevel.LOW, "", ""

    # Run detection heuristics
    is_ssid, ssid_reason = is_ssid_like(value)
    is_device, device_reason = is_device_name_like(value)
    is_entropy, entropy_reason = is_high_entropy(value)

    is_adjacent = False
    adjacent_reason = ""
    if values_context is not None and value_index is not None:
        is_adjacent, adjacent_reason = is_adjacent_to_redacted(values_context, value_index)

    # Determine if we should flag
    should_flag = is_ssid or is_device or is_entropy or is_adjacent

    if not should_flag:
        return False, ConfidenceLevel.LOW, "", ""

    # Determine category and reason
    if is_ssid:
        category = "wifi_ssid"
        reason = ssid_reason
    elif is_device:
        category = "device_name"
        reason = device_reason
    elif is_entropy:
        category = "credential"
        reason = entropy_reason
    else:
        category = "suspicious"
        reason = adjacent_reason

    # Add adjacency info if applicable
    if is_adjacent and reason != adjacent_reason:
        reason = f"{reason}; {adjacent_reason}"

    confidence = get_confidence_for_value(
        value,
        is_ssid=is_ssid,
        is_device=is_device,
        is_entropy=is_entropy,
        is_adjacent=is_adjacent,
    )

    return True, confidence, category, reason
