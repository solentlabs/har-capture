"""Heuristic detection of suspicious values.

This module provides functions to detect values that may be PII but don't
match auto-redaction patterns. These values are flagged for user review.
"""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from har_capture.patterns.loader import CompiledDetector
    from har_capture.sanitization.report import ConfidenceLevel

# Safe patterns - values matching these should NOT be flagged
SAFE_PATTERNS: list[re.Pattern[str]] = [
    # Status values
    re.compile(
        r"^(Good|Bad|OK|Error|Locked|Unlocked|Operational|Disabled|Enabled|Active|Inactive|"
        r"Online|Offline|Up|Down|Connected|Disconnected|Configured|Allowed|Denied|Blocked|"
        r"In Progress|Not Synchronized|Synchronized|Not Locked|Unknown)$",
        re.IGNORECASE,
    ),
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
    # Date formats — numeric (2026-03-14, 03/14/2026)
    re.compile(r"^\d{1,4}[-/]\d{1,2}[-/]\d{1,4}$"),
    # Date formats — ctime (Sat Mar 14 21:28:45 2026)
    re.compile(
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$"
    ),
    # Date formats — RFC 2822 (Sat, 14 Mar 2026 21:28:45 GMT)
    re.compile(
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+\w+)?$"
    ),
    # Date formats — ISO 8601 (2026-03-14T21:28:45Z, with optional timezone/millis)
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"),
    # Date formats — full day name (Wednesday, 01 Jan 2003 16:01:11)
    re.compile(
        r"^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),?\s+\d{1,2}\s+"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"\d{4}\s+\d{2}:\d{2}:\d{2}$"
    ),
    # Date formats — full day name, month-first (Friday, Jan 01,2003 00:33:00)
    re.compile(
        r"^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),?\s+"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},?\s*"
        r"\d{4}\s+\d{2}:\d{2}:\d{2}$"
    ),
    # Uptime durations (14 days 07:57:25)
    re.compile(r"^\d+\s+days?\s+\d{2}:\d{2}:\d{2}$", re.IGNORECASE),
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
    # Already-redacted IPs with port suffix
    re.compile(r"^(?:0\.0\.0\.0|10\.255\.\d+\.\d+|192\.0\.2\.\d+):\d+$"),
    # Subnet masks
    re.compile(r"^255\.\d+\.\d+\.\d+$"),
    # CIDR notation (with redacted IPs)
    re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$"),
    # IPv6 addresses (including documentation prefix 2001:db8::)
    re.compile(r"^[0-9a-f:]+(?:/\d{1,3})?$", re.IGNORECASE),
    # URLs (http/https) — not PII themselves
    re.compile(r"^https?://\S+$"),
    # Common protocol/interface names
    re.compile(r"^(eth\d*|wlan\d*|lo|br\d*|vlan\d*|lan|wan)$", re.IGNORECASE),
    # Common plan/tier/role words (not PII)
    re.compile(
        r"^(premium|basic|standard|pro|enterprise|starter|free|trial|"
        r"admin|guest|user|default|custom|auto|retail|primary|backup|both)$",
        re.IGNORECASE,
    ),
    # UUID patterns (in asset URLs, tracking IDs)
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE),
    # Well-known domain names
    re.compile(r"^(?:www\.)?[\w.-]+\.(com|org|net|io|gov|edu)$", re.IGNORECASE),
    # Bracketed log messages: [DHCP IP: ...], [admin login ...], [Time s...]
    re.compile(r"^\[.+\]$"),
    # Already-redacted values with label prefixes (from serial pattern in HTML sanitizer)
    re.compile(r"^(?:SN|S/N|Serial\w*):\s*[A-Z_]+_[a-f0-9]{8}$", re.IGNORECASE),
    # Redacted emails
    re.compile(r"^user_[a-f0-9]+@redacted\.invalid$"),
]

# =============================================================================
# Heuristic Detection Thresholds
# =============================================================================

# Entropy thresholds for password/token detection
_ENTROPY_THRESHOLD_DEFAULT = 2.8  # Higher threshold reduces false positives
_ENTROPY_THRESHOLD_MIXED = 2.0  # Lower threshold for 3+ character types
_MIN_ENTROPY_LENGTH = 8  # Minimum length to check entropy
_MAX_ENTROPY_LENGTH = 64  # Maximum length to check entropy

# CamelCase pattern: HomeNetwork, MyWiFi, GuestAccess
_CAMELCASE_RE = re.compile(r"^[A-Z][a-z]+[A-Z][a-zA-Z0-9]*$")


def is_safe_value(
    value: str,
    extra_patterns: list[re.Pattern[str]] | None = None,
) -> bool:
    """Check if a value matches safe patterns.

    Args:
        value: The value to check
        extra_patterns: Additional compiled patterns (e.g., from domain pattern files)

    Returns:
        True if the value is safe (should not be flagged)
    """
    value = value.strip()
    if not value:
        return True

    if any(pattern.match(value) for pattern in SAFE_PATTERNS):
        return True

    return bool(extra_patterns and any(pattern.match(value) for pattern in extra_patterns))


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


def run_detector(value: str, detector: CompiledDetector) -> tuple[bool, str]:
    """Run a single data-driven heuristic detector against a value.

    Checks length bounds, letter requirement, regex patterns, and optional
    CamelCase matching as configured in the detector definition.

    Args:
        value: The value to check (already stripped)
        detector: Compiled detector from domain JSON

    Returns:
        Tuple of (matched, reason)
    """
    if len(value) < detector.min_length or len(value) > detector.max_length:
        return False, ""

    if detector.requires_letter and not re.search(r"[a-zA-Z]", value):
        return False, ""

    for pattern, reason in detector.patterns:
        if pattern.search(value):
            return True, f"{detector.category} pattern: {reason}"

    if detector.camelcase and _CAMELCASE_RE.match(value):
        return True, f"CamelCase pattern suggesting {detector.category}"

    return False, ""


_CREDENTIAL_PREFIX_PATTERN = re.compile(
    r"^(?:pass(?:word|wd)?|pwd|secret|token|key|auth)[\d!@#$%^&*]+$",
    re.IGNORECASE,
)


def is_credential_like(value: str) -> tuple[bool, str]:
    """Check if a value looks like a short credential (too short for entropy detection).

    Catches values like 'pass123', 'token42', 'key!2024' that start with common
    credential keywords followed by digits or special characters.

    Args:
        value: The value to check

    Returns:
        Tuple of (is_credential, reason)
    """
    value = value.strip()
    if len(value) < 4 or len(value) > 32:
        return False, ""
    if _CREDENTIAL_PREFIX_PATTERN.match(value):
        return True, "Credential-like prefix pattern (keyword + digits/special)"
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
    redacted_prefixes: tuple[str, ...] = (
        "***",
        "MAC_",
        "PASS_",
        "PRIV_IP_",
        "TOKEN_",
        "SERIAL_",
        "FIELD_",
        "CREDENTIAL_",
        "AUTH_",
        "COOKIE_",
        "WIFI_SSID_",
        "WIFI_",
        "DEVICE_",
        "CC_",
    ),
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
    *,
    detector_confidence: str | None = None,
    is_entropy: bool = False,
    is_adjacent: bool = False,
) -> ConfidenceLevel:
    """Determine confidence level for a flagged value.

    Args:
        value: The flagged value
        detector_confidence: Confidence declared by the matched detector ("low"/"medium"/"high"),
            or None if no detector matched
        is_entropy: Whether it has high entropy
        is_adjacent: Whether it's adjacent to redacted value

    Returns:
        Confidence level
    """
    from har_capture.sanitization.report import ConfidenceLevel

    has_detector = detector_confidence is not None

    # Adjacent to redacted + another indicator = HIGH
    if is_adjacent and (has_detector or is_entropy):
        return ConfidenceLevel.HIGH

    # Detector matched — use its declared confidence
    if has_detector and detector_confidence:
        try:
            return ConfidenceLevel[detector_confidence.upper()]
        except KeyError:
            return ConfidenceLevel.MEDIUM

    # High entropy alone = MEDIUM
    if is_entropy:
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
    extra_safe_patterns: list[re.Pattern[str]] | None = None,
    compiled_detectors: list[CompiledDetector] | None = None,
) -> tuple[bool, ConfidenceLevel, str, str]:
    """Analyze a value and determine if it should be flagged.

    Runs domain-driven detectors (if provided), entropy analysis,
    credential-prefix matching, and adjacency detection.

    Args:
        value: The value to analyze
        values_context: Optional list of surrounding values (for adjacency check)
        value_index: Index of value in values_context
        extra_safe_patterns: Additional compiled safe-value patterns (from domain files)
        compiled_detectors: Data-driven detectors from domain files. Without detectors,
            only entropy/credential/adjacency detection runs.

    Returns:
        Tuple of (should_flag, confidence, category, reason)
    """
    from har_capture.sanitization.report import ConfidenceLevel

    value = value.strip()

    # Skip empty or safe values
    if not value or is_safe_value(value, extra_patterns=extra_safe_patterns):
        return False, ConfidenceLevel.LOW, "", ""

    # Run domain-driven detectors
    detector_category = ""
    detector_reason = ""
    detector_confidence: str | None = None
    for detector in compiled_detectors or []:
        matched, reason = run_detector(value, detector)
        if matched:
            detector_category = detector.category
            detector_reason = reason
            detector_confidence = detector.confidence
            break  # First matching detector wins

    # Run core (domain-agnostic) heuristics
    is_entropy, entropy_reason = is_high_entropy(value)
    is_cred, cred_reason = is_credential_like(value)

    is_adjacent = False
    adjacent_reason = ""
    if values_context is not None and value_index is not None:
        is_adjacent, adjacent_reason = is_adjacent_to_redacted(values_context, value_index)

    has_detector = detector_confidence is not None
    should_flag = has_detector or is_entropy or is_cred or is_adjacent

    if not should_flag:
        return False, ConfidenceLevel.LOW, "", ""

    # Determine category and reason (credential prefix takes priority over detectors)
    if is_cred:
        category = "credential"
        reason = cred_reason
    elif has_detector:
        category = detector_category
        reason = detector_reason
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
        detector_confidence=detector_confidence,
        is_entropy=is_entropy or is_cred,
        is_adjacent=is_adjacent,
    )

    return True, confidence, category, reason
