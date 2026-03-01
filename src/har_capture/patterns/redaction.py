"""Consolidated redaction checking logic.

This module provides a single source of truth for determining if a value
has been redacted or sanitized. It combines pattern matching from both
configuration files and code-based patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

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


def is_redacted(value: str, custom_patterns: str | None = None) -> bool:
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
