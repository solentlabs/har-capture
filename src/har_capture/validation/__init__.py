"""HAR validation utilities for PII detection.

This module provides validation for HAR files to detect potential
secrets and PII before committing. Useful for CI/pre-commit hooks.

Exports:
    - validate_har: Validate a HAR file for PII
    - Finding: Dataclass for validation findings
"""

from __future__ import annotations

from har_capture.validation.secrets import (
    COOKIE_ATTRIBUTES_ONLY,
    MAC_PATTERN,
    REDACTED_PATTERNS,
    SENSITIVE_FIELDS,
    SENSITIVE_HEADERS,
    Finding,
    check_content,
    check_headers,
    check_json_fields,
    check_post_data,
    is_cookie_attributes_only,
    is_private_ip,
    is_redacted,
    truncate,
    validate_har,
)

__all__ = [
    "COOKIE_ATTRIBUTES_ONLY",
    "MAC_PATTERN",
    "REDACTED_PATTERNS",
    "SENSITIVE_FIELDS",
    "SENSITIVE_HEADERS",
    "Finding",
    "check_content",
    "check_headers",
    "check_json_fields",
    "check_post_data",
    "is_cookie_attributes_only",
    "is_private_ip",
    "is_redacted",
    "truncate",
    "validate_har",
]
