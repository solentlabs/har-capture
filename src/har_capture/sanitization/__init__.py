"""Sanitization utilities for HAR and HTML files.

This module provides PII removal from HTML and HAR files with ZERO external
dependencies (stdlib only).

Exports:
    - sanitize_html: Remove PII from HTML content
    - sanitize_har: Remove PII from HAR data
    - sanitize_har_file: Sanitize a HAR file on disk
    - check_for_pii: Detect potential PII in content
    - SanitizationReport: Report of sanitization operations
    - RedactionCollector: Collector for tracking redactions
"""

from __future__ import annotations

from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.har import (
    DEFAULT_MAX_HAR_SIZE,
    SENSITIVE_FIELD_PATTERNS,
    SENSITIVE_HEADERS,
    HarSizeError,
    HarValidationError,
    appears_sanitized,
    apply_user_redactions,
    is_flaggable_field,
    is_sensitive_field,
    sanitize_entry,
    sanitize_har,
    sanitize_har_file,
    sanitize_header_value,
    sanitize_post_data,
    validate_har_structure,
)
from har_capture.sanitization.html import (
    check_for_pii,
    sanitize_html,
)
from har_capture.sanitization.report import (
    ConfidenceLevel,
    FlaggedValue,
    RedactionStatus,
    SanitizationReport,
)

__all__ = [
    # HTML sanitization
    "sanitize_html",
    "check_for_pii",
    # HAR sanitization
    "sanitize_har",
    "sanitize_har_file",
    "sanitize_entry",
    "sanitize_post_data",
    "sanitize_header_value",
    "is_sensitive_field",
    "is_flaggable_field",
    "validate_har_structure",
    "apply_user_redactions",
    "appears_sanitized",
    "SENSITIVE_HEADERS",
    "SENSITIVE_FIELD_PATTERNS",
    # Size limits and errors
    "DEFAULT_MAX_HAR_SIZE",
    "HarSizeError",
    "HarValidationError",
    # Report types
    "SanitizationReport",
    "FlaggedValue",
    "ConfidenceLevel",
    "RedactionStatus",
    "RedactionCollector",
]
