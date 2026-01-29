"""Sanitization utilities for HAR and HTML files.

This module provides PII removal from HTML and HAR files with ZERO external
dependencies (stdlib only).

Exports:
    - sanitize_html: Remove PII from HTML content
    - sanitize_har: Remove PII from HAR data
    - sanitize_har_file: Sanitize a HAR file on disk
    - check_for_pii: Detect potential PII in content
"""

from __future__ import annotations

from har_capture.sanitization.har import (
    DEFAULT_MAX_HAR_SIZE,
    SENSITIVE_FIELD_PATTERNS,
    SENSITIVE_HEADERS,
    HarSizeError,
    HarValidationError,
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
    "validate_har_structure",
    "SENSITIVE_HEADERS",
    "SENSITIVE_FIELD_PATTERNS",
    # Size limits and errors
    "DEFAULT_MAX_HAR_SIZE",
    "HarSizeError",
    "HarValidationError",
]
