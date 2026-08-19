"""HAR validation utilities for PII detection.

This module provides validation for HAR files to detect potential
secrets and PII before committing. Useful for CI/pre-commit hooks.

Exports:
    - validate_har: Validate a HAR file for PII
    - Finding: Dataclass for validation findings
    - analyze_capture_completeness / analyze_har_file: Report what a capture
      contains and which evidence is missing from it
"""

from __future__ import annotations

from har_capture.validation.artifacts import (
    compressed_sibling_pair,
    stale_compressed_sibling,
)
from har_capture.validation.completeness import (
    MID_SESSION_CAPTURE,
    NO_POST_REQUESTS,
    SINGLE_CREDENTIAL_POST,
    CaptureCompletenessReport,
    CompletenessWarning,
    analyze_capture_completeness,
    analyze_har_file,
    load_har,
)
from har_capture.validation.secrets import (
    COOKIE_ATTRIBUTES_ONLY,
    MAC_PATTERN,
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
    # Artifact consistency
    "compressed_sibling_pair",
    "stale_compressed_sibling",
    # Capture-completeness validation
    "analyze_capture_completeness",
    "analyze_har_file",
    "load_har",
    "CaptureCompletenessReport",
    "CompletenessWarning",
    "MID_SESSION_CAPTURE",
    "NO_POST_REQUESTS",
    "SINGLE_CREDENTIAL_POST",
    # PII leak detection
    "COOKIE_ATTRIBUTES_ONLY",
    "MAC_PATTERN",
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
