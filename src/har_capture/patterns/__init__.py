"""Pattern loading and hashing utilities for sanitization.

This module provides:
- Loading of PII patterns, sensitive fields, and allowlists from JSON
- Salted hash generation for correlation-preserving redaction
- Pattern merging for custom user patterns
"""

from __future__ import annotations

from har_capture.patterns.hasher import Hasher
from har_capture.patterns.loader import (
    PatternLoadError,
    clear_pattern_cache,
    compile_pattern,
    get_bloat_extensions,
    get_password_field_patterns,
    get_session_cookie_patterns,
    load_allowlist,
    load_capture_settings,
    load_pii_patterns,
    load_sensitive_patterns,
)
from har_capture.patterns.redaction import (
    MAC_RE,
    URL_VALUED_HEADERS,
    QueryCredential,
    QueryPayload,
    classify_identity_field,
    decode_base64_payload,
    decode_transport_body,
    find_query_credential,
    find_query_payload,
    is_allowlisted,
    is_base64_credential,
    is_base64_decodable_text,
    is_blank_query_value,
    is_constant_mac,
    is_cookie_attribute_metadata,
    is_cookie_attribute_name,
    is_fully_redacted,
    is_mac_value,
    is_redacted,
    is_text_mime,
    iter_url_credentials,
    mac_layout,
    mime_kind,
    parse_json_container,
    query_param_segment,
    split_url_query,
    url_query,
)

__all__ = [
    # Pattern loading
    "load_pii_patterns",
    "load_sensitive_patterns",
    "load_allowlist",
    "load_capture_settings",
    "get_bloat_extensions",
    "get_password_field_patterns",
    "get_session_cookie_patterns",
    "clear_pattern_cache",
    "compile_pattern",
    "PatternLoadError",
    # Redaction checking and shared detection primitives
    "MAC_RE",
    "QueryCredential",
    "QueryPayload",
    "classify_identity_field",
    "decode_base64_payload",
    "decode_transport_body",
    "find_query_credential",
    "find_query_payload",
    "is_allowlisted",
    "is_blank_query_value",
    "is_constant_mac",
    "is_base64_credential",
    "is_base64_decodable_text",
    "is_cookie_attribute_metadata",
    "is_cookie_attribute_name",
    "is_fully_redacted",
    "is_mac_value",
    "is_redacted",
    "is_text_mime",
    "iter_url_credentials",
    "mac_layout",
    "mime_kind",
    "parse_json_container",
    "query_param_segment",
    "split_url_query",
    "url_query",
    "URL_VALUED_HEADERS",
    # Hashing
    "Hasher",
]
