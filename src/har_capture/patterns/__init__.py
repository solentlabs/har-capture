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
    is_allowlisted,
    load_allowlist,
    load_capture_settings,
    load_pii_patterns,
    load_sensitive_patterns,
)

__all__ = [
    # Pattern loading
    "load_pii_patterns",
    "load_sensitive_patterns",
    "load_allowlist",
    "load_capture_settings",
    "get_bloat_extensions",
    "clear_pattern_cache",
    "compile_pattern",
    "is_allowlisted",
    "PatternLoadError",
    # Hashing
    "Hasher",
]
