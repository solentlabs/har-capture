"""HAR capture and PII sanitization library.

This library provides tools for:
- Capturing HTTP traffic as HAR files using Playwright
- Sanitizing HAR and HTML files to remove PII
- Validating HAR files for PII leaks before committing

Core sanitization has ZERO dependencies (only stdlib).
Optional features require: playwright (capture), typer (cli).

Example usage:
    from har_capture.sanitization import sanitize_html, sanitize_har

    # Sanitize HTML
    clean_html = sanitize_html(raw_html)

    # Sanitize HAR
    clean_har = sanitize_har(har_data)

    # Validate HAR for PII leaks
    from har_capture.validation import validate_har
    findings = validate_har("device.har")
"""

from __future__ import annotations

__version__ = "0.2.0"

# Re-export public API for convenience
from har_capture.sanitization import (
    check_for_pii,
    sanitize_har,
    sanitize_har_file,
    sanitize_html,
)

__all__ = [
    "__version__",
    "check_for_pii",
    "sanitize_har",
    "sanitize_har_file",
    "sanitize_html",
]
