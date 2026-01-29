"""HAR file sanitization utilities.

This module provides functions to sanitize HAR (HTTP Archive) files by removing
sensitive information while preserving the structure needed for debugging device
authentication and parsing issues.

Reuses PII patterns from html.py for consistency.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from har_capture.patterns import Hasher, load_sensitive_patterns
from har_capture.sanitization.html import sanitize_html

if TYPE_CHECKING:
    from pathlib import Path

_LOGGER = logging.getLogger(__name__)

# Maximum recursion depth for JSON sanitization to prevent stack overflow
_MAX_RECURSION_DEPTH = 50

# Default maximum HAR file size (100 MB)
DEFAULT_MAX_HAR_SIZE = 100 * 1024 * 1024


class HarSizeError(ValueError):
    """Raised when HAR file exceeds size limit."""

    def __init__(self, size: int, max_size: int) -> None:
        self.size = size
        self.max_size = max_size
        super().__init__(
            f"HAR file size ({size:,} bytes) exceeds limit ({max_size:,} bytes). "
            f"Use max_size parameter to increase or set to None to disable."
        )


class HarValidationError(ValueError):
    """Raised when HAR structure is invalid."""

    def __init__(self, message: str, path: str = "") -> None:
        self.path = path
        full_message = f"Invalid HAR structure: {message}"
        if path:
            full_message += f" (at {path})"
        super().__init__(full_message)


def validate_har_structure(har_data: dict[str, Any], *, strict: bool = False) -> list[str]:
    """Validate HAR structure against HAR 1.2 spec.

    Args:
        har_data: Parsed HAR data
        strict: If True, require all HAR 1.2 fields. If False, only require minimal structure.

    Returns:
        List of validation warnings (empty if valid)

    Raises:
        HarValidationError: If structure is fundamentally invalid (missing log or entries)

    Example:
        >>> warnings = validate_har_structure({"log": {"entries": []}})
        >>> # warnings may contain "Missing log.version", "Missing log.creator", etc.
    """
    warnings: list[str] = []

    # Required: root must have "log" key
    if "log" not in har_data:
        raise HarValidationError("Missing required 'log' key", "root")

    log = har_data["log"]
    if not isinstance(log, dict):
        raise HarValidationError("'log' must be an object", "log")

    # Required: log must have "entries" array
    if "entries" not in log:
        raise HarValidationError("Missing required 'entries' key", "log")

    entries = log["entries"]
    if not isinstance(entries, list):
        raise HarValidationError("'entries' must be an array", "log.entries")

    # Recommended fields (warnings only)
    if "version" not in log:
        warnings.append("Missing log.version (recommended)")
    if "creator" not in log:
        warnings.append("Missing log.creator (recommended)")

    if strict:
        # Strict mode: validate each entry
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                warnings.append(f"Entry {i} is not an object")
                continue

            if "request" not in entry:
                warnings.append(f"Entry {i} missing 'request'")
            elif isinstance(entry["request"], dict):
                req = entry["request"]
                if "method" not in req:
                    warnings.append(f"Entry {i} request missing 'method'")
                if "url" not in req:
                    warnings.append(f"Entry {i} request missing 'url'")

            if "response" not in entry:
                warnings.append(f"Entry {i} missing 'response'")
            elif isinstance(entry["response"], dict):
                resp = entry["response"]
                if "status" not in resp:
                    warnings.append(f"Entry {i} response missing 'status'")

    return warnings


def _load_sensitive_headers() -> tuple[set[str], set[str]]:
    """Load sensitive header names from patterns.

    Returns:
        Tuple of (full_redact_headers, cookie_redact_headers)
    """
    sensitive = load_sensitive_patterns()
    headers = sensitive.get("headers", {})
    full_redact = set(h.lower() for h in headers.get("full_redact", []))
    cookie_redact = set(h.lower() for h in headers.get("cookie_redact", []))
    return full_redact, cookie_redact


def _load_sensitive_field_patterns() -> re.Pattern[str]:
    """Load sensitive field patterns from patterns file.

    Returns:
        Compiled regex pattern for matching sensitive field names
    """
    sensitive = load_sensitive_patterns()
    patterns = sensitive.get("fields", {}).get("patterns", [])
    if not patterns:
        patterns = ["password", "secret", "token", "key", "auth"]
    # Escape patterns to prevent regex injection
    escaped = [re.escape(p) for p in patterns]
    return re.compile("|".join(escaped), re.IGNORECASE)


# Load patterns at module level for efficiency
_FULL_REDACT_HEADERS, _COOKIE_REDACT_HEADERS = _load_sensitive_headers()
_SENSITIVE_FIELD_RE = _load_sensitive_field_patterns()


def is_sensitive_field(field_name: str) -> bool:
    """Check if a form field name is sensitive.

    Args:
        field_name: Name of the form field

    Returns:
        True if the field likely contains sensitive data

    Example:
        >>> is_sensitive_field("loginPassword")
        True
        >>> is_sensitive_field("username")
        False
    """
    return bool(_SENSITIVE_FIELD_RE.search(field_name))


def sanitize_header_value(
    name: str,
    value: str,
    hasher: Hasher | None = None,
) -> str:
    """Sanitize a header value if it's sensitive.

    Args:
        name: Header name
        value: Header value
        hasher: Optional hasher for correlation-preserving redaction

    Returns:
        Sanitized value or original if not sensitive

    Example:
        >>> sanitize_header_value("Authorization", "Bearer abc123")
        '[REDACTED]'
        >>> sanitize_header_value("Content-Type", "text/html")
        'text/html'
    """
    name_lower = name.lower()

    if name_lower in _FULL_REDACT_HEADERS:
        if hasher:
            return hasher.hash_generic(value, "AUTH")
        return "[REDACTED]"

    if name_lower in _COOKIE_REDACT_HEADERS:
        # Preserve cookie names, redact values
        def redact_cookie(match: re.Match[str]) -> str:
            cookie_name = match.group(1)
            cookie_value = match.group(2)
            if hasher:
                hashed = hasher.hash_generic(cookie_value, "COOKIE")
                return f"{cookie_name}={hashed}"
            return f"{cookie_name}=[REDACTED]"

        return re.sub(r"([^=;\s]+)=([^;]*)", redact_cookie, value)

    return value


def _sanitize_form_urlencoded(text: str, hasher: Hasher | None = None) -> str:
    """Sanitize form-urlencoded text by redacting sensitive fields.

    Args:
        text: Form-urlencoded text to sanitize
        hasher: Optional hasher for correlation-preserving redaction

    Returns:
        Sanitized text with sensitive field values redacted
    """
    pairs = []
    for pair in text.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            if is_sensitive_field(key):
                if hasher:
                    value = hasher.hash_generic(value, "FIELD")
                else:
                    value = "[REDACTED]"
            pairs.append(f"{key}={value}")
        else:
            pairs.append(pair)
    return "&".join(pairs)


def _sanitize_json_text(text: str, hasher: Hasher | None = None) -> str:
    """Sanitize JSON text by redacting sensitive fields.

    Args:
        text: JSON text to sanitize
        hasher: Optional hasher for correlation-preserving redaction

    Returns:
        Sanitized JSON text with sensitive field values redacted
    """
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in data:
                if is_sensitive_field(key) and isinstance(data[key], str):
                    if hasher:
                        data[key] = hasher.hash_generic(data[key], "FIELD")
                    else:
                        data[key] = "[REDACTED]"
        return json.dumps(data)
    except json.JSONDecodeError:
        return text


def sanitize_post_data(
    post_data: dict[str, Any] | None,
    hasher: Hasher | None = None,
) -> dict[str, Any] | None:
    """Sanitize POST data while preserving field names.

    Args:
        post_data: HAR postData object
        hasher: Optional hasher for correlation-preserving redaction

    Returns:
        Sanitized postData object
    """
    if not post_data:
        return post_data

    result = copy.deepcopy(post_data)

    # Sanitize params array
    if "params" in result and isinstance(result["params"], list):
        for param in result["params"]:
            if isinstance(param, dict) and "name" in param and is_sensitive_field(param["name"]):
                if hasher:
                    param["value"] = hasher.hash_generic(param.get("value", ""), "FIELD")
                else:
                    param["value"] = "[REDACTED]"

    # Sanitize raw text (form-urlencoded or JSON)
    if result.get("text"):
        text = result["text"]
        mime_type = result.get("mimeType", "")

        if "application/x-www-form-urlencoded" in mime_type:
            result["text"] = _sanitize_form_urlencoded(text, hasher)
        elif "application/json" in mime_type:
            result["text"] = _sanitize_json_text(text, hasher)

    return result


def _sanitize_json_recursive(data: Any, hasher: Hasher | None = None, _depth: int = 0) -> Any:
    """Recursively sanitize JSON data.

    Args:
        data: JSON data (dict, list, or primitive)
        hasher: Optional hasher for correlation-preserving redaction
        _depth: Current recursion depth (internal use)

    Returns:
        Sanitized data
    """
    if _depth > _MAX_RECURSION_DEPTH:
        _LOGGER.warning("Max recursion depth exceeded in JSON sanitization")
        return data

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if is_sensitive_field(key) and isinstance(value, str):
                if hasher:
                    result[key] = hasher.hash_generic(value, "FIELD")
                else:
                    result[key] = "[REDACTED]"
            else:
                result[key] = _sanitize_json_recursive(value, hasher, _depth + 1)
        return result
    if isinstance(data, list):
        return [_sanitize_json_recursive(item, hasher, _depth + 1) for item in data]
    return data


def _sanitize_headers(headers: list[dict[str, Any]], hasher: Hasher | None = None) -> None:
    """Sanitize a list of headers in-place.

    Args:
        headers: List of header dicts with 'name' and 'value' keys
        hasher: Optional hasher for correlation-preserving redaction
    """
    for header in headers:
        if isinstance(header, dict) and "name" in header and "value" in header:
            header["value"] = sanitize_header_value(header["name"], header["value"], hasher)


def _sanitize_request(req: dict[str, Any], hasher: Hasher | None = None) -> None:
    """Sanitize a HAR request object in-place.

    Args:
        req: HAR request object containing headers, postData, and queryString
        hasher: Optional hasher for correlation-preserving redaction
    """
    # Sanitize headers
    if "headers" in req and isinstance(req["headers"], list):
        _sanitize_headers(req["headers"], hasher)

    # Sanitize POST data
    if "postData" in req:
        req["postData"] = sanitize_post_data(req["postData"], hasher)

    # Sanitize query string params (in case password is in URL)
    if "queryString" in req and isinstance(req["queryString"], list):
        for param in req["queryString"]:
            if isinstance(param, dict) and "name" in param and is_sensitive_field(param["name"]):
                if hasher:
                    param["value"] = hasher.hash_generic(param.get("value", ""), "FIELD")
                else:
                    param["value"] = "[REDACTED]"


def _sanitize_response_content(
    content: dict[str, Any],
    salt: str | None = "auto",
    custom_patterns: str | None = None,
) -> None:
    """Sanitize response content in-place.

    Args:
        content: HAR response content object with 'text' and 'mimeType' keys
        salt: Salt for hashed redaction
        custom_patterns: Optional path to custom patterns file
    """
    if "text" not in content or not content["text"]:
        return

    mime_type = content.get("mimeType", "")

    if "text/html" in mime_type or "text/xml" in mime_type:
        content["text"] = sanitize_html(content["text"], salt=salt, custom_patterns=custom_patterns)
    elif "application/json" in mime_type:
        hasher = Hasher.create(salt) if salt else None
        try:
            data = json.loads(content["text"])
            content["text"] = json.dumps(_sanitize_json_recursive(data, hasher))
        except json.JSONDecodeError:
            _LOGGER.warning("Invalid JSON in response content, skipping sanitization")


def _sanitize_response(
    resp: dict[str, Any],
    hasher: Hasher | None = None,
    salt: str | None = "auto",
    custom_patterns: str | None = None,
) -> None:
    """Sanitize a HAR response object in-place.

    Args:
        resp: HAR response object containing headers and content
        hasher: Optional hasher for header redaction
        salt: Salt for content sanitization
        custom_patterns: Optional path to custom patterns file
    """
    # Sanitize headers
    if "headers" in resp and isinstance(resp["headers"], list):
        _sanitize_headers(resp["headers"], hasher)

    # Sanitize response content
    if "content" in resp and isinstance(resp["content"], dict):
        _sanitize_response_content(resp["content"], salt, custom_patterns)


def sanitize_entry(
    entry: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | None = None,
) -> dict[str, Any]:
    """Sanitize a single HAR entry (request/response pair).

    Args:
        entry: HAR entry object
        salt: Salt for hashed redaction
        custom_patterns: Optional path to custom patterns file

    Returns:
        Sanitized entry
    """
    result = copy.deepcopy(entry)
    hasher = Hasher.create(salt) if salt else None

    if "request" in result:
        _sanitize_request(result["request"], hasher)

    if "response" in result:
        _sanitize_response(result["response"], hasher, salt, custom_patterns)

    return result


def sanitize_har(
    har_data: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | None = None,
) -> dict[str, Any]:
    """Sanitize an entire HAR file.

    Args:
        har_data: Parsed HAR JSON data
        salt: Salt for hashed redaction. Options:
            - "auto" (default): Random salt, correlates within this call
            - None: Static placeholders (legacy behavior)
            - Any string: Consistent hashing across calls with same salt
        custom_patterns: Optional path to custom patterns JSON file

    Returns:
        Sanitized HAR data

    Example:
        >>> import json
        >>> har = {"log": {"entries": []}}
        >>> sanitized = sanitize_har(har)
        >>> "log" in sanitized
        True
    """
    result = copy.deepcopy(har_data)

    if "log" not in result:
        _LOGGER.warning("HAR data missing 'log' key")
        return result

    log = result["log"]

    # Sanitize all entries
    if "entries" in log and isinstance(log["entries"], list):
        log["entries"] = [
            sanitize_entry(entry, salt=salt, custom_patterns=custom_patterns) for entry in log["entries"]
        ]

    # Sanitize pages (if present)
    if "pages" in log and isinstance(log["pages"], list):
        for page in log["pages"]:
            if isinstance(page, dict) and "title" in page:
                page["title"] = sanitize_html(page["title"], salt=salt, custom_patterns=custom_patterns)

    return result


def sanitize_har_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    salt: str | None = "auto",
    custom_patterns: str | None = None,
    max_size: int | None = DEFAULT_MAX_HAR_SIZE,
    validate: bool = True,
) -> str:
    """Sanitize a HAR file and write to a new file.

    Args:
        input_path: Path to input HAR file
        output_path: Path to output file (default: input_path with .sanitized.har suffix)
        salt: Salt for hashed redaction
        custom_patterns: Optional path to custom patterns JSON file
        max_size: Maximum file size in bytes (default: 100MB). Set to None to disable.
        validate: If True, validate HAR structure before processing (default: True)

    Returns:
        Path to the sanitized file

    Raises:
        HarSizeError: If file exceeds max_size limit
        HarValidationError: If HAR structure is invalid (when validate=True)
        FileNotFoundError: If input file doesn't exist
        json.JSONDecodeError: If file is not valid JSON

    Example:
        >>> # sanitize_har_file("device.har")  # Creates device.sanitized.har
        >>> # sanitize_har_file("device.har", "clean.har")  # Creates clean.har
        >>> # sanitize_har_file("large.har", max_size=None)  # No size limit
        >>> # sanitize_har_file("file.har", validate=False)  # Skip validation
    """
    from pathlib import Path as PathlibPath

    input_path = PathlibPath(input_path)
    input_str = str(input_path)

    # Check file size before reading
    if max_size is not None:
        file_size = input_path.stat().st_size
        if file_size > max_size:
            raise HarSizeError(file_size, max_size)

    if output_path is None:
        if input_str.endswith(".har"):
            output_str = input_str[:-4] + ".sanitized.har"
        else:
            output_str = input_str + ".sanitized.har"
    else:
        output_str = str(output_path)

    with open(input_str, encoding="utf-8") as f:
        har_data = json.load(f)

    # Validate HAR structure
    if validate:
        warnings = validate_har_structure(har_data)
        for warning in warnings:
            _LOGGER.warning("HAR validation: %s", warning)

    sanitized = sanitize_har(har_data, salt=salt, custom_patterns=custom_patterns)

    with open(output_str, "w", encoding="utf-8") as f:
        json.dump(sanitized, f, indent=2)

    _LOGGER.info("Sanitized HAR written to: %s", output_str)
    return output_str


# Legacy exports for backwards compatibility
SENSITIVE_HEADERS: set[str] = _FULL_REDACT_HEADERS | _COOKIE_REDACT_HEADERS
SENSITIVE_FIELD_PATTERNS: list[str] = load_sensitive_patterns().get("fields", {}).get("patterns", [])
