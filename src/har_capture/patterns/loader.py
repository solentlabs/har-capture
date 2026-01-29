"""Pattern loading utilities for sanitization.

This module provides functions to load PII patterns, sensitive fields,
allowlists, and capture settings from JSON files.
"""

from __future__ import annotations

import json
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Maximum number of cache entries to prevent unbounded growth
_MAX_CACHE_SIZE = 20

# LRU cache for loaded patterns (OrderedDict for LRU behavior)
_pattern_cache: OrderedDict[str, Any] = OrderedDict()


def _cache_get(key: str) -> Any | None:
    """Get value from cache, moving it to end (most recently used)."""
    if key in _pattern_cache:
        _pattern_cache.move_to_end(key)
        return _pattern_cache[key]
    return None


def _cache_set(key: str, value: Any) -> None:
    """Set value in cache with LRU eviction."""
    if key in _pattern_cache:
        _pattern_cache.move_to_end(key)
    _pattern_cache[key] = value
    # Evict oldest entries if cache is full
    while len(_pattern_cache) > _MAX_CACHE_SIZE:
        evicted_key = next(iter(_pattern_cache))
        _pattern_cache.pop(evicted_key)
        _LOGGER.debug("Pattern cache evicted: %s", evicted_key)


class PatternLoadError(Exception):
    """Raised when pattern files cannot be loaded."""


def _get_builtin_path(filename: str) -> Path:
    """Get path to a built-in pattern file.

    Args:
        filename: Name of the pattern file (e.g., "pii.json")

    Returns:
        Path to the built-in pattern file
    """
    return Path(__file__).parent / filename


def _normalize_path(path: Path | str | None) -> str | None:
    """Normalize a path to a string for cache key consistency.

    Args:
        path: Path object, string, or None

    Returns:
        Absolute path string or None
    """
    if path is None:
        return None
    return str(Path(path).resolve())


def load_json_file(path: Path | str) -> dict[str, Any]:
    """Load a JSON file with error handling.

    Args:
        path: Path to the JSON file

    Returns:
        Parsed JSON data

    Raises:
        PatternLoadError: If file cannot be read or parsed
    """
    path_str = str(path)
    try:
        with open(path, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
            return data
    except FileNotFoundError as e:
        raise PatternLoadError(f"Pattern file not found: {path_str}") from e
    except PermissionError as e:
        raise PatternLoadError(f"Permission denied reading pattern file: {path_str}") from e
    except json.JSONDecodeError as e:
        raise PatternLoadError(f"Invalid JSON in pattern file {path_str}: {e}") from e


def load_pii_patterns(custom_path: Path | str | None = None) -> dict[str, Any]:
    """Load PII detection patterns.

    Args:
        custom_path: Optional path to custom patterns file to merge

    Returns:
        Dict with 'patterns' and 'preserved_gateway_ips' keys

    Raises:
        PatternLoadError: If custom patterns file cannot be loaded
    """
    normalized = _normalize_path(custom_path)
    cache_key = f"pii:{normalized}"
    cached = _cache_get(cache_key)
    if cached is not None:
        result: dict[str, Any] = cached
        return result

    # Load built-in patterns
    builtin = load_json_file(_get_builtin_path("pii.json"))

    # Merge custom patterns if provided
    if custom_path:
        custom = load_json_file(custom_path)
        if "patterns" in custom and isinstance(custom["patterns"], dict):
            builtin["patterns"].update(custom["patterns"])
        if "preserved_gateway_ips" in custom and isinstance(custom["preserved_gateway_ips"], list):
            builtin["preserved_gateway_ips"].extend(custom["preserved_gateway_ips"])

    _cache_set(cache_key, builtin)
    return builtin


def load_sensitive_patterns(custom_path: Path | str | None = None) -> dict[str, Any]:
    """Load sensitive field and header patterns.

    Args:
        custom_path: Optional path to custom patterns file to merge

    Returns:
        Dict with 'headers', 'fields', and 'tagValueList' keys

    Raises:
        PatternLoadError: If custom patterns file cannot be loaded
    """
    normalized = _normalize_path(custom_path)
    cache_key = f"sensitive:{normalized}"
    cached = _cache_get(cache_key)
    if cached is not None:
        result: dict[str, Any] = cached
        return result

    builtin = load_json_file(_get_builtin_path("sensitive.json"))

    if custom_path:
        custom = load_json_file(custom_path)
        if "headers" in custom:
            if "full_redact" in custom["headers"]:
                builtin["headers"]["full_redact"].extend(custom["headers"]["full_redact"])
            if "cookie_redact" in custom["headers"]:
                builtin["headers"]["cookie_redact"].extend(custom["headers"]["cookie_redact"])
        if "fields" in custom and "patterns" in custom["fields"]:
            builtin["fields"]["patterns"].extend(custom["fields"]["patterns"])
        if "tagValueList" in custom and "safe_values" in custom["tagValueList"]:
            builtin["tagValueList"]["safe_values"].extend(custom["tagValueList"]["safe_values"])

    _cache_set(cache_key, builtin)
    return builtin


def load_capture_settings(custom_path: Path | str | None = None) -> dict[str, Any]:
    """Load capture settings (bloat extensions, etc.).

    Args:
        custom_path: Optional path to custom settings file to merge

    Returns:
        Dict with 'bloat_extensions' categories

    Raises:
        PatternLoadError: If custom settings file cannot be loaded
    """
    normalized = _normalize_path(custom_path)
    cache_key = f"capture:{normalized}"
    cached = _cache_get(cache_key)
    if cached is not None:
        result: dict[str, Any] = cached
        return result

    builtin = load_json_file(_get_builtin_path("capture.json"))

    if custom_path:
        custom = load_json_file(custom_path)
        if "bloat_extensions" in custom:
            for category, extensions in custom["bloat_extensions"].items():
                if category.startswith("_"):
                    continue
                if category in builtin["bloat_extensions"]:
                    builtin["bloat_extensions"][category].extend(extensions)
                else:
                    builtin["bloat_extensions"][category] = extensions

    _cache_set(cache_key, builtin)
    return builtin


def get_bloat_extensions(
    include_fonts: bool = False,
    include_images: bool = False,
    include_media: bool = False,
    custom_path: Path | str | None = None,
) -> set[str]:
    """Get the set of bloat file extensions to filter.

    Args:
        include_fonts: If True, don't filter font files
        include_images: If True, don't filter image files
        include_media: If True, don't filter media files
        custom_path: Optional path to custom capture settings

    Returns:
        Set of file extensions to filter (e.g., {".woff", ".png", ...})
    """
    settings = load_capture_settings(custom_path)
    bloat = settings.get("bloat_extensions", {})

    extensions: set[str] = set()

    for category, exts in bloat.items():
        if category.startswith("_"):
            continue
        # Skip categories that user wants to include
        if category == "fonts" and include_fonts:
            continue
        if category == "images" and include_images:
            continue
        if category == "media" and include_media:
            continue
        extensions.update(exts)

    return extensions


def load_allowlist(custom_path: Path | str | None = None) -> dict[str, Any]:
    """Load allowlist of safe placeholder values.

    Args:
        custom_path: Optional path to custom allowlist file to merge

    Returns:
        Dict with 'static_placeholders', 'format_preserving_patterns', and 'hash_prefixes' keys

    Raises:
        PatternLoadError: If custom allowlist file cannot be loaded
    """
    normalized = _normalize_path(custom_path)
    cache_key = f"allowlist:{normalized}"
    cached = _cache_get(cache_key)
    if cached is not None:
        result: dict[str, Any] = cached
        return result

    builtin = load_json_file(_get_builtin_path("allowlist.json"))

    if custom_path:
        custom = load_json_file(custom_path)
        if "static_placeholders" in custom and "values" in custom["static_placeholders"]:
            builtin["static_placeholders"]["values"].extend(custom["static_placeholders"]["values"])
        if "hash_prefixes" in custom and "values" in custom["hash_prefixes"]:
            builtin["hash_prefixes"]["values"].extend(custom["hash_prefixes"]["values"])
        # format_preserving_patterns can be extended by adding new keys
        if "format_preserving_patterns" in custom:
            for key, pattern in custom["format_preserving_patterns"].items():
                if not key.startswith("_"):
                    builtin["format_preserving_patterns"][key] = pattern

    _cache_set(cache_key, builtin)
    return builtin


def clear_pattern_cache() -> None:
    """Clear the pattern cache.

    Useful for testing or when patterns have been modified.
    """
    _pattern_cache.clear()


def compile_pattern(pattern_def: dict[str, Any]) -> re.Pattern[str]:
    """Compile a pattern definition into a regex.

    Args:
        pattern_def: Pattern definition with 'regex' and optional 'flags'

    Returns:
        Compiled regex pattern

    Raises:
        re.error: If regex pattern is invalid
    """
    regex = pattern_def["regex"]
    flags = 0

    if "flags" in pattern_def:
        for flag_name in pattern_def["flags"]:
            # Support all standard regex flags dynamically
            flag = getattr(re, flag_name, None)
            if flag is not None and isinstance(flag, re.RegexFlag):
                flags |= flag
            else:
                _LOGGER.warning("Unknown regex flag: %s", flag_name)

    return re.compile(regex, flags)


def is_allowlisted(value: str, allowlist: dict[str, Any] | None = None) -> bool:
    """Check if a value is in the allowlist.

    Args:
        value: Value to check
        allowlist: Allowlist data (loads default if None)

    Returns:
        True if the value should be ignored
    """
    if allowlist is None:
        allowlist = load_allowlist()

    # Check static placeholders (exact matches)
    static = allowlist.get("static_placeholders", {})
    if value in static.get("values", []):
        return True

    # Check hash prefixes (for values like SERIAL_a1b2c3d4)
    prefixes = allowlist.get("hash_prefixes", {})
    for prefix in prefixes.get("values", []):
        if value.startswith(prefix):
            return True

    # Check format-preserving patterns (MAC, IP, email in reserved ranges)
    for pattern_def in allowlist.get("format_preserving_patterns", {}).values():
        if isinstance(pattern_def, dict) and "pattern" in pattern_def:
            if re.search(pattern_def["pattern"], value, re.IGNORECASE):
                return True

    return False
