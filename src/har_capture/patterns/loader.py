"""Pattern loading utilities for sanitization.

This module provides functions to load PII patterns, sensitive fields,
allowlists, and capture settings from JSON files.
"""

from __future__ import annotations

import json
import logging
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from fnmatch import fnmatch
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


@dataclass(frozen=True)
class CompiledDetector:
    """A compiled heuristic detector loaded from a domain JSON file.

    Each detector checks values against length bounds, letter requirements,
    regex patterns, and optional CamelCase matching. The category and
    confidence are declared in the domain file.
    """

    category: str
    confidence: str  # "low", "medium", "high"
    min_length: int
    max_length: int
    requires_letter: bool
    patterns: list[tuple[re.Pattern[str], str]] = field(default_factory=list)
    camelcase: bool = False


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


def _load_custom_patterns(custom: Path | str | dict[str, Any]) -> dict[str, Any]:
    """Load custom patterns from file path or dict.

    Args:
        custom: Either a file path (Path/str) or pattern dict

    Returns:
        Pattern data as dict

    Raises:
        PatternLoadError: If file cannot be loaded
    """
    if isinstance(custom, dict):
        return custom
    return load_json_file(custom)


def _apply_pattern_inclusions(patterns: dict[str, Any], inclusions: list[str]) -> None:
    """Keep only patterns whose names match an entry in the inclusion list.

    Supports exact names (``"mac_address"``) and glob wildcards
    (``"credit_card_*"``).  Modifies *patterns* in place.

    Args:
        patterns: The ``patterns`` dict (pattern_name → definition).
        inclusions: List of pattern names or glob expressions to keep.
    """
    exact = {e for e in inclusions if "*" not in e}
    globs = [e for e in inclusions if "*" in e]

    to_remove = [name for name in patterns if name not in exact and not any(fnmatch(name, g) for g in globs)]
    for name in to_remove:
        del patterns[name]


def load_pii_patterns(custom_path: Path | str | dict[str, Any] | None = None) -> dict[str, Any]:
    """Load PII detection patterns.

    Args:
        custom_path: Optional custom patterns to merge. Can be:
            - Path/str: Path to JSON file
            - dict: Pattern definitions directly (e.g., from modem.yaml)
            - None: Use built-in patterns only

    Returns:
        Dict with 'patterns' and 'preserved_gateway_ips' keys

    Raises:
        PatternLoadError: If custom patterns file cannot be loaded
    """
    # Only cache file-based patterns (dicts are ephemeral)
    if isinstance(custom_path, dict):
        cache_key = None
    else:
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
        custom = _load_custom_patterns(custom_path)
        if "patterns" in custom and isinstance(custom["patterns"], dict):
            builtin["patterns"].update(custom["patterns"])
        if "preserved_gateway_ips" in custom and isinstance(custom["preserved_gateway_ips"], list):
            builtin["preserved_gateway_ips"].extend(custom["preserved_gateway_ips"])
        # Apply inclusions declared by the domain/custom file
        if "include_patterns" in custom and isinstance(custom["include_patterns"], list):
            _apply_pattern_inclusions(builtin["patterns"], custom["include_patterns"])

    if cache_key:
        _cache_set(cache_key, builtin)
    return builtin


def load_sensitive_patterns(custom_path: Path | str | dict[str, Any] | None = None) -> dict[str, Any]:
    """Load sensitive field and header patterns.

    Args:
        custom_path: Optional custom patterns to merge. Can be:
            - Path/str: Path to JSON file
            - dict: Pattern definitions directly (e.g., from modem.yaml)
            - None: Use built-in patterns only

    Returns:
        Dict with 'headers', 'fields', and 'tagValueList' keys

    Raises:
        PatternLoadError: If custom patterns file cannot be loaded
    """
    if isinstance(custom_path, dict):
        cache_key = None
    else:
        normalized = _normalize_path(custom_path)
        cache_key = f"sensitive:{normalized}"
        cached = _cache_get(cache_key)
        if cached is not None:
            result: dict[str, Any] = cached
            return result

    builtin = load_json_file(_get_builtin_path("sensitive.json"))

    if custom_path:
        custom = _load_custom_patterns(custom_path)
        if "headers" in custom:
            if "full_redact" in custom["headers"]:
                builtin["headers"]["full_redact"].extend(custom["headers"]["full_redact"])
            if "cookie_redact" in custom["headers"]:
                builtin["headers"]["cookie_redact"].extend(custom["headers"]["cookie_redact"])
        if "fields" in custom and "patterns" in custom["fields"]:
            builtin["fields"]["patterns"].extend(custom["fields"]["patterns"])
        if "tagValueList" in custom and "safe_values" in custom["tagValueList"]:
            builtin["tagValueList"]["safe_values"].extend(custom["tagValueList"]["safe_values"])
        if "heuristics" in custom:
            builtin.setdefault("heuristics", {})
            if "safe_value_patterns" in custom["heuristics"]:
                builtin["heuristics"].setdefault("safe_value_patterns", [])
                builtin["heuristics"]["safe_value_patterns"].extend(
                    custom["heuristics"]["safe_value_patterns"]
                )
            if "detectors" in custom["heuristics"]:
                builtin["heuristics"].setdefault("detectors", [])
                builtin["heuristics"]["detectors"].extend(custom["heuristics"]["detectors"])

    if cache_key:
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


def load_allowlist(custom_path: Path | str | dict[str, Any] | None = None) -> dict[str, Any]:
    """Load allowlist of safe placeholder values.

    Args:
        custom_path: Optional custom allowlist to merge. Can be:
            - Path/str: Path to JSON file
            - dict: Allowlist definitions directly
            - None: Use built-in allowlist only

    Returns:
        Dict with 'static_placeholders', 'format_preserving_patterns', and 'hash_prefixes' keys

    Raises:
        PatternLoadError: If custom allowlist file cannot be loaded
    """
    if isinstance(custom_path, dict):
        cache_key = None
    else:
        normalized = _normalize_path(custom_path)
        cache_key = f"allowlist:{normalized}"
        cached = _cache_get(cache_key)
        if cached is not None:
            result: dict[str, Any] = cached
            return result

    builtin = load_json_file(_get_builtin_path("allowlist.json"))

    if custom_path:
        custom = _load_custom_patterns(custom_path)
        if "static_placeholders" in custom and "values" in custom["static_placeholders"]:
            builtin["static_placeholders"]["values"].extend(custom["static_placeholders"]["values"])
        if "hash_prefixes" in custom and "values" in custom["hash_prefixes"]:
            builtin["hash_prefixes"]["values"].extend(custom["hash_prefixes"]["values"])
        # format_preserving_patterns can be extended by adding new keys
        if "format_preserving_patterns" in custom:
            for key, pattern in custom["format_preserving_patterns"].items():
                if not key.startswith("_"):
                    builtin["format_preserving_patterns"][key] = pattern
        # redaction_patterns can be extended with additional patterns
        if "redaction_patterns" in custom and "values" in custom["redaction_patterns"]:
            if "redaction_patterns" not in builtin:
                builtin["redaction_patterns"] = {"values": []}
            builtin["redaction_patterns"]["values"].extend(custom["redaction_patterns"]["values"])

    if cache_key:
        _cache_set(cache_key, builtin)
    return builtin


def clear_pattern_cache() -> None:
    """Clear the pattern cache.

    Useful for testing or when patterns have been modified.
    """
    _pattern_cache.clear()


def _get_domains_dir() -> Path:
    """Get path to the built-in domains directory."""
    return Path(__file__).parent / "domains"


def resolve_patterns_arg(value: str) -> Path:
    """Resolve a --patterns argument to a file path.

    If the value contains path separators or ends with .json, it is treated
    as a file path. Otherwise, it is looked up as a built-in domain name
    (hyphens normalized to underscores).

    Args:
        value: Pattern name or file path (e.g., "network-device" or "./custom.json")

    Returns:
        Resolved Path to the pattern file

    Raises:
        PatternLoadError: If the pattern file cannot be found
    """
    # File path: contains separator or has .json extension
    if "/" in value or "\\" in value or value.endswith(".json"):
        path = Path(value)
        if not path.exists():
            raise PatternLoadError(f"Pattern file not found: {value}")
        return path

    # Built-in domain name: normalize hyphens to underscores
    name = value.replace("-", "_")
    path = _get_domains_dir() / f"{name}.json"
    if not path.exists():
        available = list_domains()
        names = [d["name"] for d in available]
        raise PatternLoadError(
            f"Unknown pattern domain '{value}'. Available: {', '.join(names) if names else '(none)'}"
        )
    return path


def list_domains() -> list[dict[str, str]]:
    """List available built-in domain pattern files.

    Returns:
        List of dicts with 'name', 'description', and 'path' keys
    """
    domains_dir = _get_domains_dir()
    if not domains_dir.exists():
        return []

    result = []
    for path in sorted(domains_dir.glob("*.json")):
        data = _try_load_domain(path)
        if data is not None:
            result.append(
                {
                    "name": path.stem.replace("_", "-"),
                    "description": data.get("_description", ""),
                    "path": str(path),
                }
            )
    return result


def _try_load_domain(path: Path) -> dict[str, Any] | None:
    """Load a domain JSON file, returning None on failure."""
    try:
        return load_json_file(path)
    except PatternLoadError:
        _LOGGER.warning("Skipping invalid domain file: %s", path)
        return None


def compile_safe_value_patterns(
    sensitive_data: dict[str, Any],
) -> list[re.Pattern[str]]:
    """Compile heuristic safe-value patterns from loaded sensitive data.

    Args:
        sensitive_data: Loaded sensitive patterns (from load_sensitive_patterns)

    Returns:
        List of compiled regex patterns for safe value detection
    """
    patterns: list[re.Pattern[str]] = []
    for pdef in sensitive_data.get("heuristics", {}).get("safe_value_patterns", []):
        compiled = compile_pattern(pdef)
        if compiled is not None:
            patterns.append(compiled)
    return patterns


def compile_detectors(
    sensitive_data: dict[str, Any],
) -> list[CompiledDetector]:
    """Compile heuristic detectors from loaded sensitive data.

    Args:
        sensitive_data: Loaded sensitive patterns (from load_sensitive_patterns)

    Returns:
        List of compiled detectors. Empty if no detectors are defined.
    """
    detectors: list[CompiledDetector] = []
    for ddef in sensitive_data.get("heuristics", {}).get("detectors", []):
        compiled_patterns: list[tuple[re.Pattern[str], str]] = []
        for pdef in ddef.get("patterns", []):
            regex_str = pdef.get("regex")
            if not regex_str:
                continue
            reason = pdef.get("reason", "")
            flags = 0
            for flag_name in pdef.get("flags", []):
                flag = getattr(re, flag_name, None)
                if flag is not None and isinstance(flag, re.RegexFlag):
                    flags |= flag
            try:
                compiled_patterns.append((re.compile(regex_str, flags), reason))
            except re.error:
                _LOGGER.warning(
                    "Skipping invalid detector pattern in '%s': %s",
                    ddef.get("category", "unknown"),
                    regex_str,
                )

        detectors.append(
            CompiledDetector(
                category=ddef.get("category", "unknown"),
                confidence=ddef.get("confidence", "medium"),
                min_length=ddef.get("min_length", 1),
                max_length=ddef.get("max_length", 256),
                requires_letter=ddef.get("requires_letter", False),
                patterns=compiled_patterns,
                camelcase=ddef.get("camelcase", False),
            )
        )
    return detectors


def merge_pattern_files(paths: list[Path]) -> dict[str, Any]:
    """Load and merge multiple pattern files into a single dict.

    Merging follows the same extend-lists/update-dicts convention used
    throughout the loader. Later files take precedence.

    Args:
        paths: Ordered list of pattern file paths to merge

    Returns:
        Merged pattern data suitable for passing as custom_patterns dict
    """
    if not paths:
        return {}

    merged = load_json_file(paths[0])
    for path in paths[1:]:
        extra = load_json_file(path)
        # Merge each known section
        for section in ("headers", "fields", "tagValueList", "heuristics", "patterns"):
            if section not in extra:
                continue
            if section not in merged:
                merged[section] = extra[section]
                continue
            # Merge sub-keys: extend lists, update dicts
            for key, val in extra[section].items():
                if key.startswith("_"):
                    continue
                if key not in merged[section]:
                    merged[section][key] = val
                elif isinstance(val, list) and isinstance(merged[section][key], list):
                    merged[section][key].extend(val)
                elif isinstance(val, dict) and isinstance(merged[section][key], dict):
                    merged[section][key].update(val)
                else:
                    merged[section][key] = val
        # Accumulate include_patterns across files (list extend)
        if "include_patterns" in extra and isinstance(extra["include_patterns"], list):
            merged.setdefault("include_patterns", [])
            merged["include_patterns"].extend(extra["include_patterns"])
    return merged


def compile_pattern(pattern_def: dict[str, Any]) -> re.Pattern[str] | None:
    """Compile a pattern definition into a regex.

    Args:
        pattern_def: Pattern definition with 'regex' and optional 'flags'

    Returns:
        Compiled regex pattern, or None if the regex is invalid
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

    try:
        return re.compile(regex, flags)
    except re.error:
        pattern_name = pattern_def.get("replacement_prefix", "unknown")
        _LOGGER.warning("Skipping invalid regex in pattern '%s'", pattern_name)
        return None
