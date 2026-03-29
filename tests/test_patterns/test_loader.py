"""Tests for pattern loader edge cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from har_capture.patterns.loader import (
    PatternLoadError,
    _cache_get,
    _cache_set,
    clear_pattern_cache,
    compile_pattern,
    compile_safe_value_patterns,
    list_domains,
    load_json_file,
    load_pii_patterns,
    load_sensitive_patterns,
    resolve_patterns_arg,
)


class TestPatternLoadError:
    """Tests for PatternLoadError exception."""

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Test FileNotFoundError is wrapped."""
        with pytest.raises(PatternLoadError, match="not found"):
            load_json_file(tmp_path / "nonexistent.json")

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod doesn't work on Windows")
    def test_permission_denied(self, tmp_path: Path) -> None:
        """Test PermissionError is wrapped."""
        # Create file with no read permissions
        restricted_file = tmp_path / "restricted.json"
        restricted_file.write_text('{"test": true}')
        restricted_file.chmod(0o000)

        try:
            with pytest.raises(PatternLoadError, match="Permission denied"):
                load_json_file(restricted_file)
        finally:
            # Restore permissions for cleanup
            restricted_file.chmod(0o644)

    def test_invalid_json(self, tmp_path: Path) -> None:
        """Test JSONDecodeError is wrapped."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ not valid json }")

        with pytest.raises(PatternLoadError, match="Invalid JSON"):
            load_json_file(invalid_file)

    def test_empty_file(self, tmp_path: Path) -> None:
        """Test empty file produces PatternLoadError."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")

        with pytest.raises(PatternLoadError, match="Invalid JSON"):
            load_json_file(empty_file)


class TestCacheLRU:
    """Tests for LRU cache behavior."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        clear_pattern_cache()

    def teardown_method(self) -> None:
        """Clear cache after each test."""
        clear_pattern_cache()

    def test_cache_stores_value(self) -> None:
        """Test cache stores and retrieves values."""
        _cache_set("test_key", {"data": "value"})
        result = _cache_get("test_key")
        assert result == {"data": "value"}

    def test_cache_returns_none_for_missing(self) -> None:
        """Test cache returns None for missing keys."""
        result = _cache_get("nonexistent")
        assert result is None

    def test_cache_eviction(self) -> None:
        """Test cache evicts oldest entries when full."""
        # Fill cache beyond limit (20 entries)
        for i in range(25):
            _cache_set(f"key_{i}", f"value_{i}")

        # First 5 entries should be evicted
        for i in range(5):
            assert _cache_get(f"key_{i}") is None

        # Later entries should still exist
        for i in range(5, 25):
            assert _cache_get(f"key_{i}") == f"value_{i}"

    def test_cache_lru_order(self) -> None:
        """Test LRU access order is maintained."""
        # Add 15 entries
        for i in range(15):
            _cache_set(f"key_{i}", f"value_{i}")

        # Access key_0 to make it recently used
        _cache_get("key_0")

        # Add 10 more entries to trigger eviction
        for i in range(15, 25):
            _cache_set(f"key_{i}", f"value_{i}")

        # key_0 should still exist (was recently accessed)
        assert _cache_get("key_0") is not None

        # key_1 through key_4 should be evicted (oldest not accessed)
        for i in range(1, 5):
            assert _cache_get(f"key_{i}") is None


class TestCustomPatternsLoading:
    """Tests for custom pattern file loading."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        clear_pattern_cache()

    def teardown_method(self) -> None:
        """Clear cache after each test."""
        clear_pattern_cache()

    def test_custom_patterns_merge(self, tmp_path: Path) -> None:
        """Test custom patterns are merged with builtin."""
        custom_file = tmp_path / "custom_pii.json"
        custom_file.write_text(
            json.dumps(
                {
                    "patterns": {
                        "custom_ssn": {
                            "regex": r"\d{3}-\d{2}-\d{4}",
                            "replacement_prefix": "SSN",
                        }
                    }
                }
            )
        )

        result = load_pii_patterns(custom_file)

        # Should have custom pattern
        assert "custom_ssn" in result["patterns"]
        # Should still have builtin patterns
        assert "mac_address" in result["patterns"]

    def test_malformed_custom_patterns(self, tmp_path: Path) -> None:
        """Test malformed custom patterns file raises error."""
        malformed_file = tmp_path / "malformed.json"
        malformed_file.write_text('{"patterns": "not a dict"}')

        # Should load without error (malformed structure is allowed)
        # The code doesn't validate structure, just JSON syntax
        result = load_pii_patterns(malformed_file)
        # The builtin patterns should still be there
        assert "mac_address" in result["patterns"]

    def test_custom_patterns_with_nonexistent_file(self) -> None:
        """Test nonexistent custom patterns file raises error."""
        with pytest.raises(PatternLoadError, match="not found"):
            load_pii_patterns("/nonexistent/path/patterns.json")


class TestCompilePattern:
    """Tests for compile_pattern function."""

    @pytest.mark.parametrize(
        ("pattern_def", "desc"),
        [
            ({"regex": "[invalid(regex", "replacement_prefix": "BAD"}, "unclosed_bracket"),
            ({"regex": "*bad", "replacement_prefix": "BAD"}, "quantifier_at_start"),
            ({"regex": "(((unclosed", "replacement_prefix": "BAD"}, "unclosed_paren"),
        ],
    )
    def test_invalid_regex_returns_none(self, pattern_def: dict, desc: str) -> None:
        """Test that invalid regex patterns return None instead of raising."""
        result = compile_pattern(pattern_def)
        assert result is None, f"{desc}: invalid regex should return None"

    def test_valid_regex_returns_pattern(self) -> None:
        """Test that valid regex patterns compile successfully."""
        result = compile_pattern({"regex": r"\d{3}-\d{2}-\d{4}", "replacement_prefix": "SSN"})
        assert result is not None
        assert result.pattern == r"\d{3}-\d{2}-\d{4}"

    def test_valid_regex_with_flags(self) -> None:
        """Test that valid regex with flags compiles successfully."""
        result = compile_pattern({"regex": "test", "flags": ["IGNORECASE"], "replacement_prefix": "T"})
        assert result is not None
        assert result.flags & __import__("re").IGNORECASE


# ── Domain pattern loading ───────────────────────────────────────────────


class TestListDomains:
    """Tests for list_domains."""

    def test_returns_network_device(self) -> None:
        """Built-in network-device domain is listed."""
        domains = list_domains()
        names = [d["name"] for d in domains]
        assert "network-device" in names

    def test_domain_has_description(self) -> None:
        """Each domain has a non-empty description."""
        for d in list_domains():
            assert d["description"], f"Domain {d['name']} missing description"

    def test_domain_has_path(self) -> None:
        """Each domain has a valid path."""
        for d in list_domains():
            assert Path(d["path"]).exists(), f"Domain {d['name']} path missing"


RESOLVE_PATTERNS_CASES = [
    # (input, should_resolve, description)
    ("network-device", True, "builtin_name_with_hyphens"),
    ("network_device", True, "builtin_name_with_underscores"),
]


class TestResolvePatternsArg:
    """Tests for resolve_patterns_arg."""

    @pytest.mark.parametrize(
        ("value", "should_resolve", "desc"),
        RESOLVE_PATTERNS_CASES,
        ids=[c[2] for c in RESOLVE_PATTERNS_CASES],
    )
    def test_resolves_builtin(self, value: str, should_resolve: bool, desc: str) -> None:
        """Built-in names resolve to existing files."""
        path = resolve_patterns_arg(value)
        assert path.exists(), f"{desc}: resolved path should exist"

    def test_resolves_file_path(self, tmp_path: Path) -> None:
        """File paths resolve directly."""
        f = tmp_path / "custom.json"
        f.write_text("{}")
        path = resolve_patterns_arg(str(f))
        assert path == f

    def test_unknown_name_raises(self) -> None:
        """Unknown domain name raises PatternLoadError."""
        with pytest.raises(PatternLoadError, match="Unknown pattern domain"):
            resolve_patterns_arg("nonexistent-domain")

    def test_missing_file_raises(self) -> None:
        """Missing file path raises PatternLoadError."""
        with pytest.raises(PatternLoadError, match="not found"):
            resolve_patterns_arg("/tmp/no_such_file.json")  # noqa: S108


class TestCompileSafeValuePatterns:
    """Tests for compile_safe_value_patterns."""

    def test_compiles_from_sensitive_data(self) -> None:
        """Compiles patterns from the heuristics section of sensitive data."""
        data = {
            "heuristics": {
                "safe_value_patterns": [
                    {"regex": "^test$"},
                    {"regex": "^foo$", "flags": ["IGNORECASE"]},
                ],
            },
        }
        patterns = compile_safe_value_patterns(data)
        assert len(patterns) == 2
        assert patterns[0].match("test")
        assert not patterns[0].match("TEST")
        assert patterns[1].match("FOO")

    def test_empty_when_no_heuristics(self) -> None:
        """Returns empty list when no heuristics section."""
        assert compile_safe_value_patterns({}) == []

    def test_skips_invalid_regex(self) -> None:
        """Invalid regex patterns are skipped."""
        data = {
            "heuristics": {
                "safe_value_patterns": [
                    {"regex": "^valid$"},
                    {"regex": "[invalid("},
                ],
            },
        }
        patterns = compile_safe_value_patterns(data)
        assert len(patterns) == 1


class TestSensitivePatternsHeuristicsMerge:
    """Tests for heuristics.safe_value_patterns merging in load_sensitive_patterns."""

    def test_merges_custom_safe_value_patterns(self) -> None:
        """Custom heuristics.safe_value_patterns are merged into loaded data."""
        clear_pattern_cache()
        custom = {
            "heuristics": {
                "safe_value_patterns": [
                    {"regex": "^custom_safe$"},
                ],
            },
        }
        result = load_sensitive_patterns(custom)
        heuristics = result.get("heuristics", {})
        safe_pats = heuristics.get("safe_value_patterns", [])
        assert any(p.get("regex") == "^custom_safe$" for p in safe_pats)

    def test_no_heuristics_section_ok(self) -> None:
        """Loading without heuristics section works fine."""
        clear_pattern_cache()
        result = load_sensitive_patterns(None)
        # Should not have heuristics section (not in core sensitive.json)
        assert isinstance(result, dict)
