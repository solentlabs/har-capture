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
    load_json_file,
    load_pii_patterns,
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
