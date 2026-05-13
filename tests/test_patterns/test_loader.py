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
    merge_pattern_files,
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

    def test_json_backspace_escape_trap_warns(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        r"""Warn when JSON parses ``\b`` to ASCII backspace in a pattern regex.

        A custom pattern file with ``\b`` instead of ``\\b`` parses to ASCII
        backspace, compiles silently, and matches nothing - exactly the silent
        no-op behind issue #51. The loader should log a warning so the user
        has some diagnostic rather than a quiet PII leak.
        """
        import logging

        # Write the file directly so we can hit the JSON parser's interpretation
        # of "\b" (which produces ASCII backspace 0x08). Using json.dumps would
        # not reproduce the user's mistake.
        custom_file = tmp_path / "buggy_patterns.json"
        custom_file.write_text(
            '{"patterns": {"test_pattern": {"regex": "\\b[0-9]{8}\\b", "replacement_prefix": "TEST"}}}'
        )

        with caplog.at_level(logging.WARNING, logger="har_capture.patterns.loader"):
            load_pii_patterns(custom_file)

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, "Expected a warning about the JSON \\b escape trap"
        joined = " ".join(r.getMessage() for r in warnings)
        assert "word-boundary" in joined
        assert "buggy_patterns.json" in joined

    def test_custom_scheme_redact_merged_additively(self, tmp_path: Path) -> None:
        """``headers.scheme_redact`` from a custom file extends the built-in list."""
        custom_file = tmp_path / "custom_scheme.json"
        custom_file.write_text(json.dumps({"headers": {"scheme_redact": ["Proxy-Authorization"]}}))

        result = load_sensitive_patterns(custom_file)
        scheme_redact = result["headers"]["scheme_redact"]
        # Built-in entry still present, custom entry appended.
        assert "authorization" in scheme_redact
        assert "Proxy-Authorization" in scheme_redact

    def test_well_escaped_pattern_does_not_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        r"""A correctly-escaped ``\\b`` pattern should not trigger the warning."""
        import logging

        custom_file = tmp_path / "good_patterns.json"
        # \\\\b in Python source = \\b in the file = \b after JSON parsing
        custom_file.write_text(
            '{"patterns": {"test_pattern": {"regex": "\\\\b[0-9]{8}\\\\b", "replacement_prefix": "TEST"}}}'
        )

        with caplog.at_level(logging.WARNING, logger="har_capture.patterns.loader"):
            load_pii_patterns(custom_file)

        trap_warnings = [
            r for r in caplog.records if r.levelno >= logging.WARNING and "word-boundary" in r.getMessage()
        ]
        assert not trap_warnings, (
            f"Did not expect a word-boundary warning for the correctly-escaped pattern; "
            f"got: {[r.getMessage() for r in trap_warnings]}"
        )


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
            resolve_patterns_arg("/nonexistent/dir/no_such_file.json")


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


_LOADER_FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "test_loader.json"
_LOADER_FIXTURE = json.loads(_LOADER_FIXTURE_PATH.read_text())

INCLUDE_LOADER_CASES = [
    (c["domain_config"], c["expected_present"], c["expected_absent"], c["exact_set"], c["id"])
    for c in _LOADER_FIXTURE["include_patterns_loader_cases"]
]

INCLUDE_PII_CASES = [
    (c["domain_config"], c["content"], c["expected_detected"], c["expected_not_detected"], c["id"])
    for c in _LOADER_FIXTURE["include_patterns_pii_cases"]
]


class TestIncludePatterns:
    """Tests for include_patterns in domain/custom pattern files."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        clear_pattern_cache()

    def teardown_method(self) -> None:
        """Clear cache after each test."""
        clear_pattern_cache()

    @pytest.mark.parametrize(
        ("domain_config", "expected_present", "expected_absent", "exact_set", "desc"),
        INCLUDE_LOADER_CASES,
        ids=[c[4] for c in INCLUDE_LOADER_CASES],
    )
    def test_load_pii_with_inclusions(
        self,
        tmp_path: Path,
        domain_config: dict,
        expected_present: list[str],
        expected_absent: list[str],
        exact_set: bool,
        desc: str,
    ) -> None:
        """Test that include_patterns filters the loaded pattern set."""
        domain = tmp_path / "domain.json"
        domain.write_text(json.dumps(domain_config))

        result = load_pii_patterns(str(domain))
        if exact_set:
            assert set(result["patterns"]) == set(expected_present), f"{desc}: exact set mismatch"
        for name in expected_present:
            assert name in result["patterns"], f"{desc}: {name} should be present"
        for name in expected_absent:
            assert name not in result["patterns"], f"{desc}: {name} should be absent"

    @pytest.mark.parametrize(
        ("domain_config", "content", "expected_detected", "expected_not_detected", "desc"),
        INCLUDE_PII_CASES,
        ids=[c[4] for c in INCLUDE_PII_CASES],
    )
    def test_check_for_pii_with_inclusions(
        self,
        tmp_path: Path,
        domain_config: dict,
        content: str,
        expected_detected: list[str],
        expected_not_detected: list[str],
        desc: str,
    ) -> None:
        """End-to-end: check_for_pii respects include_patterns from domain file."""
        from har_capture.sanitization.html import check_for_pii

        domain = tmp_path / "domain.json"
        domain.write_text(json.dumps(domain_config))

        findings = check_for_pii(content, custom_patterns=str(domain))
        detected = {f["pattern"] for f in findings}
        for name in expected_detected:
            assert name in detected, f"{desc}: {name} should be detected"
        for name in expected_not_detected:
            assert name not in detected, f"{desc}: {name} should not be detected"

    def test_dict_custom_with_inclusions(self) -> None:
        """Inclusions work when custom_path is a dict (not a file)."""
        result = load_pii_patterns({"include_patterns": ["mac_address", "serial_number"]})
        assert set(result["patterns"]) == {"mac_address", "serial_number"}

    def test_merge_accumulates_inclusions(self, tmp_path: Path) -> None:
        """merge_pattern_files extends include_patterns across files."""
        file_a = tmp_path / "a.json"
        file_a.write_text(json.dumps({"include_patterns": ["mac_address"]}))
        file_b = tmp_path / "b.json"
        file_b.write_text(json.dumps({"include_patterns": ["email"]}))

        merged = merge_pattern_files([file_a, file_b])
        assert set(merged["include_patterns"]) == {"mac_address", "email"}


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
