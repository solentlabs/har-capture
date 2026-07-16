"""Tests for consolidated redaction checking.

This module tests the unified redaction checking logic that determines if
a value has already been redacted or sanitized.

Test Coverage:
    - Static placeholder recognition ([REDACTED], XX:XX:XX:XX:XX:XX, etc.)
    - Hash prefix detection (DEVICE_, SERIAL_, TOKEN_, etc.)
    - Format-preserving pattern matching (02:xx MACs, 10.255.x.x IPs)
    - Redaction pattern recognition (***PASSWORD***, 000000, etc.)
    - Case-insensitive matching
    - Custom pattern file support with merging
    - Edge cases (empty strings, partial matches, prefix positioning)
    - Integration with validation.secrets module
    - Error handling for invalid pattern files

Test Strategy:
    - Table-driven tests with parameterized test data
    - Separate tables for redacted vs non-redacted values
    - Integration tests with custom allowlist files
    - Error condition testing (malformed JSON, missing files)
    - Backwards compatibility validation

Dependencies:
    - pytest for test framework and parametrization
    - tempfile for creating test pattern files
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from har_capture.patterns.redaction import is_allowlisted, is_redacted

# Load test data from fixture
_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_redaction.json").read_text())

REDACTED_VALUES = _FIXTURES["redacted_values"]
NON_REDACTED_VALUES = _FIXTURES["non_redacted_values"]
CASE_INSENSITIVE_PAIRS = [tuple(group) for group in _FIXTURES["case_insensitive_pairs"]]


class TestIsRedacted:
    """Tests for is_redacted function."""

    @pytest.mark.parametrize("value", REDACTED_VALUES)
    def test_redacted_values(self, value: str) -> None:
        """Test values that should be recognized as redacted."""
        assert is_redacted(value), f"Expected {value!r} to be redacted"

    @pytest.mark.parametrize("value", NON_REDACTED_VALUES)
    def test_non_redacted_values(self, value: str) -> None:
        """Test that normal values are not considered redacted."""
        assert not is_redacted(value), f"Expected {value!r} to NOT be redacted"

    @pytest.mark.parametrize("variants", CASE_INSENSITIVE_PAIRS)
    def test_case_insensitive_matching(self, variants: tuple[str, ...]) -> None:
        """Test that pattern matching is case-insensitive."""
        for variant in variants:
            assert is_redacted(variant), f"Expected {variant!r} to be redacted (case-insensitive)"

    @pytest.mark.parametrize(
        "value,expected",
        [
            # Exact matches
            ("[REDACTED]", True),
            ("DEVICE_test", True),
            # Partial matches in context
            ("This value is REDACTED", True),
            ("Value: [REDACTED]", True),
            # Prefix matching
            ("DEVICE_test", True),
            ("MY_DEVICE_test", False),  # Not at start
            # Edge cases
            ("", False),
            ("   ", False),
        ],
    )
    def test_edge_cases(self, value: str, expected: bool) -> None:
        """Test edge cases and boundary conditions."""
        assert is_redacted(value) == expected

    def test_custom_patterns(self) -> None:
        """Test custom patterns file works correctly."""
        custom_allowlist = {
            "static_placeholders": {
                "values": [
                    "XX:XX:XX:XX:XX:XX",
                    "0.0.0.0",
                    "::",
                    "x@x.invalid",
                    "[REDACTED]",
                    "CUSTOM_REDACTED",
                ]
            },
            "hash_prefixes": {
                "values": [
                    "SERIAL_",
                    "ACCOUNT_",
                    "PASS_",
                    "TOKEN_",
                    "CSRF_",
                    "CONFIG_",
                    "WIFI_",
                    "DEVICE_",
                    "FIELD_",
                    "AUTH_",
                    "COOKIE_",
                    "CUSTOM_",
                ]
            },
            "format_preserving_patterns": {
                "mac": {
                    "pattern": "^02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$",
                    "description": "Locally administered MAC",
                },
                "private_ip": {
                    "pattern": "^10\\.255\\.\\d{1,3}\\.\\d{1,3}$",
                    "description": "Redacted private IP",
                },
                "public_ip": {
                    "pattern": "^192\\.0\\.2\\.\\d{1,3}$",
                    "description": "TEST-NET-1",
                },
                "ipv6": {
                    "pattern": "^2001:db8::",
                    "description": "IPv6 documentation",
                },
                "email": {
                    "pattern": "@redacted\\.invalid$",
                    "description": "Reserved .invalid TLD",
                },
            },
            "redaction_patterns": {
                "values": [
                    "\\[REDACTED\\]",
                    "REDACTED",
                    "XXX+",
                    "0{6,}",
                    "\\*\\*\\*[A-Z]+\\*\\*\\*",
                    "COOKIE_[a-f0-9]{8}",
                    "MAC_[a-f0-9]{8}",
                    "PASS_[a-f0-9]{8}",
                    "TOKEN_[a-f0-9]{8}",
                    "FIELD_[a-f0-9]{8}",
                    "^MYAPP_.*",
                ]
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_allowlist, f)
            custom_path = f.name

        try:
            # Test custom patterns
            assert is_redacted("CUSTOM_REDACTED", custom_patterns=custom_path)
            assert is_redacted("CUSTOM_abc123", custom_patterns=custom_path)
            assert is_redacted("MYAPP_secret", custom_patterns=custom_path)
            # Standard patterns should still work
            assert is_redacted("[REDACTED]", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)

    def test_backwards_compatibility_with_secrets_module(self) -> None:
        """Test that the function works as a drop-in replacement."""
        result = is_redacted("[REDACTED]")
        assert isinstance(result, bool)
        assert result is True

        result = is_redacted("my_password_value")
        assert isinstance(result, bool)
        assert result is False


class TestIsAllowlisted:
    """Tests for is_allowlisted function (backward compatibility wrapper)."""

    @pytest.mark.parametrize(
        "value,allowlist,expected",
        [
            # None allowlist (loads default)
            ("[REDACTED]", None, True),
            ("DEVICE_test", None, True),
            ("my_value", None, False),
            # Explicit allowlist - static placeholders
            ("EXPLICIT_VALUE", {"static_placeholders": {"values": ["EXPLICIT_VALUE"]}}, True),
            ("other", {"static_placeholders": {"values": ["EXPLICIT_VALUE"]}}, False),
            # Explicit allowlist - hash prefixes
            ("PREFIX_abc123", {"hash_prefixes": {"values": ["PREFIX_"]}}, True),
            ("other_abc123", {"hash_prefixes": {"values": ["PREFIX_"]}}, False),
        ],
    )
    def test_allowlist_checking(self, value: str, allowlist: dict | None, expected: bool) -> None:
        """Test is_allowlisted with various allowlist configurations."""
        assert is_allowlisted(value, allowlist) == expected

    def test_format_preserving_patterns_in_allowlist(self) -> None:
        """Test that format-preserving patterns work with explicit allowlist."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "format_preserving_patterns": {"test_pattern": {"pattern": "^TEST_\\d+$", "description": "Test"}},
        }

        assert is_allowlisted("TEST_123", allowlist)
        assert is_allowlisted("TEST_999", allowlist)
        assert not is_allowlisted("TEST_abc", allowlist)

    def test_redaction_patterns_in_allowlist(self) -> None:
        """Test that redaction_patterns work with explicit allowlist."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "redaction_patterns": {"values": ["SANITIZED", "\\*\\*\\*"]},
        }

        assert is_allowlisted("SANITIZED", allowlist)
        assert is_allowlisted("***", allowlist)
        assert is_allowlisted("***VALUE***", allowlist)
        assert not is_allowlisted("normal_value", allowlist)


class TestIntegrationWithValidationModule:
    """Test integration with validation.secrets module."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("[REDACTED]", True),
            ("DEVICE_test", True),
            ("my_password", False),
        ],
    )
    def test_validation_secrets_uses_new_module(self, value: str, expected: bool) -> None:
        """Test that validation.secrets.is_redacted uses the new module."""
        from har_capture.validation.secrets import is_redacted as secrets_is_redacted

        assert secrets_is_redacted(value) == expected

    def test_custom_patterns_with_validation_module(self) -> None:
        """Test custom patterns work through validation.secrets."""
        from har_capture.validation.secrets import is_redacted as secrets_is_redacted

        custom_allowlist = {
            "static_placeholders": {"values": ["CUSTOM_VAL"]},
            "hash_prefixes": {"values": []},
            "redaction_patterns": {"values": []},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_allowlist, f)
            custom_path = f.name

        try:
            assert secrets_is_redacted("CUSTOM_VAL", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)


class TestMalformedRegexHandling:
    """Tests that malformed regex patterns in allowlist are handled gracefully."""

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        [
            ("[invalid(regex", "unclosed_bracket"),
            ("*bad", "quantifier_at_start"),
            ("(?P<dup>a)(?P<dup>b)", "duplicate_group_name"),
        ],
    )
    def test_malformed_regex_in_allowlist_is_skipped(self, pattern: str, desc: str) -> None:
        """Test that invalid regex patterns in redaction_patterns are skipped."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "redaction_patterns": {"values": [pattern, "VALID_PATTERN"]},
        }

        # Should not raise, and should still match the valid pattern
        assert is_allowlisted("VALID_PATTERN", allowlist), f"{desc}: valid pattern should still match"
        # Should not crash on the invalid pattern
        assert not is_allowlisted("unmatched_value", allowlist), f"{desc}: should return False for non-match"


class TestFormatPreservingInvalidRegex:
    """Tests for invalid regex in format_preserving_patterns."""

    def test_invalid_format_preserving_regex_is_skipped(self) -> None:
        """Test that invalid regex in format_preserving_patterns is skipped gracefully."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "format_preserving_patterns": {
                "bad_regex": {
                    "pattern": "[invalid(regex",
                    "description": "broken regex",
                },
                "good_regex": {
                    "pattern": "^GOOD_\\d+$",
                    "description": "valid regex",
                },
            },
        }
        # Should not raise; bad pattern is skipped, good pattern still works
        assert is_allowlisted("GOOD_123", allowlist)
        assert not is_allowlisted("random_value", allowlist)


class TestCookieAttributeMetadataDetection:
    """Tests for is_cookie_attribute_metadata helper."""

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        [
            ("HttpOnly: true, Secure: true", True, "standard_metadata"),
            ("SameSite=Lax", True, "samesite_attr"),
            ("session=abc123", False, "normal_cookie"),
            ("", False, "empty_string"),
            ("   ", False, "whitespace_only"),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else "",
    )
    def test_cookie_attribute_metadata(self, value: str, expected: bool, desc: str) -> None:
        """Test is_cookie_attribute_metadata with various inputs."""
        from har_capture.patterns.redaction import is_cookie_attribute_metadata

        assert is_cookie_attribute_metadata(value) == expected, desc


class TestIsBase64DecodableText:
    """Tests for the is_base64_decodable_text heuristic helper."""

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        [
            ("ZXhhbXBsZS1ub3QtcmVhbA==", True, "base64_bare_password"),
            ("YWRtaW46aHVudGVyMg==", True, "base64_userpass_also_matches"),
            ("aGVsbG8gd29ybGQ=", True, "base64_text_with_space"),
            ("admin", False, "plain_word_invalid_length"),
            ("login", False, "plain_word_invalid_length_2"),
            ("test", False, "valid_b64_but_nonprintable_bytes"),
            ("1234", False, "digits_decode_to_nonprintable"),
            ("FIELD_9f856745", False, "placeholder_not_base64_charset"),
            ("not-base64!", False, "invalid_charset"),
            ("Zg==", False, "decoded_too_short"),
            ("", False, "empty_string"),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else "",
    )
    def test_is_base64_decodable_text(self, value: str, expected: bool, desc: str) -> None:
        from har_capture.patterns.redaction import is_base64_decodable_text

        assert is_base64_decodable_text(value) == expected, desc


class TestErrorHandling:
    """Test error handling in redaction checking."""

    def test_invalid_custom_patterns_file(self) -> None:
        """Test handling of invalid custom patterns file."""
        with pytest.raises(Exception):  # PatternLoadError
            is_redacted("test", custom_patterns="/nonexistent/file.json")

    def test_malformed_custom_patterns_json(self) -> None:
        """Test handling of malformed JSON in custom patterns."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            custom_path = f.name

        try:
            with pytest.raises(Exception):  # JSON decode error
                is_redacted("test", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)

    def test_empty_custom_patterns_file(self) -> None:
        """Test handling of empty custom patterns file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            custom_path = f.name

        try:
            # Should not crash, just return False for non-redacted values
            assert not is_redacted("test_value", custom_patterns=custom_path)
            # Standard patterns should still work
            assert is_redacted("[REDACTED]", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)
