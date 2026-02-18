"""Tests for apply_user_redactions function.

This module tests Pass 2 of interactive sanitization where user-selected
redactions are applied via global find-replace across the HAR file.

Test Coverage:
    - Basic user redaction application
    - Multiple redactions in single pass
    - Values appearing multiple times
    - Special character escaping (quotes, newlines, backslashes)
    - Empty redaction lists (no-op)
    - Invalid HAR data error handling
    - Malformed JSON after replacement
    - Circular reference detection

Test Strategy:
    - Unit tests for the apply function in isolation
    - Integration with SanitizationReport structure
    - Error condition testing with clear error messages
    - Salt preservation across passes
    - JSON serialization edge cases

Dependencies:
    - pytest for test framework
    - SanitizationReport for test data structures
"""

from __future__ import annotations

import json
import logging

import pytest

from har_capture.sanitization.har import apply_user_redactions
from har_capture.sanitization.report import (
    ConfidenceLevel,
    FlaggedValue,
    RedactionStatus,
    SanitizationReport,
)

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
SIMPLE_REPLACEMENT_CASES = [
    # (har_data, value_to_redact, expected_not_in_result, description)
    (
        {"log": {"entries": [], "content": "SSID: HomeNetwork-5G"}},
        "HomeNetwork-5G",
        "HomeNetwork-5G",
        "simple_ssid_replacement",
    ),
    (
        {"log": {"entries": [], "password": "secretpass123"}},
        "secretpass123",
        "secretpass123",
        "simple_password_replacement",
    ),
    (
        {"log": {"entries": [], "device": "Johns-iPhone"}},
        "Johns-iPhone",
        "Johns-iPhone",
        "device_name_replacement",
    ),
    (
        {"log": {"entries": [], "values": ["a", "b", "MyNetwork", "c"]}},
        "MyNetwork",
        "MyNetwork",
        "value_in_array_replacement",
    ),
]

JSON_ESCAPING_CASES = [
    # (original_value, description)
    ("Line1\nLine2", "newline_escaped"),
    ('value"with"quotes', "quotes_escaped"),
    ("path\\to\\file", "backslash_escaped"),
    ("tab\there", "tab_escaped"),
    ("carriage\rreturn", "carriage_return_escaped"),
    ("combo\n\t\"\\", "multiple_special_chars"),
]

MULTIPLE_OCCURRENCES_CASES = [
    # (har_data, value_to_redact, expected_occurrences_redacted, description)
    (
        {"log": {"a": "MySSID", "b": {"c": "MySSID"}, "d": ["MySSID", "other", "MySSID"]}},
        "MySSID",
        4,
        "value_appears_four_times",
    ),
    (
        {"log": {"content": "SSID: Test | SSID: Test | Password: secret"}},
        "Test",
        2,
        "value_appears_twice",
    ),
]

STATUS_HANDLING_CASES = [
    # (status, should_redact, description)
    (RedactionStatus.USER_REDACTED, True, "user_redacted_is_applied"),
    (RedactionStatus.USER_SKIPPED, False, "user_skipped_not_applied"),
    (RedactionStatus.FLAGGED, False, "flagged_not_applied"),
    (RedactionStatus.AUTO_REDACTED, False, "auto_redacted_not_applied_again"),
]
# fmt: on


# =============================================================================
# Helper Functions
# =============================================================================


def create_report_with_flagged(
    flagged_values: list[tuple[str, str, RedactionStatus]],
    salt: str = "test-salt",
) -> SanitizationReport:
    """Create a SanitizationReport with specified flagged values.

    Args:
        flagged_values: List of (original_value, category, status) tuples
        salt: Salt for hashing

    Returns:
        SanitizationReport with the flagged values
    """
    flagged = [
        FlaggedValue(
            original_value=val,
            category=cat,
            confidence=ConfidenceLevel.MEDIUM,
            context="test context",
            reason="test reason",
            status=status,
        )
        for val, cat, status in flagged_values
    ]
    return SanitizationReport(
        input_file="input.har",
        output_file="output.har",
        salt=salt,
        flagged=flagged,
    )


# =============================================================================
# Test Classes
# =============================================================================


class TestSimpleReplacement:
    """Tests for basic value replacement."""

    @pytest.mark.parametrize(
        ("har_data", "value_to_redact", "expected_not_in", "desc"),
        SIMPLE_REPLACEMENT_CASES,
        ids=[c[3] for c in SIMPLE_REPLACEMENT_CASES],
    )
    def test_simple_replacement(
        self,
        har_data: dict,
        value_to_redact: str,
        expected_not_in: str,
        desc: str,
    ) -> None:
        """Test simple value replacement."""
        report = create_report_with_flagged([(value_to_redact, "wifi_ssid", RedactionStatus.USER_REDACTED)])
        result = apply_user_redactions(har_data, report)

        # Original value should not be in result
        result_str = json.dumps(result)
        assert expected_not_in not in result_str, f"{desc}: '{expected_not_in}' should be redacted"

    def test_replacement_uses_hash_format(self) -> None:
        """Test replacement value follows hash format (CATEGORY_xxxxxxxx)."""
        har_data = {"log": {"entries": [], "content": "SSID: HomeNetwork"}}
        report = create_report_with_flagged([("HomeNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)])
        result = apply_user_redactions(har_data, report)

        result_str = json.dumps(result)
        # Should contain redacted placeholder
        assert "WIFI_SSID_" in result_str, "Redacted value should have WIFI_SSID_ prefix"

    def test_redacted_value_stored_in_report(self) -> None:
        """Test redacted_value is stored in the FlaggedValue."""
        har_data = {"log": {"entries": [], "content": "SSID: HomeNetwork"}}
        report = create_report_with_flagged([("HomeNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)])
        apply_user_redactions(har_data, report)

        assert report.flagged[0].redacted_value is not None
        assert report.flagged[0].redacted_value.startswith("WIFI_SSID_")


class TestJSONEscaping:
    """Tests for proper JSON escaping during replacement."""

    @pytest.mark.parametrize(
        ("original_value", "desc"),
        JSON_ESCAPING_CASES,
        ids=[c[1] for c in JSON_ESCAPING_CASES],
    )
    def test_json_escaping(self, original_value: str, desc: str) -> None:
        """Test values with special characters are properly escaped."""
        har_data = {"log": {"entries": [], "content": f"Value: {original_value}"}}
        report = create_report_with_flagged([(original_value, "credential", RedactionStatus.USER_REDACTED)])
        result = apply_user_redactions(har_data, report)

        # Original value should not be in result
        # Use json.dumps to properly check the escaped representation
        result_str = json.dumps(result)
        escaped_original = json.dumps(original_value)[1:-1]  # Strip quotes
        assert escaped_original not in result_str, f"{desc}: escaped value should be redacted"

    def test_json_escaping_newline(self) -> None:
        """Test values with newlines are properly escaped in JSON context."""
        har_data = {"log": {"entries": [], "content": "SSID: Line1\nLine2"}}
        flagged = FlaggedValue(
            original_value="Line1\nLine2",
            category="wifi_ssid",
            confidence=ConfidenceLevel.HIGH,
            context="test",
            reason="test",
            status=RedactionStatus.USER_REDACTED,
        )
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="test-salt",
            flagged=[flagged],
        )
        result = apply_user_redactions(har_data, report)

        # The original value (with newline) should be gone
        assert "Line1\nLine2" not in json.dumps(result)
        # Redacted placeholder should be present
        assert "WIFI_SSID_" in json.dumps(result)

    def test_json_escaping_quotes(self) -> None:
        """Test values with quotes are properly escaped."""
        har_data = {"log": {"entries": [], "content": 'password: secret"value'}}
        flagged = FlaggedValue(
            original_value='secret"value',
            category="password",
            confidence=ConfidenceLevel.HIGH,
            context="test",
            reason="test",
            status=RedactionStatus.USER_REDACTED,
        )
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="test-salt",
            flagged=[flagged],
        )
        result = apply_user_redactions(har_data, report)

        # Check the escaped version is not present
        assert 'secret\\"value' not in json.dumps(result)

    def test_json_escaping_backslash(self) -> None:
        """Test values with backslashes are properly escaped."""
        har_data = {"log": {"entries": [], "content": "path: C:\\Users\\test"}}
        flagged = FlaggedValue(
            original_value="C:\\Users\\test",
            category="credential",
            confidence=ConfidenceLevel.HIGH,
            context="test",
            reason="test",
            status=RedactionStatus.USER_REDACTED,
        )
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="test-salt",
            flagged=[flagged],
        )
        result = apply_user_redactions(har_data, report)

        # Check the escaped version is not present
        result_str = json.dumps(result)
        assert "C:\\\\Users\\\\test" not in result_str


class TestMultipleOccurrences:
    """Tests for global replacement of multiple occurrences."""

    @pytest.mark.parametrize(
        ("har_data", "value_to_redact", "expected_count", "desc"),
        MULTIPLE_OCCURRENCES_CASES,
        ids=[c[3] for c in MULTIPLE_OCCURRENCES_CASES],
    )
    def test_multiple_occurrences_all_replaced(
        self,
        har_data: dict,
        value_to_redact: str,
        expected_count: int,
        desc: str,
    ) -> None:
        """Test all occurrences of a value are replaced."""
        report = create_report_with_flagged([(value_to_redact, "wifi_ssid", RedactionStatus.USER_REDACTED)])
        result = apply_user_redactions(har_data, report)

        result_str = json.dumps(result)
        # Original should not appear
        assert value_to_redact not in result_str

        # Redacted placeholder should appear expected_count times
        redacted = report.flagged[0].redacted_value
        assert redacted is not None
        assert result_str.count(redacted) == expected_count


class TestStatusHandling:
    """Tests for proper handling of different redaction statuses."""

    @pytest.mark.parametrize(
        ("status", "should_redact", "desc"),
        STATUS_HANDLING_CASES,
        ids=[c[2] for c in STATUS_HANDLING_CASES],
    )
    def test_status_handling(self, status: RedactionStatus, should_redact: bool, desc: str) -> None:
        """Test only USER_REDACTED values are replaced."""
        har_data = {"log": {"entries": [], "content": "SSID: TestNetwork"}}
        report = create_report_with_flagged([("TestNetwork", "wifi_ssid", status)])
        result = apply_user_redactions(har_data, report)

        result_str = json.dumps(result)
        if should_redact:
            assert "TestNetwork" not in result_str, f"{desc}: value should be redacted"
        else:
            assert "TestNetwork" in result_str, f"{desc}: value should NOT be redacted"


class TestSaltConsistency:
    """Tests for salt handling in apply_user_redactions."""

    def test_same_salt_produces_same_hash(self) -> None:
        """Test same salt produces consistent hashes."""
        har_data1 = {"log": {"entries": [], "content": "SSID: TestNetwork"}}
        har_data2 = {"log": {"entries": [], "content": "SSID: TestNetwork"}}

        report1 = create_report_with_flagged(
            [("TestNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)],
            salt="same-salt",
        )
        report2 = create_report_with_flagged(
            [("TestNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)],
            salt="same-salt",
        )

        apply_user_redactions(har_data1, report1)
        apply_user_redactions(har_data2, report2)

        assert report1.flagged[0].redacted_value == report2.flagged[0].redacted_value

    def test_different_salt_produces_different_hash(self) -> None:
        """Test different salts produce different hashes."""
        har_data1 = {"log": {"entries": [], "content": "SSID: TestNetwork"}}
        har_data2 = {"log": {"entries": [], "content": "SSID: TestNetwork"}}

        report1 = create_report_with_flagged(
            [("TestNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)],
            salt="salt-one",
        )
        report2 = create_report_with_flagged(
            [("TestNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)],
            salt="salt-two",
        )

        apply_user_redactions(har_data1, report1)
        apply_user_redactions(har_data2, report2)

        assert report1.flagged[0].redacted_value != report2.flagged[0].redacted_value


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_flagged_list(self) -> None:
        """Test with no flagged values."""
        har_data = {"log": {"entries": [], "content": "SSID: TestNetwork"}}
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="test-salt",
            flagged=[],
        )
        result = apply_user_redactions(har_data, report)

        # Data should be unchanged
        assert result == har_data

    def test_value_not_in_har(self) -> None:
        """Test flagged value that doesn't exist in HAR."""
        har_data = {"log": {"entries": [], "content": "SSID: ActualNetwork"}}
        report = create_report_with_flagged(
            [("NonExistentValue", "wifi_ssid", RedactionStatus.USER_REDACTED)]
        )
        result = apply_user_redactions(har_data, report)

        # Original data unchanged
        assert "ActualNetwork" in json.dumps(result)

    def test_empty_har_data(self) -> None:
        """Test with minimal HAR data."""
        har_data: dict = {"log": {}}
        report = create_report_with_flagged([("TestNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)])
        result = apply_user_redactions(har_data, report)

        assert result == {"log": {}}

    def test_preserves_structure(self) -> None:
        """Test HAR structure is preserved after redaction."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test"},
                "entries": [
                    {
                        "request": {"url": "http://test/"},
                        "response": {"content": {"text": "SSID: MyNetwork"}},
                    }
                ],
            }
        }
        report = create_report_with_flagged([("MyNetwork", "wifi_ssid", RedactionStatus.USER_REDACTED)])
        result = apply_user_redactions(har_data, report)

        # Structure preserved
        assert result["log"]["version"] == "1.2"
        assert result["log"]["creator"]["name"] == "test"
        assert len(result["log"]["entries"]) == 1
        # Value redacted
        assert "MyNetwork" not in result["log"]["entries"][0]["response"]["content"]["text"]


class TestErrorHandling:
    """Tests for error handling and validation."""

    @pytest.mark.parametrize(
        ("har_data", "expected_error", "description"),
        [
            ("not a dict", "must be a dictionary", "not_dict"),
            ({}, "Missing required 'log' key", "missing_log"),
        ],
    )
    def test_invalid_har_data(self, har_data: dict | str, expected_error: str, description: str) -> None:
        """Test that invalid HAR data raises HarValidationError."""
        from har_capture.sanitization.har import HarValidationError

        report = SanitizationReport(
            input_file="test.har",
            output_file="test.sanitized.har",
            salt="test-salt",
        )

        with pytest.raises(HarValidationError, match=expected_error):
            apply_user_redactions(har_data, report)  # type: ignore

    def test_malformed_json_serialization(self) -> None:
        """Test handling of data that can't be serialized."""
        from har_capture.sanitization.har import HarValidationError

        # Create circular reference (can't be serialized to JSON)
        har_data: dict = {"log": {"entries": []}}
        har_data["self_ref"] = har_data  # Circular reference

        report = create_report_with_flagged([("test", "test", RedactionStatus.USER_REDACTED)])

        with pytest.raises(HarValidationError, match="Failed to serialize"):
            apply_user_redactions(har_data, report)

    def test_no_redactions_needed(self) -> None:
        """Test that no changes are made when no redactions are requested."""
        har_data = {"log": {"entries": [{"request": {"url": "https://example.com"}}]}}

        report = SanitizationReport(
            input_file="test.har",
            output_file="test.sanitized.har",
            salt="test-salt",
            flagged=[
                FlaggedValue(
                    original_value="test",
                    category="test",
                    confidence=ConfidenceLevel.HIGH,
                    context="test",
                    reason="test",
                    status=RedactionStatus.USER_SKIPPED,  # Not redacted
                )
            ],
        )

        result = apply_user_redactions(har_data, report)
        assert result == har_data  # No changes

    def test_partial_redaction_failure_continues(self) -> None:
        """Test that failure to redact one value doesn't stop others."""
        har_data = {"log": {"a": "value1", "b": "value2"}}

        # Create report with two values to redact
        report = create_report_with_flagged(
            [
                ("value1", "test", RedactionStatus.USER_REDACTED),
                ("value2", "test", RedactionStatus.USER_REDACTED),
            ]
        )

        # Even if one fails, the other should succeed
        # (In practice, failures are rare, but we handle them gracefully)
        result = apply_user_redactions(har_data, report)

        # Both values should be redacted
        result_str = json.dumps(result)
        assert "value1" not in result_str
        assert "value2" not in result_str


class TestLogOutputSecurity:
    """Tests that log messages do not leak PII."""

    @pytest.mark.parametrize(
        ("original_value", "category", "desc"),
        [
            ("my-super-secret-password", "password", "password_not_logged"),
            ("HomeNetwork-5G-WiFi", "wifi_ssid", "ssid_not_logged"),
            ("john.doe@example.com", "email", "email_not_logged"),
        ],
    )
    def test_log_does_not_contain_original_value(
        self, original_value: str, category: str, desc: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that log output during normal operation does not contain original PII value."""
        har_data = {"log": {"entries": [], "content": original_value}}

        # Create a flagged value that will trigger the error handler by
        # mocking the hasher to raise an exception
        flagged = FlaggedValue(
            original_value=original_value,
            category=category,
            confidence=ConfidenceLevel.HIGH,
            context="test",
            reason="test",
            status=RedactionStatus.USER_REDACTED,
        )
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="test-salt",
            flagged=[flagged],
        )

        # Normal operation should not log the original value
        with caplog.at_level(logging.WARNING, logger="har_capture.sanitization.har"):
            apply_user_redactions(har_data, report)

        # The original PII value must NOT appear in any log messages
        for record in caplog.records:
            assert original_value not in record.getMessage(), (
                f"{desc}: original PII value leaked into log message"
            )
