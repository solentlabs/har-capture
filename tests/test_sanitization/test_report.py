"""Tests for sanitization report data structures.

This module tests the data classes used to track sanitization results,
flagged values, and user decisions during interactive workflows.

Test Coverage:
    - FlaggedValue creation and serialization
    - SanitizationReport structure and methods
    - ConfidenceLevel enum values
    - RedactionStatus state transitions
    - Report statistics (counts, percentages)
    - JSON serialization/deserialization
    - Report metadata (files, salt)

Test Strategy:
    - Unit tests for each data class
    - Validation of immutability where appropriate
    - JSON round-trip testing
    - Statistics calculation verification
    - Edge cases (empty reports, all statuses)

Dependencies:
    - pytest for test framework
    - dataclasses for structure validation
"""

from __future__ import annotations

import json

import pytest

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
FLAGGED_VALUE_CASES = [
    # (original_value, category, confidence, status, expected_status_value)
    ("HomeNetwork-5G", "wifi_ssid", ConfidenceLevel.HIGH, RedactionStatus.FLAGGED, "flagged"),
    ("Johns-iPhone", "device_name", ConfidenceLevel.MEDIUM, RedactionStatus.USER_REDACTED, "user"),
    ("secretpass", "credential", ConfidenceLevel.LOW, RedactionStatus.USER_SKIPPED, "skipped"),
    ("auto-val", "mac_address", ConfidenceLevel.HIGH, RedactionStatus.AUTO_REDACTED, "auto"),
]

TO_DICT_FIELD_CASES = [
    # (field_name, expected_type, description)
    ("input_file", str, "input_file_is_string"),
    ("output_file", str, "output_file_is_string"),
    ("salt", str, "salt_is_string"),
    ("summary", dict, "summary_is_dict"),
    ("auto_redacted_counts", dict, "auto_redacted_counts_is_dict"),
    ("flagged", list, "flagged_is_list"),
    ("warnings", list, "warnings_is_list"),
]

TOTAL_COUNT_CASES = [
    # (auto_counts, flagged_statuses, expected_auto, expected_user_redacted, expected_user_skipped)
    ({}, [], 0, 0, 0),
    ({"mac": 5}, [], 5, 0, 0),
    ({"mac": 5, "ip": 3}, [], 8, 0, 0),
    ({}, [RedactionStatus.USER_REDACTED], 0, 1, 0),
    ({}, [RedactionStatus.USER_SKIPPED], 0, 0, 1),
    ({}, [RedactionStatus.FLAGGED, RedactionStatus.USER_REDACTED, RedactionStatus.USER_SKIPPED], 0, 1, 1),
    ({"mac": 2, "pass": 1}, [RedactionStatus.USER_REDACTED, RedactionStatus.USER_REDACTED], 3, 2, 0),
]

HAS_PENDING_REVIEW_CASES = [
    # (statuses, expected_has_pending, description)
    ([], False, "empty_list_no_pending"),
    ([RedactionStatus.FLAGGED], True, "one_flagged_has_pending"),
    ([RedactionStatus.USER_REDACTED], False, "one_redacted_no_pending"),
    ([RedactionStatus.USER_SKIPPED], False, "one_skipped_no_pending"),
    ([RedactionStatus.USER_REDACTED, RedactionStatus.FLAGGED], True, "mixed_has_pending"),
    ([RedactionStatus.USER_REDACTED, RedactionStatus.USER_SKIPPED], False, "all_decided_no_pending"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestFlaggedValue:
    """Tests for FlaggedValue dataclass."""

    @pytest.mark.parametrize(
        ("original_value", "category", "confidence", "status", "expected_status_value"),
        FLAGGED_VALUE_CASES,
        ids=[f"{c[0]}_{c[4]}" for c in FLAGGED_VALUE_CASES],
    )
    def test_flagged_value_creation(
        self,
        original_value: str,
        category: str,
        confidence: ConfidenceLevel,
        status: RedactionStatus,
        expected_status_value: str,
    ) -> None:
        """Test FlaggedValue can be created with various parameters."""
        fv = FlaggedValue(
            original_value=original_value,
            category=category,
            confidence=confidence,
            context="test context",
            reason="test reason",
            status=status,
        )
        assert fv.original_value == original_value
        assert fv.category == category
        assert fv.confidence == confidence
        assert fv.status == status
        assert fv.status.value == expected_status_value

    def test_flagged_value_defaults(self) -> None:
        """Test FlaggedValue default values."""
        fv = FlaggedValue(
            original_value="test",
            category="test_cat",
            confidence=ConfidenceLevel.MEDIUM,
            context="ctx",
            reason="reason",
        )
        assert fv.occurrences == 1
        assert fv.status == RedactionStatus.FLAGGED
        assert fv.redacted_value is None


class TestSanitizationReport:
    """Tests for SanitizationReport dataclass."""

    @pytest.mark.parametrize(
        ("field_name", "expected_type", "desc"),
        TO_DICT_FIELD_CASES,
        ids=[c[2] for c in TO_DICT_FIELD_CASES],
    )
    def test_to_dict_serialization_fields(self, field_name: str, expected_type: type, desc: str) -> None:
        """Test to_dict returns expected fields with correct types."""
        report = SanitizationReport(
            input_file="input.har",
            output_file="output.har",
            salt="test-salt",
            auto_redacted_counts={"mac": 5},
            flagged=[
                FlaggedValue(
                    original_value="test",
                    category="test_cat",
                    confidence=ConfidenceLevel.MEDIUM,
                    context="ctx",
                    reason="reason",
                )
            ],
            warnings=["test warning"],
        )
        result = report.to_dict()
        assert field_name in result, f"Missing field: {field_name}"
        assert isinstance(result[field_name], expected_type), f"Wrong type for {field_name}"

    def test_to_dict_summary_contains_counts(self) -> None:
        """Test to_dict summary section contains correct counts."""
        report = SanitizationReport(
            input_file="input.har",
            output_file="output.har",
            salt="salt",
            auto_redacted_counts={"mac": 3, "ip": 2},
            flagged=[
                FlaggedValue(
                    original_value="val1",
                    category="cat",
                    confidence=ConfidenceLevel.HIGH,
                    context="ctx",
                    reason="reason",
                    status=RedactionStatus.USER_REDACTED,
                ),
                FlaggedValue(
                    original_value="val2",
                    category="cat",
                    confidence=ConfidenceLevel.LOW,
                    context="ctx",
                    reason="reason",
                    status=RedactionStatus.USER_SKIPPED,
                ),
            ],
        )
        result = report.to_dict()
        assert result["summary"]["auto_redacted"] == 5
        assert result["summary"]["user_redacted"] == 1
        assert result["summary"]["user_skipped"] == 1

    def test_to_dict_json_serializable(self) -> None:
        """Test to_dict output is JSON serializable."""
        report = SanitizationReport(
            input_file="input.har",
            output_file="output.har",
            salt="test-salt",
            auto_redacted_counts={"mac": 5, "password": 2},
            flagged=[
                FlaggedValue(
                    original_value="HomeNetwork",
                    category="wifi_ssid",
                    confidence=ConfidenceLevel.HIGH,
                    context="...data...",
                    reason="SSID-like pattern",
                    occurrences=2,
                    status=RedactionStatus.USER_REDACTED,
                )
            ],
            warnings=["Manual review recommended"],
        )
        # Should not raise
        json_str = json.dumps(report.to_dict())
        # Should be valid JSON
        restored = json.loads(json_str)
        assert restored["salt"] == "test-salt"
        assert len(restored["flagged"]) == 1

    @pytest.mark.parametrize(
        ("auto_counts", "statuses", "expected_auto", "expected_user_redacted", "expected_skipped"),
        TOTAL_COUNT_CASES,
        ids=[
            f"auto{sum(c[0].values())}_red{sum(1 for s in c[1] if s == RedactionStatus.USER_REDACTED)}_skip{sum(1 for s in c[1] if s == RedactionStatus.USER_SKIPPED)}"
            for c in TOTAL_COUNT_CASES
        ],
    )
    def test_total_counts(
        self,
        auto_counts: dict[str, int],
        statuses: list[RedactionStatus],
        expected_auto: int,
        expected_user_redacted: int,
        expected_skipped: int,
    ) -> None:
        """Test total count properties."""
        flagged = [
            FlaggedValue(
                original_value=f"val{i}",
                category="cat",
                confidence=ConfidenceLevel.MEDIUM,
                context="ctx",
                reason="reason",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="salt",
            auto_redacted_counts=auto_counts,
            flagged=flagged,
        )
        assert report.total_auto_redacted == expected_auto
        assert report.total_user_redacted == expected_user_redacted
        assert report.total_user_skipped == expected_skipped

    @pytest.mark.parametrize(
        ("statuses", "expected_has_pending", "desc"),
        HAS_PENDING_REVIEW_CASES,
        ids=[c[2] for c in HAS_PENDING_REVIEW_CASES],
    )
    def test_has_pending_review(
        self, statuses: list[RedactionStatus], expected_has_pending: bool, desc: str
    ) -> None:
        """Test has_pending_review property."""
        flagged = [
            FlaggedValue(
                original_value=f"val{i}",
                category="cat",
                confidence=ConfidenceLevel.MEDIUM,
                context="ctx",
                reason="reason",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="salt",
            flagged=flagged,
        )
        assert report.has_pending_review is expected_has_pending


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""

    def test_confidence_levels_have_correct_values(self) -> None:
        """Test confidence level enum values."""
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"


class TestRedactionStatus:
    """Tests for RedactionStatus enum."""

    def test_redaction_statuses_have_correct_values(self) -> None:
        """Test redaction status enum values."""
        assert RedactionStatus.AUTO_REDACTED.value == "auto"
        assert RedactionStatus.FLAGGED.value == "flagged"
        assert RedactionStatus.USER_REDACTED.value == "user"
        assert RedactionStatus.USER_SKIPPED.value == "skipped"
