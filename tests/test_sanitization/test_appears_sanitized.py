"""Tests for appears_sanitized detection.

This module tests the heuristic that determines if a HAR file has already
been sanitized, allowing users to skip redundant sanitization passes.

Test Coverage:
    - Detection of sanitized values in URLs, headers, and content
    - Recognition of various redaction formats (hash prefixes, placeholders)
    - False positive avoidance (real values that look sanitized)
    - Multiple redacted value scenarios
    - Edge cases (empty HAR, no entries, minimal data)

Test Strategy:
    - Table-driven tests with clear true/false positive cases
    - Realistic HAR structure testing
    - Coverage of all redaction format types
    - Edge case validation

Dependencies:
    - pytest for test framework and parametrization
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from har_capture.sanitization.har import appears_sanitized

_FIXTURES = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "test_appears_sanitized.json").read_text()
)
REDACTION_PATTERN_CASES = _FIXTURES["redaction_pattern_cases"]["cases"]

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
APPEARS_SANITIZED_CASES = [
    # (har_data, threshold, expected_sanitized, expected_min_count, description)
    # Clean files
    (
        {"log": {"entries": [], "content": "normal content"}},
        10, False, 0, "clean_empty_file"
    ),
    (
        {"log": {"entries": [], "content": "MAC: AA:BB:CC:DD:EE:FF IP: 192.168.1.1"}},
        10, False, 0, "clean_with_unsanitized_data"
    ),
    # Partially sanitized (below threshold)
    (
        {"log": {"entries": [], "content": "MAC_a1b2c3d4 MAC_e5f6a7b8"}},
        10, False, 2, "partial_mac_hashes"
    ),
    (
        {"log": {"entries": [], "content": "PASS_12345678 TOKEN_abcdef12"}},
        10, False, 2, "partial_pass_token"
    ),
    # Fully sanitized (at or above threshold)
    (
        {
            "log": {
                "entries": [],
                "content": " ".join([f"MAC_{i:08x}" for i in range(10)])
            }
        },
        10, True, 10, "exactly_threshold_mac"
    ),
    (
        {
            "log": {
                "entries": [],
                "content": " ".join([f"PASS_{i:08x}" for i in range(15)])
            }
        },
        10, True, 15, "above_threshold_pass"
    ),
]

THRESHOLD_VARIATION_CASES = [
    # (count_in_file, threshold, expected_sanitized, description)
    (5, 10, False, "count_5_threshold_10"),
    (10, 10, True, "count_10_threshold_10"),
    (15, 10, True, "count_15_threshold_10"),
    (5, 5, True, "count_5_threshold_5"),
    (3, 5, False, "count_3_threshold_5"),
    (0, 1, False, "count_0_threshold_1"),
    (1, 1, True, "count_1_threshold_1"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestAppearsSanitized:
    """Tests for appears_sanitized detection."""

    @pytest.mark.parametrize(
        ("har_data", "threshold", "expected_sanitized", "expected_min_count", "desc"),
        APPEARS_SANITIZED_CASES,
        ids=[c[4] for c in APPEARS_SANITIZED_CASES],
    )
    def test_appears_sanitized(
        self,
        har_data: dict,
        threshold: int,
        expected_sanitized: bool,
        expected_min_count: int,
        desc: str,
    ) -> None:
        """Test appears_sanitized detection."""
        is_sanitized, count = appears_sanitized(har_data, threshold=threshold)
        assert is_sanitized is expected_sanitized, f"{desc}: expected {expected_sanitized}"
        assert count >= expected_min_count, f"{desc}: expected at least {expected_min_count} matches"


class TestRedactionPatternDetection:
    """Tests for individual redaction pattern detection."""

    @pytest.mark.parametrize("case", REDACTION_PATTERN_CASES, ids=[c["id"] for c in REDACTION_PATTERN_CASES])
    def test_pattern_detection(self, case: dict) -> None:
        """Each placeholder shape is counted, or not, on its own."""
        # 15 copies clear the default threshold of 10
        har_data = {"content": " ".join([case["text"]] * 15)}
        is_sanitized, count = appears_sanitized(har_data, threshold=10)

        if case["detected"]:
            assert count >= 15
            assert is_sanitized is True
        else:
            assert count < 10


class TestThresholdVariation:
    """Tests for threshold parameter."""

    @pytest.mark.parametrize(
        ("count_in_file", "threshold", "expected_sanitized", "desc"),
        THRESHOLD_VARIATION_CASES,
        ids=[c[3] for c in THRESHOLD_VARIATION_CASES],
    )
    def test_threshold_variation(
        self,
        count_in_file: int,
        threshold: int,
        expected_sanitized: bool,
        desc: str,
    ) -> None:
        """Test threshold parameter affects detection."""
        # Create HAR with specified number of redaction patterns
        patterns = [f"MAC_{i:08x}" for i in range(count_in_file)]
        har_data = {"content": " ".join(patterns)}

        is_sanitized, count = appears_sanitized(har_data, threshold=threshold)
        assert is_sanitized is expected_sanitized, desc
        assert count == count_in_file, f"Expected count {count_in_file}, got {count}"


class TestMixedPatterns:
    """Tests for files with mixed redaction patterns."""

    def test_mixed_patterns_counted(self) -> None:
        """Test different pattern types are all counted."""
        har_data = {
            "log": {
                "entries": [],
                "content": (
                    "MAC_11111111 MAC_22222222 "
                    "PASS_33333333 PASS_44444444 "
                    "TOKEN_55555555 TOKEN_66666666 "
                    "***MAC*** ***PASSWORD*** "
                    "02:00:00:00:00:01 02:00:00:00:00:02"
                ),
            }
        }
        is_sanitized, count = appears_sanitized(har_data, threshold=5)

        assert is_sanitized is True
        assert count >= 10, "Should count all different pattern types"

    def test_nested_structure_searched(self) -> None:
        """Test patterns in nested HAR structure are found."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"url": "http://test/", "headers": []},
                        "response": {"content": {"text": "MAC_a1a1a1a1 PASS_b2b2b2b2 TOKEN_c3c3c3c3"}},
                    },
                    {
                        "request": {"url": "http://test2/", "headers": []},
                        "response": {"content": {"text": "MAC_d4d4d4d4 MAC_e5e5e5e5 MAC_f6f6f6f6"}},
                    },
                ],
            }
        }
        is_sanitized, count = appears_sanitized(har_data, threshold=5)

        assert is_sanitized is True
        assert count >= 6


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_har(self) -> None:
        """Test empty HAR file."""
        is_sanitized, count = appears_sanitized({})
        assert is_sanitized is False
        assert count == 0

    def test_none_values_in_har(self) -> None:
        """Test HAR with None values doesn't crash."""
        har_data = {"log": None, "content": None}
        # Should not raise
        is_sanitized, _count = appears_sanitized(har_data)
        assert is_sanitized is False

    def test_large_har_file(self) -> None:
        """Test with larger HAR file."""
        # Generate larger HAR with many entries
        entries = []
        for i in range(100):
            entries.append(
                {
                    "request": {"url": f"http://test/{i}"},
                    "response": {"content": {"text": f"MAC_{i:08x}"}},
                }
            )
        har_data = {"log": {"entries": entries}}

        is_sanitized, count = appears_sanitized(har_data, threshold=50)
        assert is_sanitized is True
        assert count >= 100
