"""Tests for heuristic detection of suspicious values.

This module tests ML-free heuristics that flag values requiring user review
during interactive sanitization (SSIDs, device names, high-entropy values).

Test Coverage:
    - Safe value detection (known good values)
    - SSID-like pattern matching (WiFi network names)
    - Device name pattern matching
    - High-entropy value detection (potential passwords)
    - Adjacency detection (values near redacted content)
    - Value analysis with confidence scoring
    - Confidence level assignment
    - ReDoS prevention with length checks
    - Entropy threshold tuning

Test Strategy:
    - Table-driven tests with real-world examples
    - False positive/negative testing
    - Performance testing for ReDoS vectors
    - Confidence score validation
    - Edge case coverage (short values, special chars)

Dependencies:
    - pytest for test framework and parametrization
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from har_capture.patterns.loader import CompiledDetector, compile_detectors
from har_capture.sanitization.heuristics import (
    analyze_value,
    calculate_entropy,
    get_confidence_for_value,
    is_adjacent_to_redacted,
    is_credential_like,
    is_high_entropy,
    is_safe_value,
    run_detector,
)
from har_capture.sanitization.report import ConfidenceLevel

# =============================================================================
# Load test data from JSON fixture
# =============================================================================

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_heuristics.json").read_text())

SAFE_VALUE_CASES = [(c["value"], c["is_safe"], c["id"]) for c in _FIXTURES["safe_value_cases"]]

DOMAIN_SAFE_VALUE_CASES = [(c["value"], c["id"]) for c in _FIXTURES["domain_safe_value_cases"]]

SSID_LIKE_CASES = [
    # The "too_long" case uses a generated string that can't live in JSON
    ("a" * 35, c["is_match"], c["id"]) if c["id"] == "too_long" else (c["value"], c["is_match"], c["id"])
    for c in _FIXTURES["ssid_like_cases"]
]

CREDENTIAL_LIKE_CASES = [(c["value"], c["is_match"], c["id"]) for c in _FIXTURES["credential_like_cases"]]

DEVICE_NAME_LIKE_CASES = [(c["value"], c["is_match"], c["id"]) for c in _FIXTURES["device_name_like_cases"]]

HIGH_ENTROPY_CASES = [(c["value"], c["is_match"], c["id"]) for c in _FIXTURES["high_entropy_cases"]]

ADJACENT_TO_REDACTED_CASES = [
    (c["values"], c["index"], c["is_adjacent"], c["id"]) for c in _FIXTURES["adjacent_to_redacted_cases"]
]

ANALYZE_VALUE_CORE_CASES = [
    (c["value"], c["values_context"], c["value_index"], c["should_flag"], c["expected_category"], c["id"])
    for c in _FIXTURES["analyze_value_core_cases"]
]

ANALYZE_VALUE_DETECTOR_CASES = [
    (c["value"], c["values_context"], c["value_index"], c["should_flag"], c["expected_category"], c["id"])
    for c in _FIXTURES["analyze_value_detector_cases"]
]

ANALYZE_VALUE_NO_DETECTOR_CATEGORY_CASES = [
    (c["value"], c["with_detector_category"], c["without_detector_category"], c["id"])
    for c in _FIXTURES["analyze_value_no_detector_category_cases"]
]

CONFIDENCE_LEVEL_CASES = [
    (c["detector_confidence"], c["is_entropy"], c["is_adjacent"], ConfidenceLevel(c["expected"]), c["id"])
    for c in _FIXTURES["confidence_level_cases"]
]


# =============================================================================
# Test Classes
# =============================================================================


class TestIsSafeValue:
    """Tests for safe value detection."""

    @pytest.mark.parametrize(
        ("value", "expected_safe", "desc"),
        SAFE_VALUE_CASES,
        ids=[c[2] for c in SAFE_VALUE_CASES],
    )
    def test_is_safe_value(self, value: str, expected_safe: bool, desc: str) -> None:
        """Test safe value detection."""
        result = is_safe_value(value)
        assert result is expected_safe, (
            f"{desc}: '{value}' should be {'safe' if expected_safe else 'not safe'}"
        )


class TestDomainSafeValues:
    """Tests for domain-specific safe value patterns (loaded from JSON)."""

    @pytest.fixture
    def network_device_patterns(self) -> list[re.Pattern[str]]:
        """Load compiled patterns from the network-device domain file."""
        from har_capture.patterns.loader import (
            compile_safe_value_patterns,
            load_sensitive_patterns,
            resolve_patterns_arg,
        )

        path = resolve_patterns_arg("network-device")
        sensitive = load_sensitive_patterns(str(path))
        return compile_safe_value_patterns(sensitive)

    @pytest.mark.parametrize(
        ("value", "desc"),
        DOMAIN_SAFE_VALUE_CASES,
        ids=[c[1] for c in DOMAIN_SAFE_VALUE_CASES],
    )
    def test_safe_with_domain_patterns(
        self,
        value: str,
        desc: str,
        network_device_patterns: list[re.Pattern[str]],
    ) -> None:
        """Domain-specific values are safe when domain patterns are loaded."""
        assert is_safe_value(value, extra_patterns=network_device_patterns), (
            f"{desc}: '{value}' should be safe with network-device patterns"
        )

    @pytest.mark.parametrize(
        ("value", "desc"),
        [
            c
            for c in DOMAIN_SAFE_VALUE_CASES
            if c[0]
            not in {
                # These incidentally match core patterns (version string, IPv6 hex:colon)
                "2.4g",
                "36:40:44:48:149:153:157:161:165:",
            }
        ],
        ids=[
            c[1]
            for c in DOMAIN_SAFE_VALUE_CASES
            if c[0]
            not in {
                "2.4g",
                "36:40:44:48:149:153:157:161:165:",
            }
        ],
    )
    def test_not_safe_without_domain_patterns(self, value: str, desc: str) -> None:
        """Domain-specific values are NOT safe without domain patterns."""
        assert not is_safe_value(value), f"{desc}: '{value}' should NOT be safe without domain patterns"


class TestRunDetector:
    """Tests for data-driven heuristic detectors loaded from domain files."""

    @pytest.fixture
    def network_detectors(self) -> list[CompiledDetector]:
        """Load compiled detectors from the network-device domain file."""
        from har_capture.patterns.loader import load_sensitive_patterns, resolve_patterns_arg

        path = resolve_patterns_arg("network-device")
        sensitive = load_sensitive_patterns(str(path))
        return compile_detectors(sensitive)

    @pytest.fixture
    def ssid_detector(self, network_detectors: list[CompiledDetector]) -> CompiledDetector:
        """Get the wifi_ssid detector."""
        return next(d for d in network_detectors if d.category == "wifi_ssid")

    @pytest.fixture
    def device_detector(self, network_detectors: list[CompiledDetector]) -> CompiledDetector:
        """Get the device_name detector."""
        return next(d for d in network_detectors if d.category == "device_name")

    @pytest.mark.parametrize(
        ("value", "expected_match", "desc"),
        SSID_LIKE_CASES,
        ids=[c[2] for c in SSID_LIKE_CASES],
    )
    def test_ssid_detector(
        self,
        value: str,
        expected_match: bool,
        desc: str,
        ssid_detector: CompiledDetector,
    ) -> None:
        """Test SSID detection via data-driven detector."""
        matched, reason = run_detector(value, ssid_detector)
        assert matched is expected_match, (
            f"{desc}: '{value}' should {'match' if expected_match else 'not match'} SSID detector"
        )
        if matched:
            assert reason, "Matched values should have a reason"

    @pytest.mark.parametrize(
        ("value", "expected_match", "desc"),
        DEVICE_NAME_LIKE_CASES,
        ids=[c[2] for c in DEVICE_NAME_LIKE_CASES],
    )
    def test_device_name_detector(
        self,
        value: str,
        expected_match: bool,
        desc: str,
        device_detector: CompiledDetector,
    ) -> None:
        """Test device name detection via data-driven detector."""
        matched, reason = run_detector(value, device_detector)
        assert matched is expected_match, (
            f"{desc}: '{value}' should {'match' if expected_match else 'not match'} device detector"
        )
        if matched:
            assert reason, "Matched values should have a reason"


class TestIsCredentialLike:
    """Tests for credential-prefix detection."""

    @pytest.mark.parametrize(
        ("value", "expected_cred", "desc"),
        CREDENTIAL_LIKE_CASES,
        ids=[c[2] for c in CREDENTIAL_LIKE_CASES],
    )
    def test_is_credential_like(self, value: str, expected_cred: bool, desc: str) -> None:
        """Test credential-like detection."""
        is_cred, reason = is_credential_like(value)
        assert is_cred is expected_cred, (
            f"{desc}: '{value}' should {'be' if expected_cred else 'not be'} credential-like"
        )
        if is_cred:
            assert reason, "Credential-like values should have a reason"


class TestIsHighEntropy:
    """Tests for high entropy detection."""

    @pytest.mark.parametrize(
        ("value", "expected_high", "desc"),
        HIGH_ENTROPY_CASES,
        ids=[c[2] for c in HIGH_ENTROPY_CASES],
    )
    def test_is_high_entropy(self, value: str, expected_high: bool, desc: str) -> None:
        """Test high entropy detection."""
        is_high, reason = is_high_entropy(value)
        assert is_high is expected_high, (
            f"{desc}: '{value}' should {'have' if expected_high else 'not have'} high entropy"
        )
        if is_high:
            assert reason, "High entropy values should have a reason"

    def test_entropy_calculation(self) -> None:
        """Test entropy calculation returns reasonable values."""
        # Uniform distribution (high entropy)
        high_entropy = calculate_entropy("aB1!cD2@eF3#")
        # Repeated chars (low entropy)
        low_entropy = calculate_entropy("aaaaaaaaaa")

        assert high_entropy > low_entropy
        assert low_entropy >= 0
        assert high_entropy <= 6  # Max entropy for ~100 ASCII chars

    def test_entropy_of_empty_string_is_zero(self) -> None:
        """An empty string has no randomness and must not divide by zero."""
        assert calculate_entropy("") == 0.0


class TestIsAdjacentToRedacted:
    """Tests for adjacency to redacted values."""

    @pytest.mark.parametrize(
        ("values", "index", "expected_adjacent", "desc"),
        ADJACENT_TO_REDACTED_CASES,
        ids=[c[3] for c in ADJACENT_TO_REDACTED_CASES],
    )
    def test_is_adjacent_to_redacted(
        self, values: list[str], index: int, expected_adjacent: bool, desc: str
    ) -> None:
        """Test adjacency detection."""
        is_adjacent, reason = is_adjacent_to_redacted(values, index)
        assert is_adjacent is expected_adjacent, f"{desc}: index {index} in {values}"
        if is_adjacent:
            assert reason, "Adjacent values should have a reason"


class TestAnalyzeValue:
    """Tests for the main analyze_value function."""

    @pytest.fixture
    def network_detectors(self) -> list[CompiledDetector]:
        """Load compiled detectors from the network-device domain file."""
        from har_capture.patterns.loader import load_sensitive_patterns, resolve_patterns_arg

        path = resolve_patterns_arg("network-device")
        sensitive = load_sensitive_patterns(str(path))
        return compile_detectors(sensitive)

    @pytest.mark.parametrize(
        ("value", "values_context", "value_index", "should_flag", "expected_category", "desc"),
        ANALYZE_VALUE_CORE_CASES,
        ids=[c[5] for c in ANALYZE_VALUE_CORE_CASES],
    )
    def test_analyze_value_core(
        self,
        value: str,
        values_context: list[str] | None,
        value_index: int | None,
        should_flag: bool,
        expected_category: str,
        desc: str,
    ) -> None:
        """Test analyze_value with core heuristics only (no detectors)."""
        flagged, _confidence, category, reason = analyze_value(value, values_context, value_index)
        assert flagged is should_flag, f"{desc}: '{value}' should {'be' if should_flag else 'not be'} flagged"
        if should_flag:
            assert category == expected_category, (
                f"{desc}: expected category '{expected_category}', got '{category}'"
            )
            assert reason, "Flagged values should have a reason"

    @pytest.mark.parametrize(
        ("value", "values_context", "value_index", "should_flag", "expected_category", "desc"),
        ANALYZE_VALUE_DETECTOR_CASES,
        ids=[c[5] for c in ANALYZE_VALUE_DETECTOR_CASES],
    )
    def test_analyze_value_with_detectors(
        self,
        value: str,
        values_context: list[str] | None,
        value_index: int | None,
        should_flag: bool,
        expected_category: str,
        desc: str,
        network_detectors: list[CompiledDetector],
    ) -> None:
        """Test analyze_value with domain detectors loaded."""
        flagged, _confidence, category, reason = analyze_value(
            value,
            values_context,
            value_index,
            compiled_detectors=network_detectors,
        )
        assert flagged is should_flag, f"{desc}: '{value}' should {'be' if should_flag else 'not be'} flagged"
        if should_flag:
            assert category == expected_category, (
                f"{desc}: expected category '{expected_category}', got '{category}'"
            )
            assert reason, "Flagged values should have a reason"

    @pytest.mark.parametrize(
        ("value", "with_cat", "without_cat", "desc"),
        ANALYZE_VALUE_NO_DETECTOR_CATEGORY_CASES,
        ids=[c[3] for c in ANALYZE_VALUE_NO_DETECTOR_CATEGORY_CASES],
    )
    def test_analyze_value_category_changes_without_detectors(
        self,
        value: str,
        with_cat: str,
        without_cat: str,
        desc: str,
        network_detectors: list[CompiledDetector],
    ) -> None:
        """Without detectors, domain values are categorized differently (entropy, not SSID/device)."""
        # With detectors: domain-specific category
        _, _, cat_with, _ = analyze_value(value, compiled_detectors=network_detectors)
        assert cat_with == with_cat, f"{desc}: with detectors expected '{with_cat}', got '{cat_with}'"

        # Without detectors: falls back to entropy/credential
        _, _, cat_without, _ = analyze_value(value)
        assert cat_without == without_cat, (
            f"{desc}: without detectors expected '{without_cat}', got '{cat_without}'"
        )


class TestGetConfidenceForValue:
    """Tests for confidence level determination."""

    @pytest.mark.parametrize(
        ("detector_confidence", "is_entropy", "is_adjacent", "expected", "desc"),
        CONFIDENCE_LEVEL_CASES,
        ids=[c[4] for c in CONFIDENCE_LEVEL_CASES],
    )
    def test_get_confidence_for_value(
        self,
        detector_confidence: str | None,
        is_entropy: bool,
        is_adjacent: bool,
        expected: ConfidenceLevel,
        desc: str,
    ) -> None:
        """Test confidence level determination."""
        result = get_confidence_for_value(
            "test-value",
            detector_confidence=detector_confidence,
            is_entropy=is_entropy,
            is_adjacent=is_adjacent,
        )
        assert result == expected

    def test_unknown_detector_confidence_falls_back_to_medium(self) -> None:
        """A domain file naming a confidence we don't ship must not raise.

        Detector confidence comes from user-supplied JSON, so an unrecognized
        string is contributor input, not a bug — degrade instead of crashing.
        """
        result = get_confidence_for_value(
            "test-value",
            detector_confidence="catastrophic",
            is_entropy=False,
            is_adjacent=False,
        )
        assert result == ConfidenceLevel.MEDIUM


class TestRegexDoSPrevention:
    """Tests for ReDoS prevention in heuristics."""

    @pytest.fixture
    def ssid_detector(self) -> CompiledDetector:
        """Load the wifi_ssid detector from network-device domain."""
        from har_capture.patterns.loader import load_sensitive_patterns, resolve_patterns_arg

        path = resolve_patterns_arg("network-device")
        sensitive = load_sensitive_patterns(str(path))
        detectors = compile_detectors(sensitive)
        return next(d for d in detectors if d.category == "wifi_ssid")

    def test_long_string_doesnt_cause_redos(self, ssid_detector: CompiledDetector) -> None:
        """Test that long strings don't cause catastrophic backtracking."""
        import time

        # This would cause catastrophic backtracking without length check
        malicious_input = "A" + "-" * 1000 + "!"

        start = time.time()
        result, _reason = run_detector(malicious_input, ssid_detector)
        elapsed = time.time() - start

        # Should be fast (< 0.1s) and return False (too long)
        assert elapsed < 0.1, f"Took {elapsed}s, should be < 0.1s"
        assert result is False, "Should reject very long strings"

    @pytest.mark.parametrize(
        ("value", "description"),
        [
            ("A" * 33, "over_wifi_standard_32_chars"),
            ("A" * 150, "very_long_150_chars"),
        ],
    )
    def test_ssid_length_limit_enforced(
        self,
        value: str,
        description: str,
        ssid_detector: CompiledDetector,
    ) -> None:
        """Test that detector length limit is enforced."""
        result, _ = run_detector(value, ssid_detector)
        assert result is False, f"{description}: should be rejected"


class TestEntropyThresholds:
    """Tests for entropy threshold adjustments."""

    @pytest.mark.parametrize(
        ("value", "description"),
        [
            ("module99", "lowercase_digit_entropy_2.75"),
            ("hello123", "lowercase_digit_entropy_2.75"),
            ("testcase", "lowercase_only_low_entropy"),
            ("config11", "lowercase_digit_repeating_chars"),
        ],
    )
    def test_entropy_false_positives_not_flagged(self, value: str, description: str) -> None:
        """Test that legitimate technical strings aren't flagged."""
        result, _reason = is_high_entropy(value)
        assert result is False, f"'{value}' should not be flagged as high entropy"

    @pytest.mark.parametrize(
        ("value", "description"),
        [
            ("P@ssw0rd!", "classic_password_with_special"),
            ("MyS3cur3Pass", "mixed_case_numbers"),
            ("admin#2024", "special_numbers"),
            ("Test123!@#", "multiple_character_types"),
        ],
    )
    def test_entropy_true_positives_still_caught(self, value: str, description: str) -> None:
        """Test that real passwords are still caught."""
        result, _reason = is_high_entropy(value)
        assert result is True, f"'{value}' should be flagged as high entropy"

    @pytest.mark.parametrize(
        ("value", "expected", "description"),
        [
            ("hello123", False, "low_entropy_2_char_types"),
            ("Password1!", True, "4_char_types_moderate_entropy"),
        ],
    )
    def test_entropy_threshold_2_8(self, value: str, expected: bool, description: str) -> None:
        """Test that entropy threshold of 2.8 is being used."""
        result, _ = is_high_entropy(value)
        assert result is expected, description

    @pytest.mark.parametrize(
        ("value", "expected", "description"),
        [
            ("P@ss1", False, "too_short_under_8_chars"),
            ("A1@" * 30, False, "too_long_over_64_chars"),
            ("P@ssw0rd123", True, "valid_length_8_to_64_chars"),
        ],
    )
    def test_entropy_length_bounds(self, value: str, expected: bool, description: str) -> None:
        """Test that entropy checks respect length bounds."""
        result, _ = is_high_entropy(value)
        assert result is expected, description
