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

import pytest

from har_capture.sanitization.heuristics import (
    analyze_value,
    calculate_entropy,
    get_confidence_for_value,
    is_adjacent_to_redacted,
    is_credential_like,
    is_device_name_like,
    is_high_entropy,
    is_safe_value,
    is_ssid_like,
)
from har_capture.sanitization.report import ConfidenceLevel

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
SAFE_VALUE_CASES = [
    # (value, is_safe, description)
    # Status values
    ("Good", True, "status_good"),
    ("Bad", True, "status_bad"),
    ("OK", True, "status_ok"),
    ("Error", True, "status_error"),
    ("Connected", True, "status_connected"),
    ("Disconnected", True, "status_disconnected"),
    ("Active", True, "status_active"),
    ("Inactive", True, "status_inactive"),
    ("Online", True, "status_online"),
    ("Offline", True, "status_offline"),
    ("Up", True, "status_up"),
    ("Down", True, "status_down"),
    # Band indicators
    ("2.4g", True, "band_2.4g"),
    ("5g", True, "band_5g"),
    ("6g", True, "band_6g"),
    ("2.4GHz", True, "band_2.4ghz"),
    ("5GHz", True, "band_5ghz"),
    # Security types
    ("WPA", True, "security_wpa"),
    ("WPA2", True, "security_wpa2"),
    ("WPA3", True, "security_wpa3"),
    ("WEP", True, "security_wep"),
    ("NONE", True, "security_none"),
    ("Open", True, "security_open"),
    ("WPA2-PSK", True, "security_wpa2psk"),
    # Numeric values
    ("123", True, "numeric_channel"),
    ("0", True, "numeric_zero"),
    ("11", True, "numeric_channel_11"),
    # dB values
    ("-70dBm", True, "dbm_value"),
    ("50dB", True, "db_value"),
    # Version strings
    ("1.0", True, "version_1.0"),
    ("2.3.4", True, "version_semantic"),
    ("v1.2.3", True, "version_prefixed"),
    ("V2.0", True, "version_cap_prefixed"),
    # Empty/placeholder
    ("---", True, "placeholder_dashes"),
    ("none", True, "placeholder_none"),
    ("null", True, "placeholder_null"),
    ("N/A", True, "placeholder_na"),
    ("-", True, "placeholder_single_dash"),
    # Boolean
    ("true", True, "bool_true"),
    ("false", True, "bool_false"),
    ("yes", True, "bool_yes"),
    ("no", True, "bool_no"),
    # Time/date
    ("12:30", True, "time_format"),
    ("2024-01-15", True, "date_format"),
    # Percentage
    ("85%", True, "percentage"),
    # Signal strength
    ("Excellent", True, "signal_excellent"),
    ("Good", True, "signal_good"),
    ("Fair", True, "signal_fair"),
    ("Poor", True, "signal_poor"),
    # Already redacted
    ("***MAC***", True, "already_redacted_stars"),
    ("MAC_a1b2c3d4", True, "already_redacted_hash"),
    ("XX:XX:XX:XX:XX:XX", True, "already_redacted_mac"),
    ("0.0.0.0", True, "already_redacted_ip_zero"),
    ("10.255.1.2", True, "already_redacted_ip_rfc5737"),
    ("192.0.2.123", True, "already_redacted_documentation_ip"),
    # Interface names
    ("eth0", True, "interface_eth0"),
    ("wlan0", True, "interface_wlan0"),
    ("lo", True, "interface_lo"),
    ("br0", True, "interface_br0"),
    ("lan", True, "interface_lan"),
    ("wan", True, "interface_wan"),
    # Empty
    ("", True, "empty_string"),
    ("  ", True, "whitespace_only"),
    # Common plan/tier/role words (new)
    ("premium", True, "safe_plan_premium"),
    ("admin", True, "safe_role_admin"),
    ("guest", True, "safe_role_guest"),
    ("default", True, "safe_role_default"),
    ("retail", True, "safe_category_retail"),
    ("primary", True, "safe_category_primary"),
    # Already-redacted values with prefixes (new)
    ("SN: SERIAL_0ad826ed", True, "safe_redacted_serial_with_prefix"),
    ("user_70a438cb@redacted.invalid", True, "safe_redacted_email"),
    # Values that should NOT be safe (will fail - flagged as suspicious)
    ("HomeNetwork-5G", False, "ssid_like_not_safe"),
    ("Johns-iPhone", False, "device_name_not_safe"),
    ("secretpass123", False, "password_like_not_safe"),
    ("MyWifi", False, "short_ssid_not_safe"),
]

SSID_LIKE_CASES = [
    # (value, is_ssid_like, description)
    # Should be detected as SSID-like
    ("HomeNetwork-5G", True, "ends_with_5g"),
    ("MyWifi-2.4g", True, "ends_with_2.4g"),
    ("GuestNetwork-guest", True, "ends_with_guest"),
    ("WiFi-ext", True, "ends_with_ext"),
    ("home-network", True, "starts_with_home"),
    ("office-wifi", True, "contains_wifi"),
    ("guest-network", True, "starts_with_guest"),
    ("Network-123", True, "name_number_pattern"),
    ("MyRouter", True, "camelcase_ssid"),
    ("FamilyWiFi", True, "camelcase_ssid_multi"),
    ("HomeNetwork", True, "camelcase_no_separator"),
    # Should NOT be detected as SSID-like (false positives fixed)
    ("AB", False, "too_short"),
    ("123456", False, "numeric_only"),
    ("", False, "empty"),
    ("a" * 35, False, "too_long"),
    ("admin", False, "common_word_not_ssid"),
    ("premium", False, "plan_tier_not_ssid"),
    ("NETGEAR-C7000", False, "device_model_not_ssid"),
    ("enabled", False, "status_word_not_ssid"),
    ("active", False, "status_word_not_ssid_2"),
    ("retail", False, "category_word_not_ssid"),
]

CREDENTIAL_LIKE_CASES = [
    # (value, is_credential, description)
    # Should be detected as credential-like
    ("pass123", True, "pass_prefix_digits"),
    ("password42", True, "password_prefix_digits"),
    ("token99", True, "token_prefix_digits"),
    ("key!2024", True, "key_prefix_special"),
    ("secret789", True, "secret_prefix_digits"),
    ("auth42", True, "auth_prefix_digits"),
    ("pwd!123", True, "pwd_prefix_special"),
    # Should NOT be detected
    ("abc1234", False, "no_credential_prefix"),
    ("admin", False, "too_short_no_digits"),
    ("password", False, "no_trailing_digits"),
    ("pass", False, "prefix_only_no_digits"),
    ("", False, "empty"),
]

DEVICE_NAME_LIKE_CASES = [
    # (value, is_device_like, description)
    # Should be detected as device names
    ("John's iPhone", True, "possessive_iphone"),
    ("Mary's MacBook", True, "possessive_macbook"),
    ("Living-Room-TV", True, "room_name_tv"),
    ("Kitchen Tablet", True, "room_tablet"),
    ("iPhone-14", True, "iphone_model"),
    ("Galaxy-S23", True, "galaxy_model"),
    ("Pixel-7", True, "pixel_model"),
    ("MacBook Pro", True, "macbook_pro"),
    ("Android Phone", True, "android_phone"),
    # Router/modem brands (new)
    ("NETGEAR-C7000", True, "netgear_model"),
    ("Linksys-WRT", True, "linksys_model"),
    ("TP-Link Archer", True, "tplink_model"),
    ("ARRIS-SB8200", True, "arris_model"),
    # Should NOT be detected as device names
    ("Good", False, "status_value"),
    ("WPA2", False, "security_type"),
    ("5GHz", False, "band_indicator"),
    ("", False, "empty"),
    ("AB", False, "too_short"),
]

HIGH_ENTROPY_CASES = [
    # (value, is_high_entropy, description)
    # Should be detected as high entropy
    ("aB3$dEf7!gH9", True, "mixed_chars_high_entropy"),
    ("X7y!Z2m@P9q&", True, "password_like"),
    ("Abcd1234!@#$", True, "mixed_case_num_special"),
    # Should NOT be detected as high entropy
    ("aaaaaaaa", False, "repeated_chars"),
    ("12345678", False, "sequential_numbers"),
    ("abcdefgh", False, "sequential_letters"),
    ("short", False, "too_short"),
    ("Good", False, "safe_value"),
    ("", False, "empty"),
]

ADJACENT_TO_REDACTED_CASES = [
    # (values, index, is_adjacent, description)
    (["normal", "MAC_a1b2c3d4", "test"], 0, True, "before_mac_hash"),
    (["test", "MAC_a1b2c3d4", "normal"], 2, True, "after_mac_hash"),
    (["a", "b", "PASS_12345678", "c"], 2, False, "is_the_redacted_value"),
    (["a", "PASS_12345678", "b"], 0, True, "before_pass_hash"),
    (["a", "XX:XX:XX:XX:XX:XX", "b"], 0, True, "before_redacted_mac"),
    (["a", "0.0.0.0", "b"], 2, True, "after_redacted_ip"),
    (["a", "b", "c"], 1, False, "no_redacted_neighbors"),
    (["***TOKEN***", "value"], 1, True, "after_star_redacted"),
    (["only"], 0, False, "single_element"),
]

ANALYZE_VALUE_CASES = [
    # (value, values_context, value_index, should_flag, expected_category, description)
    ("HomeNetwork-5G", None, None, True, "wifi_ssid", "ssid_like_flagged"),
    ("John's MacBook", None, None, True, "device_name", "device_name_flagged"),
    ("pass123", None, None, True, "credential", "credential_prefix_flagged"),
    ("NETGEAR-C7000", None, None, True, "device_name", "router_brand_flagged"),
    ("Good", None, None, False, "", "safe_value_not_flagged"),
    ("WPA2", None, None, False, "", "security_type_not_flagged"),
    ("123", None, None, False, "", "numeric_not_flagged"),
    ("", None, None, False, "", "empty_not_flagged"),
    ("admin", None, None, False, "", "safe_role_not_flagged"),
    ("premium", None, None, False, "", "safe_plan_not_flagged"),
    # With context (adjacency) - note: value "cfg" doesn't match SSID/device patterns
    ("cfg", ["cfg", "MAC_12345678"], 0, True, "suspicious", "adjacent_to_redacted"),
]

CONFIDENCE_LEVEL_CASES = [
    # (is_ssid, is_device, is_entropy, is_adjacent, expected_confidence)
    (True, False, False, True, ConfidenceLevel.HIGH),    # SSID + adjacent = HIGH
    (False, True, False, True, ConfidenceLevel.HIGH),    # Device + adjacent = HIGH
    (False, False, True, True, ConfidenceLevel.HIGH),    # Entropy + adjacent = HIGH
    (True, False, False, False, ConfidenceLevel.MEDIUM), # SSID alone = MEDIUM
    (False, True, False, False, ConfidenceLevel.MEDIUM), # Device alone = MEDIUM
    (False, False, True, False, ConfidenceLevel.MEDIUM), # Entropy alone = MEDIUM
    (False, False, False, True, ConfidenceLevel.LOW),    # Adjacent only = LOW
    (False, False, False, False, ConfidenceLevel.LOW),   # Nothing = LOW
]
# fmt: on


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


class TestIsSSIDLike:
    """Tests for SSID-like pattern detection."""

    @pytest.mark.parametrize(
        ("value", "expected_ssid", "desc"),
        SSID_LIKE_CASES,
        ids=[c[2] for c in SSID_LIKE_CASES],
    )
    def test_is_ssid_like(self, value: str, expected_ssid: bool, desc: str) -> None:
        """Test SSID-like detection."""
        is_ssid, reason = is_ssid_like(value)
        assert is_ssid is expected_ssid, (
            f"{desc}: '{value}' should {'be' if expected_ssid else 'not be'} SSID-like"
        )
        if is_ssid:
            assert reason, "SSID-like values should have a reason"


class TestIsDeviceNameLike:
    """Tests for device name pattern detection."""

    @pytest.mark.parametrize(
        ("value", "expected_device", "desc"),
        DEVICE_NAME_LIKE_CASES,
        ids=[c[2] for c in DEVICE_NAME_LIKE_CASES],
    )
    def test_is_device_name_like(self, value: str, expected_device: bool, desc: str) -> None:
        """Test device name detection."""
        is_device, reason = is_device_name_like(value)
        assert is_device is expected_device, (
            f"{desc}: '{value}' should {'be' if expected_device else 'not be'} device-like"
        )
        if is_device:
            assert reason, "Device-like values should have a reason"


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

    @pytest.mark.parametrize(
        ("value", "values_context", "value_index", "should_flag", "expected_category", "desc"),
        ANALYZE_VALUE_CASES,
        ids=[c[5] for c in ANALYZE_VALUE_CASES],
    )
    def test_analyze_value(
        self,
        value: str,
        values_context: list[str] | None,
        value_index: int | None,
        should_flag: bool,
        expected_category: str,
        desc: str,
    ) -> None:
        """Test analyze_value function."""
        flagged, _confidence, category, reason = analyze_value(value, values_context, value_index)
        assert flagged is should_flag, f"{desc}: '{value}' should {'be' if should_flag else 'not be'} flagged"
        if should_flag:
            assert category == expected_category, (
                f"{desc}: expected category '{expected_category}', got '{category}'"
            )
            assert reason, "Flagged values should have a reason"


class TestGetConfidenceForValue:
    """Tests for confidence level determination."""

    @pytest.mark.parametrize(
        ("is_ssid", "is_device", "is_entropy", "is_adjacent", "expected"),
        CONFIDENCE_LEVEL_CASES,
        ids=[f"ssid{c[0]}_dev{c[1]}_ent{c[2]}_adj{c[3]}_{c[4].value}" for c in CONFIDENCE_LEVEL_CASES],
    )
    def test_get_confidence_for_value(
        self,
        is_ssid: bool,
        is_device: bool,
        is_entropy: bool,
        is_adjacent: bool,
        expected: ConfidenceLevel,
    ) -> None:
        """Test confidence level determination."""
        result = get_confidence_for_value(
            "test-value",
            is_ssid=is_ssid,
            is_device=is_device,
            is_entropy=is_entropy,
            is_adjacent=is_adjacent,
        )
        assert result == expected


class TestRegexDoSPrevention:
    """Tests for ReDoS prevention in heuristics."""

    def test_long_string_doesnt_cause_redos(self) -> None:
        """Test that long strings don't cause catastrophic backtracking."""
        import time

        # This would cause catastrophic backtracking without length check
        malicious_input = "A" + "-" * 1000 + "!"

        start = time.time()
        result, _reason = is_ssid_like(malicious_input)
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
    def test_ssid_length_limit_enforced(self, value: str, description: str) -> None:
        """Test that SSID length limit is enforced."""
        result, _ = is_ssid_like(value)
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
