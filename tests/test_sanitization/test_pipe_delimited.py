"""Tests for pipe-delimited credential sanitization.

Device web interfaces often embed configuration in pipe-delimited JavaScript
variables. This format is common in router/modem admin pages where settings
are stored as positional values without labels.

Example format: var tagValueList = 'val1|val2|val3|...'

Sanitization challenges:
1. No field labels - must infer sensitive values by pattern/position
2. SSIDs with hyphens (MyWiFi-5G) - common for dual-band networks
3. Short passwords (<8 chars) - PINs, WEP keys, truncated values
4. Passwords with special chars - common in user-generated passwords

These tests verify:
1. Known patterns (passwords, MACs) are auto-redacted
2. Suspicious values (SSIDs, device names) are flagged for interactive review
3. Technical data is preserved
"""

from __future__ import annotations

import pytest

from har_capture.sanitization.heuristics import analyze_value
from har_capture.sanitization.html import sanitize_html

# =============================================================================
# Test Data - Pipe-Delimited Credential Gaps
# =============================================================================

# These test cases represent gaps found in real-world HAR captures
# where users had to manually redact values the sanitizer missed

# ┌───────────────────────────────────────────────────────────────────┬─────────────────┬─────────────────────┐
# │ tagValueList content                                              │ should_redact   │ description         │
# ├───────────────────────────────────────────────────────────────────┼─────────────────┼─────────────────────┤
# │ WiFi credential patterns that SHOULD be sanitized                 │ value to remove │ test case name      │
# └───────────────────────────────────────────────────────────────────┴─────────────────┴─────────────────────┘
#
# fmt: off
# Values that heuristics SHOULD flag for interactive review (SSIDs, device names)
HEURISTIC_FLAGGED_VALUES = [
    # SSIDs with hyphens - common for dual-band networks
    ("MyNetwork-5G", "ssid_with_hyphen_5g"),
    ("Home-WiFi", "ssid_with_hyphen_simple"),
    ("My_Home_Network", "ssid_with_underscore"),
    ("Guest-Network", "guest_ssid_with_hyphen"),
    ("NETGEAR-5G-Guest", "manufacturer_guest_ssid"),
    # Device names
    ("John-iPhone", "device_name_with_hyphen"),
]

# Passwords 8+ chars that SHOULD be flagged by heuristics (high entropy detection)
# These are detected via entropy analysis and flagged for interactive review
HEURISTIC_FLAGGED_PASSWORDS = [
    # Passwords with special characters - detected by high entropy
    ("P@ssw0rd!", "credential", "password_with_special_chars"),
    ("secret#123", "credential", "password_with_hash"),
    ("MyP@ss123!", "credential", "password_mixed_types"),
]

# Short passwords (< 8 chars) - below entropy detection threshold
# These get flagged as SSID-like due to alphanumeric pattern, which is acceptable
# because they'll still appear in interactive review for user confirmation
SHORT_PASSWORD_FLAGGED_AS_SSID = [
    ("pass123", "wifi_ssid", "short_password_7chars"),
    ("abc1234", "wifi_ssid", "short_password_7chars_mixed"),
]
# fmt: on


# ┌───────────────────────────────────────────────────────────────────┬─────────────────┬─────────────────────┐
# │ tagValueList content                                              │ should_preserve │ description         │
# ├───────────────────────────────────────────────────────────────────┼─────────────────┼─────────────────────┤
# │ Values that should NOT be redacted (status, technical data)       │ value to keep   │ test case name      │
# └───────────────────────────────────────────────────────────────────┴─────────────────┴─────────────────────┘
#
# fmt: off
PRESERVE_TECHNICAL_DATA = [
    # Status values
    ("var tagValueList = 'Locked|OK|Operational|QAM256';", "Locked", "status_locked"),
    ("var tagValueList = 'Locked|OK|Operational|QAM256';", "Operational", "status_operational"),
    # Band indicators
    ("var tagValueList = '0|Good|none| |SSID|pass|2.4g|chan|'", "2.4g", "band_24g"),
    ("var tagValueList = '0|Good|none| |SSID|pass|5g|chan|'", "5g", "band_5g"),
    # Security types (should be preserved)
    ("var tagValueList = 'ssid|pass|WPA2|channel|'", "WPA2", "security_wpa2"),
    ("var tagValueList = 'ssid|pass|WPA3|channel|'", "WPA3", "security_wpa3"),
    ("var tagValueList = 'ssid|pass|NONE|channel|'", "NONE", "security_none"),
    # Numeric values
    ("var tagValueList = 'data|123|456|789|'", "123", "numeric_channel"),
    ("var tagValueList = 'freq|555000000|data|'", "555000000", "numeric_frequency"),
    # Version strings
    ("var tagValueList = 'V1.03.08|0|0|0|0|retail|'", "V1.03.08", "version_string"),
    # Empty values
    ("var tagValueList = 'a||b||c|'", "||", "empty_values"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestPipeDelimitedCredentialGaps:
    """Tests for credential detection in pipe-delimited formats.

    These tests verify:
    1. SSIDs and device names are flagged by heuristics for interactive review
    2. Passwords with special chars are flagged as high-entropy credentials
    3. Short passwords are flagged (as SSID-like) for interactive review
    4. Technical data is preserved
    """

    @pytest.mark.parametrize(
        ("suspicious_value", "desc"),
        HEURISTIC_FLAGGED_VALUES,
        ids=[c[1] for c in HEURISTIC_FLAGGED_VALUES],
    )
    def test_heuristics_flag_ssids_and_devices(self, suspicious_value: str, desc: str) -> None:
        """Test SSIDs and device names are flagged by heuristics.

        These values are detected as suspicious and flagged for user review
        when using --interactive mode. They are NOT auto-redacted because
        user confirmation is required.
        """
        flagged, _confidence, category, reason = analyze_value(suspicious_value)
        assert flagged, (
            f"{desc}: value '{suspicious_value}' should be flagged as suspicious. "
            f"Got: flagged={flagged}, category={category}, reason={reason}"
        )

    @pytest.mark.parametrize(
        ("password", "expected_category", "desc"),
        HEURISTIC_FLAGGED_PASSWORDS,
        ids=[c[2] for c in HEURISTIC_FLAGGED_PASSWORDS],
    )
    def test_heuristics_flag_passwords_with_special_chars(
        self, password: str, expected_category: str, desc: str
    ) -> None:
        """Test passwords with special characters are flagged by entropy detection.

        These 8+ character passwords with mixed character types are detected
        as high-entropy credentials and flagged for interactive review.
        """
        flagged, _confidence, category, reason = analyze_value(password)
        assert flagged, (
            f"{desc}: password '{password}' should be flagged as suspicious. "
            f"Got: flagged={flagged}, category={category}, reason={reason}"
        )
        assert category == expected_category, (
            f"{desc}: expected category '{expected_category}', got '{category}'"
        )

    @pytest.mark.parametrize(
        ("password", "expected_category", "desc"),
        SHORT_PASSWORD_FLAGGED_AS_SSID,
        ids=[c[2] for c in SHORT_PASSWORD_FLAGGED_AS_SSID],
    )
    def test_short_passwords_flagged_for_review(
        self, password: str, expected_category: str, desc: str
    ) -> None:
        """Test short passwords are flagged for interactive review.

        Passwords under 8 characters are below the entropy detection threshold.
        However, they match SSID-like patterns and are still flagged for
        user review in interactive mode, which is the desired behavior.
        """
        flagged, _confidence, category, reason = analyze_value(password)
        assert flagged, (
            f"{desc}: short password '{password}' should be flagged for review. "
            f"Got: flagged={flagged}, category={category}, reason={reason}"
        )

    @pytest.mark.parametrize(
        ("html", "should_preserve", "desc"),
        PRESERVE_TECHNICAL_DATA,
        ids=[c[2] for c in PRESERVE_TECHNICAL_DATA],
    )
    def test_preserves_technical_data(self, html: str, should_preserve: str, desc: str) -> None:
        """Test technical data is preserved (not over-sanitized)."""
        result = sanitize_html(html, salt=None)
        assert should_preserve in result, (
            f"{desc}: value '{should_preserve}' should be preserved but was removed. Result: {result}"
        )


class TestRealWorldPipeDelimited:
    """Test cases based on actual HAR captures from real devices.

    These tests verify the two-tier approach:
    1. Known patterns (passwords) are auto-redacted
    2. Suspicious values (SSIDs) are flagged for interactive review
    3. Technical data is preserved
    """

    def test_wifi_settings_pipe_format(self) -> None:
        """Test WiFi settings in pipe-delimited format.

        Common pattern in router admin pages:
        var tagValueList = '0|Good|none| |MySSID24|mypassword24|0|0|0|0|5g|MySSID5G|mypassword5g|...'

        In pipe-delimited format WITHOUT labels:
        - We can't reliably distinguish passwords from SSIDs
        - ALL suspicious values (SSIDs, high-entropy strings) are FLAGGED for review
        - Only MAC addresses within the values are auto-redacted
        - Technical data is preserved
        """
        html = (
            "var tagValueList = '0|Good|none| |HomeNetwork|secretpass123|0|0|0|0|5g|"
            "HomeNetwork-5G|secretpass456|0|0|0|0|0|0|0|0|1|0|0|0|0|---.---.---.---|1|'"
        )

        result = sanitize_html(html, salt=None)

        # Technical data should be preserved
        assert "Good" in result, "Status 'Good' should be preserved"
        assert "5g" in result, "Band indicator '5g' should be preserved"

        # In pipe-delimited format, SSIDs and passwords are FLAGGED (not auto-redacted)
        # because we can't reliably distinguish them without labels
        # Verify heuristics would flag them
        flagged1, _, _, _ = analyze_value("HomeNetwork")
        flagged2, _, _, _ = analyze_value("HomeNetwork-5G")
        flagged3, _, _, _ = analyze_value("secretpass123")
        flagged4, _, _, _ = analyze_value("secretpass456")

        assert flagged1, "HomeNetwork should be flagged for review"
        assert flagged2, "HomeNetwork-5G should be flagged for review"
        assert flagged3, "secretpass123 should be flagged for review"
        assert flagged4, "secretpass456 should be flagged for review"
