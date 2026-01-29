"""Tests for HTML sanitization utilities."""

from __future__ import annotations

import pytest

from har_capture.patterns import load_allowlist, load_pii_patterns
from har_capture.sanitization.html import (
    check_for_pii,
    sanitize_html,
)

# =============================================================================
# Test Data Tables
# =============================================================================

# ┌─────────────────────────────────────────┬─────────────────────────┬───────────────────┬─────────────────────┐
# │ input_html                              │ removed                 │ placeholder       │ description         │
# ├─────────────────────────────────────────┼─────────────────────────┼───────────────────┼─────────────────────┤
# │ PII that should be sanitized            │ original value          │ replacement       │ test case name      │
# └─────────────────────────────────────────┴─────────────────────────┴───────────────────┴─────────────────────┘
#
# Note: When salt=None, format-preserving placeholders are used:
# - MAC: XX:XX:XX:XX:XX:XX
# - Private IP: 0.0.0.0
# - Public IP: 0.0.0.0
# - IPv6: ::
# - Email: x@x.invalid
# - Generic: ***{PREFIX}***
#
# fmt: off
SANITIZE_PII_CASES = [
    # MAC addresses
    ("Device MAC: AA:BB:CC:DD:EE:FF",           "AA:BB:CC:DD:EE:FF",     "XX:XX:XX:XX:XX:XX",  "mac_colon_format"),
    ("Device MAC: 11-22-33-44-55-66",           "11-22-33-44-55-66",     "XX:XX:XX:XX:XX:XX",  "mac_dash_format"),
    ("MAC: aa:bb:cc:dd:ee:ff",                  "aa:bb:cc:dd:ee:ff",     "XX:XX:XX:XX:XX:XX",  "mac_lowercase"),
    ("Multiple: AA:BB:CC:DD:EE:FF and 11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", "XX:XX:XX:XX:XX:XX", "mac_multiple"),
    # Serial numbers - uses ***SERIAL*** placeholder
    ("Serial Number: ABC12345678",              "ABC12345678",           "***SERIAL***",       "serial_number"),
    ("SerialNum: XYZ98765432",                  "XYZ98765432",           "***SERIAL***",       "serial_num_variant"),
    ("SN: DEV123456789",                         "DEV123456789",          "***SERIAL***",       "serial_sn_prefix"),
    # IP addresses - private (uses 0.0.0.0 placeholder)
    ("Client: 192.168.100.50",                  "192.168.100.50",        "0.0.0.0",            "private_ip_192"),
    ("Device: 10.0.0.100",                      "10.0.0.100",            "0.0.0.0",            "private_ip_10"),
    ("Host: 172.16.0.50",                       "172.16.0.50",           "0.0.0.0",            "private_ip_172"),
    # IP addresses - public (uses 0.0.0.0 placeholder)
    ("External DNS: 8.8.8.8",                   "8.8.8.8",               "0.0.0.0",            "public_ip_google"),
    ("Server: 1.1.1.1",                         "1.1.1.1",               "0.0.0.0",            "public_ip_cloudflare"),
    ("API: 203.0.113.50",                       "203.0.113.50",          "0.0.0.0",            "public_ip_test_net"),
    # IPv6 addresses (uses :: placeholder)
    ("IPv6: 2001:db8::1",                       "2001:db8::1",           "::",                 "ipv6_compressed"),
    ("IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::", "ipv6_full"),
    ("Localhost: ::1",                          "::1",                   "::",                 "ipv6_localhost"),
    # Passwords - uses ***PASS*** placeholder
    ("password=secret123",                      "secret123",             "***PASS***",         "password_equals"),
    ("passphrase: mysecretphrase",              "mysecretphrase",        "***PASS***",         "passphrase"),
    ("psk=wireless_key_here",                   "wireless_key_here",     "***PASS***",         "psk_wireless"),
    # Email addresses (uses x@x.invalid placeholder)
    ("Contact: admin@example.com",              "admin@example.com",     "x@x.invalid",        "email_simple"),
    ("Email: user.name+tag@domain.co.uk",       "user.name+tag@domain.co.uk", "x@x.invalid",   "email_complex"),
    # Config paths - uses ***CONFIG*** placeholder
    ("Config File Name: customer123.cfg",       "customer123.cfg",       "***CONFIG***",       "config_path"),
    ("config file: isp_settings.cfg",           "isp_settings.cfg",      "***CONFIG***",       "config_lowercase"),
    # WiFi credentials in tagValueList - uses ***WIFI*** placeholder
    ("var tagValueList = '0|Good||happymango167|test';", "happymango167", "***WIFI***",        "wifi_credential"),
    ("var tagValueList = 'status|MySecretWiFi123|data';", "MySecretWiFi123", "***WIFI***",     "wifi_ssid_like"),
]
# fmt: on

# ┌─────────────────────────────────────────┬─────────────────────────┬─────────────────────┐
# │ input_html                              │ preserved               │ description         │
# ├─────────────────────────────────────────┼─────────────────────────┼─────────────────────┤
# │ Content that should NOT be sanitized    │ value to preserve       │ test case name      │
# └─────────────────────────────────────────┴─────────────────────────┴─────────────────────┘
#
# fmt: off
PRESERVE_CASES = [
    # Gateway IPs (common router addresses - should be in preserved_gateway_ips)
    ("Gateway: 192.168.100.1",                  "192.168.100.1",         "gateway_192_168_100_1"),
    ("Router: 192.168.1.1",                     "192.168.1.1",           "gateway_192_168_1_1"),
    ("Gateway: 192.168.0.1",                    "192.168.0.1",           "gateway_192_168_0_1"),
    # Time formats (should not match IPv6)
    ("Uptime: 12:34:56",                        "12:34:56",              "time_format_hhmmss"),
    ("Duration: 01:23:45",                      "01:23:45",              "time_format_short"),
    ("Time: 00:00:00",                          "00:00:00",              "time_format_midnight"),
    # Signal metrics
    ("Power: 7.5 dBmV SNR: 38.2 dB",            "7.5 dBmV",              "signal_dbmv"),
    ("Power: 7.5 dBmV SNR: 38.2 dB",            "38.2 dB",               "signal_db"),
    ("Frequency: 602.0 MHz",                    "602.0 MHz",             "frequency_mhz"),
    # Status values in tagValueList
    ("var tagValueList = 'Locked|OK|Operational|QAM256';", "Locked",     "status_locked"),
    ("var tagValueList = 'Locked|OK|Operational|QAM256';", "OK",         "status_ok"),
    ("var tagValueList = 'Locked|OK|Operational|QAM256';", "QAM256",     "status_qam"),
    # Numeric values
    ("Channel: 123",                            "123",                   "numeric_channel"),
    ("Version: 1.0.0",                          "1.0.0",                 "version_string"),
]
# fmt: on

# ┌─────────────────────────────────────────┬─────────────────┬─────────────────────┐
# │ content                                 │ pattern_name    │ description         │
# ├─────────────────────────────────────────┼─────────────────┼─────────────────────┤
# │ Content with PII to detect              │ expected pattern│ test case name      │
# └─────────────────────────────────────────┴─────────────────┴─────────────────────┘
#
# fmt: off
PII_DETECTION_CASES = [
    ("Device MAC: DE:AD:BE:EF:CA:FE",           "mac_address",   "DE:AD:BE:EF:CA:FE",  "mac_detect"),
    ("MAC: 11-22-33-44-55-66",                  "mac_address",   "11-22-33-44-55-66",  "mac_dash_detect"),
    ("Contact: admin@example.com",              "email",         "admin@example.com",  "email_detect"),
    ("DNS: 8.8.8.8",                            "public_ip",     "8.8.8.8",            "public_ip_detect"),
]
# fmt: on

# ┌─────────────────────────────────────────┬─────────────────────┐
# │ content                                 │ description         │
# ├─────────────────────────────────────────┼─────────────────────┤
# │ Allowlisted content (no findings)       │ test case name      │
# └─────────────────────────────────────────┴─────────────────────┘
#
# fmt: off
ALLOWLISTED_CASES = [
    # Static placeholders from allowlist.json
    ("MAC: XX:XX:XX:XX:XX:XX",                  "placeholder_mac"),
    ("IP: 0.0.0.0",                             "placeholder_ip_zero"),
    ("IPv6: ::",                                "placeholder_ipv6_empty"),
    ("Email: x@x.invalid",                      "placeholder_email"),
    ("Value: [REDACTED]",                       "placeholder_redacted"),
    # Non-PII content
    ("Power: 7.5 dBmV",                         "signal_metric"),
    ("Status: OK",                              "status_value"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestSanitizeHtml:
    """Tests for sanitize_html function."""

    @pytest.mark.parametrize(
        ("html", "removed", "placeholder", "desc"),
        SANITIZE_PII_CASES,
        ids=[c[3] for c in SANITIZE_PII_CASES],
    )
    def test_sanitizes_pii(self, html: str, removed: str, placeholder: str, desc: str) -> None:
        """Test PII is properly sanitized."""
        result = sanitize_html(html, salt=None)
        assert removed not in result, f"{desc}: original value '{removed}' should be removed"
        assert placeholder in result, f"{desc}: placeholder '{placeholder}' should be present"

    @pytest.mark.parametrize(
        ("html", "preserved", "desc"),
        PRESERVE_CASES,
        ids=[c[2] for c in PRESERVE_CASES],
    )
    def test_preserves_safe_values(self, html: str, preserved: str, desc: str) -> None:
        """Test safe values are preserved."""
        result = sanitize_html(html, salt=None)
        assert preserved in result, f"{desc}: value '{preserved}' should be preserved"

    def test_salt_produces_consistent_hashes(self) -> None:
        """Test same salt produces same hash for same input."""
        html = "MAC: AA:BB:CC:DD:EE:FF"
        result1 = sanitize_html(html, salt="test-salt")
        result2 = sanitize_html(html, salt="test-salt")
        assert result1 == result2

    def test_different_salts_produce_different_hashes(self) -> None:
        """Test different salts produce different hashes."""
        html = "MAC: AA:BB:CC:DD:EE:FF"
        result1 = sanitize_html(html, salt="salt-one")
        result2 = sanitize_html(html, salt="salt-two")
        assert result1 != result2

    def test_auto_salt_produces_format_preserving_hash(self) -> None:
        """Test auto salt produces format-preserving MAC hash."""
        html = "MAC: AA:BB:CC:DD:EE:FF"
        result = sanitize_html(html, salt="auto")
        # Format-preserving MAC starts with 02: (locally administered bit)
        assert "AA:BB:CC:DD:EE:FF" not in result
        # Should contain a MAC-like pattern
        import re

        assert re.search(
            r"02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", result, re.IGNORECASE
        )


class TestCheckForPii:
    """Tests for check_for_pii function."""

    @pytest.mark.parametrize(
        ("content", "pattern", "match", "desc"),
        PII_DETECTION_CASES,
        ids=[c[3] for c in PII_DETECTION_CASES],
    )
    def test_detects_pii(self, content: str, pattern: str, match: str, desc: str) -> None:
        """Test PII detection."""
        findings = check_for_pii(content)
        pattern_findings = [f for f in findings if f["pattern"] == pattern]
        assert len(pattern_findings) >= 1, f"{desc}: should detect {pattern}"
        assert any(f["match"] == match for f in pattern_findings), f"{desc}: should match '{match}'"

    @pytest.mark.parametrize(
        ("content", "desc"),
        ALLOWLISTED_CASES,
        ids=[c[1] for c in ALLOWLISTED_CASES],
    )
    def test_ignores_allowlisted(self, content: str, desc: str) -> None:
        """Test allowlisted values are ignored."""
        findings = check_for_pii(content)
        assert len(findings) == 0, f"{desc}: should have no findings"

    def test_returns_line_numbers(self) -> None:
        """Test line number reporting."""
        content = "Line 1\nLine 2\nMAC: DE:AD:BE:EF:CA:FE"
        findings = check_for_pii(content)
        mac_findings = [f for f in findings if f["pattern"] == "mac_address"]
        assert mac_findings[0]["line"] == 3

    def test_includes_filename(self) -> None:
        """Test filename inclusion."""
        content = "MAC: DE:AD:BE:EF:CA:FE"
        findings = check_for_pii(content, filename="test.html")
        mac_findings = [f for f in findings if f["pattern"] == "mac_address"]
        assert mac_findings[0]["filename"] == "test.html"

    def test_multiple_findings_same_line(self) -> None:
        """Test multiple PII items on same line."""
        content = "MAC: AA:BB:CC:DD:EE:FF Email: test@example.com"
        findings = check_for_pii(content)
        assert len(findings) >= 2
        patterns = {f["pattern"] for f in findings}
        assert "mac_address" in patterns
        assert "email" in patterns


class TestPatternLoading:
    """Tests for pattern loading functions."""

    # fmt: off
    EXPECTED_PATTERNS = [
        "mac_address",
        "email",
        "public_ip",
    ]
    # fmt: on

    @pytest.mark.parametrize("pattern_name", EXPECTED_PATTERNS)
    def test_pattern_defined(self, pattern_name: str) -> None:
        """Test expected patterns are defined."""
        patterns = load_pii_patterns()
        assert pattern_name in patterns["patterns"]

    # fmt: off
    # Static placeholders from allowlist.json
    EXPECTED_ALLOWLIST = [
        "XX:XX:XX:XX:XX:XX",
        "0.0.0.0",
        "::",
        "x@x.invalid",
        "[REDACTED]",
    ]
    # fmt: on

    @pytest.mark.parametrize("placeholder", EXPECTED_ALLOWLIST)
    def test_allowlist_contains_placeholder(self, placeholder: str) -> None:
        """Test allowlist contains expected placeholders."""
        allowlist = load_allowlist()
        static_values = allowlist.get("static_placeholders", {}).get("values", [])
        assert placeholder in static_values
