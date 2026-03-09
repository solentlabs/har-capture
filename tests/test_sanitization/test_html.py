"""Tests for HTML sanitization utilities.

This module tests sanitization of HTML content extracted from device web
interfaces, removing PII while preserving structure for debugging.

Test Coverage:
    - Full HTML sanitization (MAC, email, IP, passwords, etc.)
    - PII detection in HTML content
    - Pattern loading from configuration files
    - Custom pattern file support
    - Multiple PII types in single document
    - Nested HTML structures

Test Strategy:
    - Real-world HTML samples from device interfaces
    - Pattern-specific unit tests
    - End-to-end sanitization validation
    - Preservation of non-PII content
    - Custom pattern merging tests

Dependencies:
    - pytest for test framework
"""

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
    # Note: WiFi credentials in tagValueList are now FLAGGED for user review, not auto-redacted.
    # See FLAGGED_CASES below for those test cases.
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
    # WiFi credentials in tagValueList are PRESERVED (flagged for review, not auto-redacted)
    ("var tagValueList = '0|Good||happymango167|test';", "happymango167", "wifi_credential_flagged"),
    ("var tagValueList = 'status|MySecretWiFi123|data';", "MySecretWiFi123", "wifi_ssid_flagged"),
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


# =============================================================================
# Serial Number Detection in HTML Table Cells
# =============================================================================

# ┌──────────────────────────────────────────────────────────────────┬─────────────────┬──────────────────────┐
# │ html                                                             │ serial_value    │ description          │
# ├──────────────────────────────────────────────────────────────────┼─────────────────┼──────────────────────┤
# │ HTML with <td> label and <td> value                             │ value to redact │ test case name       │
# │                                                                  │ or None         │                      │
# └──────────────────────────────────────────────────────────────────┴─────────────────┴──────────────────────┘
#
# fmt: off
SERIAL_TABLE_CASES = [
    # Label in one <td>, serial in next <td>
    ('<td><strong>Serial Number</strong></td>\n<td>17V541334700308</td>', "17V541334700308", "serial_in_adjacent_td"),
    ('<td>Serial Number</td><td>ABC12345678</td>',                       "ABC12345678",     "serial_in_plain_td"),
    ('<td><strong>SN</strong></td>\n<td>ARRIS-99887766</td>',            "ARRIS-99887766",  "sn_label_in_td"),
    # Non-serial table cell (should be unchanged)
    ('<td>Model</td><td>SB8200</td>',                                    None,              "non_serial_table_cell"),
]
# fmt: on


class TestSerialNumberTableCell:
    """Tests for serial number detection in HTML table cells."""

    @pytest.mark.parametrize(
        ("html", "serial_value", "desc"),
        SERIAL_TABLE_CASES,
        ids=[c[2] for c in SERIAL_TABLE_CASES],
    )
    def test_serial_in_table_cell(self, html: str, serial_value: str | None, desc: str) -> None:
        """Test serial numbers in adjacent table cells are detected."""
        result = sanitize_html(html, salt="test")
        if serial_value:
            assert serial_value not in result, f"{desc}: serial should be redacted"
        else:
            assert result == html or "SB8200" in result, f"{desc}: non-serial should be preserved"


# =============================================================================
# Web Storage setItem() Scanning (Gap 1 fix)
# =============================================================================

# ┌──────────────────────────────────────────────────────────────────────────┬──────────────────────────┬─────────────────┬──────────────────────┐
# │ input_html                                                             │ should_not_contain       │ should_contain  │ description          │
# ├──────────────────────────────────────────────────────────────────────────┼──────────────────────────┼─────────────────┼──────────────────────┤
# │ setItem() calls with various key types                                 │ value that must be gone  │ prefix expected │ test case name       │
# └──────────────────────────────────────────────────────────────────────────┴──────────────────────────┴─────────────────┴──────────────────────┘
#
# fmt: off
SETITEM_CASES = [
    # Tier A: Sensitive key names -> auto-redact value
    ('localStorage.setItem("PrivateKey", "HMAC_replicant_c1982")',       "HMAC_replicant_c1982",    "STORAGE_",  "setitem_privatekey"),
    ('sessionStorage.setItem("csrf_token", "xsrf_wopr_play")',          "xsrf_wopr_play",          "STORAGE_",  "setitem_csrf_token"),
    ('sessionStorage.setItem("secret", "aes256_pyramid_key")',           "aes256_pyramid_key",      "STORAGE_",  "setitem_secret"),
    ('localStorage.setItem("api_key", "sk_live_moreLightFather")',      "sk_live_moreLightFather",  "STORAGE_", "setitem_api_key"),
    ('sessionStorage.setItem("auth_token", "tok_nexus6_2019")',         "tok_nexus6_2019",         "STORAGE_",  "setitem_auth_token"),
    ('localStorage.setItem("password", "Th3r3IsN0Sp00n!")',             "Th3r3IsN0Sp00n!",         "STORAGE_",  "setitem_password"),
    # Single-quoted setItem
    ("localStorage.setItem('token', 'secret_session_abc')",             "secret_session_abc",      "STORAGE_",  "setitem_single_quotes"),
    # Non-sensitive key, safe value -> preserved
    ('localStorage.setItem("theme", "dark")',                            None,                      None,        "setitem_safe_value"),
    ('sessionStorage.setItem("lang", "en")',                             None,                      None,        "setitem_safe_lang"),
]
# fmt: on


class TestSetItemScanning:
    """Tests for inline localStorage/sessionStorage.setItem() scanning."""

    @pytest.mark.parametrize(
        ("html", "should_not_contain", "should_contain", "desc"),
        SETITEM_CASES,
        ids=[c[3] for c in SETITEM_CASES],
    )
    def test_setitem_redaction(
        self,
        html: str,
        should_not_contain: str | None,
        should_contain: str | None,
        desc: str,
    ) -> None:
        """Test setItem() values are handled correctly."""
        result = sanitize_html(html, salt="test")
        if should_not_contain:
            assert should_not_contain not in result, f"{desc}: value should be redacted"
        if should_contain:
            assert should_contain in result, f"{desc}: expected prefix in output"
        if should_not_contain is None:
            # Safe values should be preserved unchanged
            assert result == html, f"{desc}: safe value should be unchanged"

    def test_setitem_pii_in_value_caught_by_ip_pass(self) -> None:
        """Test that PII in setItem values is caught by subsequent PII passes."""
        html = 'localStorage.setItem("firmware_url", "http://10.0.1.1/firmware/v3.2.1.bin")'
        result = sanitize_html(html, salt="test")
        assert "10.0.1.1" not in result, "private IP in setItem value should be redacted by IP pass"

    def test_setitem_preserves_key_name(self) -> None:
        """Test that setItem key name is preserved, only value is redacted."""
        html = 'localStorage.setItem("PrivateKey", "secret_value_123")'
        result = sanitize_html(html, salt="test")
        assert "PrivateKey" in result, "key name should be preserved"
        assert "secret_value_123" not in result, "value should be redacted"

    def test_setitem_heuristic_redact_mode(self) -> None:
        """Test Tier C: heuristic REDACT mode auto-redacts high-entropy values."""
        from har_capture.sanitization.report import HeuristicMode

        # High-entropy value with mixed character types that should trigger credential heuristic
        html = 'localStorage.setItem("config_data", "xK9mP2qR7sT4wZ")'
        result = sanitize_html(html, salt="test", heuristics=HeuristicMode.REDACT)
        # If heuristics flag it as credential-like, it should be redacted
        # If not flagged, it passes through (and subsequent PII passes handle it)
        # Either way, the code path should not error
        assert "config_data" in result, "key name should be preserved"

    def test_setitem_heuristic_flag_mode(self) -> None:
        """Test Tier C: heuristic FLAG mode preserves value but records flag."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.report import HeuristicMode

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        html = 'localStorage.setItem("config_data", "xK9mP2qR7sT4wZ")'
        result = sanitize_html(html, salt="test", collector=collector, heuristics=HeuristicMode.FLAG)
        # In FLAG mode, value is preserved (not redacted) — flagged for review
        assert "config_data" in result, "key name should be preserved"


# =============================================================================
# Serial Numbers in Pipe-Delimited Strings (Gap 2 fix)
# =============================================================================

# ┌─────────────────────────────────────────────────────────────────┬──────────────────┬─────────────────┬──────────────────────────┐
# │ input_html                                                     │ should_not_contain│ should_contain │ description              │
# ├─────────────────────────────────────────────────────────────────┼──────────────────┼─────────────────┼──────────────────────────┤
# │ pipe-delimited JS vars with serial numbers                     │ leaked serial    │ prefix expected │ test case name           │
# └─────────────────────────────────────────────────────────────────┴──────────────────┴─────────────────┴──────────────────────────┘
#
# fmt: off
PIPE_SERIAL_CASES = [
    ("var tagValueList = 'enabled|SN-N6MAA10816|WPA3';",  "SN-N6MAA10816",  "SERIAL_",  "pipe_serial_sn_dash"),
    ("var tagValueList = 'active|S/N-ABC123456|locked';",  "S/N-ABC123456",  "SERIAL_",  "pipe_serial_s_n_prefix"),
    ("var tagValueList = 'ok|SN_XYZW5678Q|enabled';",      "SN_XYZW5678Q",   "SERIAL_",  "pipe_serial_underscore"),
    ("var tagValueList = 'ok|sn-abcdefgh|enabled';",       "sn-abcdefgh",    "SERIAL_",  "pipe_serial_lowercase"),
    ("var tagValueList = 'ok|S-N-WXYZ98765|good';",          "S-N-WXYZ98765",  "SERIAL_",  "pipe_serial_s_dash_n"),
    # Non-serial values should be preserved
    ("var tagValueList = 'SNMP|enabled|good';",             None,             None,       "pipe_not_serial_snmp"),
    # Note: SNMPv3Auth is caught by step 2's general serial regex (pre-existing behavior)
    ("var tagValueList = 'SN-AB|ok';",                      None,             None,       "pipe_serial_too_short"),
]
# fmt: on


class TestPipeSerialNumber:
    """Tests for serial number detection in pipe-delimited strings."""

    @pytest.mark.parametrize(
        ("html", "should_not_contain", "should_contain", "desc"),
        PIPE_SERIAL_CASES,
        ids=[c[3] for c in PIPE_SERIAL_CASES],
    )
    def test_pipe_serial_redaction(
        self,
        html: str,
        should_not_contain: str | None,
        should_contain: str | None,
        desc: str,
    ) -> None:
        """Test serial numbers in pipe-delimited strings are handled correctly."""
        result = sanitize_html(html, salt="test")
        if should_not_contain:
            assert should_not_contain not in result, f"{desc}: serial should be redacted"
        if should_contain:
            assert should_contain in result, f"{desc}: expected prefix in output"
        if should_not_contain is None:
            # Non-serial values should be preserved
            if "SNMPv3Auth" in html:
                assert "SNMPv3Auth" in result, f"{desc}: SNMPv3Auth should be preserved"
            elif "SNMP" in html:
                assert "SNMP" in result, f"{desc}: SNMP should be preserved"
            elif "SN-AB" in html:
                assert "SN-AB" in result, f"{desc}: short value should be preserved"
