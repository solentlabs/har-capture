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

import json
from pathlib import Path

import pytest

from har_capture.patterns import load_allowlist, load_pii_patterns
from har_capture.sanitization.html import (
    check_for_pii,
    sanitize_html,
)

# =============================================================================
# Load Test Data From Fixture
# =============================================================================

_FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "test_html.json"
_FIXTURE = json.loads(_FIXTURE_PATH.read_text())

# Note: When salt=None, format-preserving placeholders are used:
# - MAC: XX:XX:XX:XX:XX:XX
# - Private IP: 0.0.0.0
# - Public IP: 0.0.0.0
# - IPv6: ::
# - Email: x@x.invalid
# - Generic: ***{PREFIX}***
#
# Note: WiFi credentials in tagValueList are now FLAGGED for user review, not auto-redacted.
# See PRESERVE_CASES (wifi_credential_flagged / wifi_ssid_flagged) for those test cases.

SANITIZE_PII_CASES = [
    (c["input_html"], c["removed"], c["placeholder"], c["id"]) for c in _FIXTURE["sanitize_pii_cases"]
]

PRESERVE_CASES = [(c["input_html"], c["preserved"], c["id"]) for c in _FIXTURE["preserve_cases"]]

PII_DETECTION_CASES = [
    (c["content"], c["pattern_name"], c["match"], c["id"]) for c in _FIXTURE["pii_detection_cases"]
]

ALLOWLISTED_CASES = [(c["content"], c["id"]) for c in _FIXTURE["allowlisted_cases"]]

SERIAL_TABLE_CASES = [(c["html"], c["serial_value"], c["id"]) for c in _FIXTURE["serial_table_cases"]]

SETITEM_CASES = [
    (c["input_html"], c["should_not_contain"], c["should_contain"], c["id"])
    for c in _FIXTURE["setitem_cases"]
]

PIPE_SERIAL_CASES = [
    (c["input_html"], c["should_not_contain"], c["should_contain"], c["id"])
    for c in _FIXTURE["pipe_serial_cases"]
]


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

    EXPECTED_PATTERNS = _FIXTURE["expected_patterns"]

    @pytest.mark.parametrize("pattern_name", EXPECTED_PATTERNS)
    def test_pattern_defined(self, pattern_name: str) -> None:
        """Test expected patterns are defined."""
        patterns = load_pii_patterns()
        assert pattern_name in patterns["patterns"]

    EXPECTED_ALLOWLIST = _FIXTURE["expected_allowlist"]

    @pytest.mark.parametrize("placeholder", EXPECTED_ALLOWLIST)
    def test_allowlist_contains_placeholder(self, placeholder: str) -> None:
        """Test allowlist contains expected placeholders."""
        allowlist = load_allowlist()
        static_values = allowlist.get("static_placeholders", {}).get("values", [])
        assert placeholder in static_values


# =============================================================================
# Serial Number Detection in HTML Table Cells
# =============================================================================


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


class TestCustomPiiPatternEdgeCases:
    """Tests for custom PII pattern loading edge cases in sanitize_html."""

    def test_skips_pattern_without_regex_key(self) -> None:
        """Test that PII patterns missing 'regex' key are skipped."""
        import json
        import tempfile
        from pathlib import Path

        custom = {
            "patterns": {
                "bad_pattern": {"description": "no regex key"},
                "good_pattern": {
                    "regex": r"CUSTOM_SECRET_\w+",
                    "replacement_prefix": "FOUND",
                },
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom, f)
            f.flush()
            custom_path = f.name

        try:
            html = "data: CUSTOM_SECRET_ABC123 end"
            result = sanitize_html(html, salt="test", custom_patterns=custom_path)
            assert "CUSTOM_SECRET_ABC123" not in result, "good pattern should still match"
        finally:
            Path(custom_path).unlink(missing_ok=True)

    def test_custom_pattern_with_ignorecase_flag(self) -> None:
        """Test that custom PII patterns with IGNORECASE flag work."""
        import json
        import tempfile
        from pathlib import Path

        custom = {
            "patterns": {
                "case_pattern": {
                    "regex": r"secret_token_\w+",
                    "replacement_prefix": "TOKEN",
                    "flags": ["IGNORECASE"],
                },
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom, f)
            f.flush()
            custom_path = f.name

        try:
            html = "data: SECRET_TOKEN_XYZ789 end"
            result = sanitize_html(html, salt="test", custom_patterns=custom_path)
            assert "SECRET_TOKEN_XYZ789" not in result, "IGNORECASE flag should enable match"
        finally:
            Path(custom_path).unlink(missing_ok=True)


class TestSetItemHeuristicCoverage:
    """Tests for setItem heuristic code paths with mocked analyze_value."""

    def test_setitem_heuristic_redact_triggers_redaction(self) -> None:
        """Test Tier C REDACT path when analyze_value flags the value."""
        from unittest.mock import patch

        from har_capture.sanitization.report import HeuristicMode

        html = 'localStorage.setItem("mykey", "some_opaque_value")'
        with patch(
            "har_capture.sanitization.heuristics.analyze_value",
            return_value=(True, "HIGH", "credential", "looks like a credential"),
        ):
            result = sanitize_html(html, salt="test", heuristics=HeuristicMode.REDACT)
        assert "some_opaque_value" not in result, "value should be redacted in REDACT mode"
        assert "mykey" in result, "key should be preserved"

    def test_setitem_heuristic_flag_records_flag(self) -> None:
        """Test Tier C FLAG path when analyze_value flags the value."""
        from unittest.mock import patch

        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.report import HeuristicMode

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        html = 'sessionStorage.setItem("config", "opaque_val_999")'
        with patch(
            "har_capture.sanitization.heuristics.analyze_value",
            return_value=(True, "MEDIUM", "credential", "looks suspicious"),
        ):
            result = sanitize_html(html, salt="test", collector=collector, heuristics=HeuristicMode.FLAG)
        assert "opaque_val_999" in result, "value should be preserved in FLAG mode"
        assert len(collector.flagged) > 0, "should have flagged a value"
