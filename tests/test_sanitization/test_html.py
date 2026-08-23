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
from har_capture.sanitization.report import HeuristicMode

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

SERIAL_SIBLING_SPAN_CASES = [
    (c["html"], c["redacted_value"], c["preserved_markup"], c["id"])
    for c in _FIXTURE["serial_sibling_span_cases"]
]

DEVICE_LABEL_BLOCK_CASES = [
    (c["html"], c["redacted_values"], c["preserved_markup"], c["id"])
    for c in _FIXTURE["device_label_block_cases"]
]

DEVICE_LABEL_PRESERVE_CASES = [
    (c["html"], c["preserved"], c["id"]) for c in _FIXTURE["device_label_preserve_cases"]
]

SETITEM_CASES = [
    (c["input_html"], c["should_not_contain"], c["should_contain"], c["id"])
    for c in _FIXTURE["setitem_cases"]
]

PIPE_SERIAL_CASES = [
    (c["input_html"], c["should_not_contain"], c["should_contain"], c["id"])
    for c in _FIXTURE["pipe_serial_cases"]
]

SERIAL_KEY_FP_CASES = [
    (c["input_html"], c.get("preserved"), c.get("removed"), c["id"])
    for c in _FIXTURE["serial_key_false_positive_cases"]
]

JS_SERIAL_VAR_CASES = [
    (c["input_html"], c.get("should_not_contain"), c.get("should_contain"), c["id"])
    for c in _FIXTURE["js_serial_variable_cases"]
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
# Serial Number / PIN Labels in Sibling Elements (Technicolor .jst markup)
# =============================================================================


class TestSerialNumberSiblingSpans:
    """Label and value in sibling elements with whitespace between the tags.

    Technicolor .jst firmware (XB6/XB7/XB8 family) renders
    ``<span class="readonlyLabel">Serial Number:</span>`` and the value in a
    following sibling ``<span class="value">``. Redaction must replace only
    the value and preserve the intermediate markup so sanitized fixtures keep
    their DOM structure.
    """

    @pytest.mark.parametrize(
        ("html", "redacted_value", "preserved_markup", "desc"),
        SERIAL_SIBLING_SPAN_CASES,
        ids=[c[3] for c in SERIAL_SIBLING_SPAN_CASES],
    )
    def test_sibling_span_value_redacted_markup_preserved(
        self, html: str, redacted_value: str, preserved_markup: str, desc: str
    ) -> None:
        """Test values in sibling elements are redacted without collapsing markup."""
        result = sanitize_html(html, salt="test")
        assert redacted_value not in result, f"{desc}: value should be redacted"
        assert preserved_markup in result, f"{desc}: intermediate markup should be preserved"


# =============================================================================
# Device Label Information Block (issue #194)
# =============================================================================


class TestDeviceLabelBlock:
    """Sticker values rendered with the value in its own element.

    Technicolor .jst (XB6/XB7/XB8/XB10) renders a "Device Label Information"
    block whose four sticker values sit in a sibling ``<span class="value">``.
    The serial and WPS PIN were reachable via the pass 2/2d tag chain, but the
    default Wi-Fi password and SSID were not, and survived every heuristic mode
    — a contributor's real Wi-Fi password reached a public issue that way.

    All markup below is synthetic; the values are fabricated.
    """

    @pytest.mark.parametrize(
        ("html", "redacted_values", "preserved_markup", "desc"),
        DEVICE_LABEL_BLOCK_CASES,
        ids=[c[3] for c in DEVICE_LABEL_BLOCK_CASES],
    )
    def test_sticker_values_redacted_markup_preserved(
        self, html: str, redacted_values: list[str], preserved_markup: str, desc: str
    ) -> None:
        """Test sticker values are redacted without collapsing the surrounding markup."""
        result = sanitize_html(html, salt="test")
        for value in redacted_values:
            assert value not in result, f"{desc}: {value!r} should be redacted"
        assert preserved_markup in result, f"{desc}: intermediate markup should be preserved"

    @pytest.mark.parametrize(
        ("html", "redacted_values", "preserved_markup", "desc"),
        DEVICE_LABEL_BLOCK_CASES,
        ids=[c[3] for c in DEVICE_LABEL_BLOCK_CASES],
    )
    def test_redaction_holds_in_every_heuristic_mode(
        self, html: str, redacted_values: list[str], preserved_markup: str, desc: str
    ) -> None:
        """Test redaction does not depend on the heuristic mode.

        The original defect was invisible to the heuristic setting: HTML label/
        value text is never routed through the heuristic engine, so all three
        modes leaked identically.
        """
        for mode in HeuristicMode:
            result = sanitize_html(html, salt="test", heuristics=mode)
            for value in redacted_values:
                assert value not in result, f"{desc}: {value!r} should be redacted in {mode}"

    @pytest.mark.parametrize(
        ("html", "preserved", "desc"),
        DEVICE_LABEL_PRESERVE_CASES,
        ids=[c[2] for c in DEVICE_LABEL_PRESERVE_CASES],
    )
    def test_prose_and_headings_preserved(self, html: str, preserved: str, desc: str) -> None:
        """Test the structural rules do not fire on help text, headings, or placeholders."""
        result = sanitize_html(html, salt="test")
        assert preserved in result, f"{desc}: {preserved!r} should be preserved"

    @pytest.mark.parametrize(
        ("html", "redacted_values", "preserved_markup", "desc"),
        DEVICE_LABEL_BLOCK_CASES,
        ids=[c[3] for c in DEVICE_LABEL_BLOCK_CASES],
    )
    def test_sanitization_is_idempotent(
        self, html: str, redacted_values: list[str], preserved_markup: str, desc: str
    ) -> None:
        """Test re-sanitizing already-sanitized markup is a no-op.

        These rules match on markup structure rather than value shape, so a
        placeholder in the value element matches as readily as a credential.
        Without the already-redacted guard a fixture sweep would rewrite every
        placeholder on each run.
        """
        once = sanitize_html(html, salt="test")
        twice = sanitize_html(once, salt="test")
        assert once == twice, f"{desc}: re-sanitizing should be a no-op"


class TestDeviceLabelCheckForPii:
    """The CI fixture gate must see the Device Label block too.

    ``check_for_pii`` is the third detection path (alongside the sanitizer and
    ``validate``); before this it returned zero findings on a block holding a
    plaintext default Wi-Fi password.
    """

    @pytest.mark.parametrize(
        ("html", "expected_pattern", "expected_match", "desc"),
        [
            (
                '<span class="readonlyLabel">Default Password:</span>'
                '<span class="value">orange4213table</span>',
                "default_password_label",
                "orange4213table",
                "sibling_span_password",
            ),
            (
                '<span class="readonlyLabel">Default Network Name (SSID):</span>'
                '<span class="value">WIFI-AAAA</span>',
                "default_ssid_label",
                "WIFI-AAAA",
                "sibling_span_ssid",
            ),
            (
                '<td><font class="wifi_ntwrk">WIFI-AAAA</font></td>',
                "ssid_attribute",
                "WIFI-AAAA",
                "ssid_attributed_element",
            ),
            (
                '<select id="mac_ssid"><option value="17">WIFI-AAAA</option></select>',
                "ssid_select_option",
                "WIFI-AAAA",
                "ssid_select_option",
            ),
        ],
    )
    def test_device_label_values_detected(
        self, html: str, expected_pattern: str, expected_match: str, desc: str
    ) -> None:
        """Test check_for_pii reports each structurally-identified value."""
        findings = check_for_pii(html, "fixture.html")
        matched = [f for f in findings if f["pattern"] == expected_pattern]
        assert len(matched) == 1, f"{desc}: expected one {expected_pattern} finding"
        assert matched[0]["match"] == expected_match
        assert matched[0]["filename"] == "fixture.html"

    def test_bare_index_option_not_reported(self) -> None:
        """Test numeric option values are treated as row indices, not network names."""
        html = '<select id="mac_ssid"><option value="1">17</option></select>'
        findings = check_for_pii(html, "fixture.html")
        assert [f for f in findings if f["pattern"] == "ssid_select_option"] == []

    def test_redacted_values_not_reported(self) -> None:
        """Test allowlisted placeholders are not re-reported as leaks."""
        html = '<span class="readonlyLabel">Default Password:</span><span class="value">***REDACTED***</span>'
        findings = check_for_pii(html, "fixture.html")
        assert [f for f in findings if f["pattern"] == "default_password_label"] == []

    def test_redacted_select_option_not_reported(self) -> None:
        """Test an already-redacted option value is not re-reported as a leak."""
        html = '<select id="mac_ssid"><option value="17">***REDACTED***</option></select>'
        findings = check_for_pii(html, "fixture.html")
        assert [f for f in findings if f["pattern"] == "ssid_select_option"] == []

    def test_select_option_line_number_is_document_relative(self) -> None:
        """Test option line numbers are rebased onto the document.

        ``SSID_OPTION_RE`` runs against the matched ``<select>`` substring, so
        its own offsets are relative to that element; without rebasing, a value
        on line 103 was reported as line 6.
        """
        content = (
            "\n" * 100 + '<div>\n<select id="mac_ssid">\n<option value="17">WIFI-AAAA</option>\n</select>'
        )
        findings = check_for_pii(content, "fixture.html")
        matched = [f for f in findings if f["pattern"] == "ssid_select_option"]
        assert len(matched) == 1
        expected = content[: content.index("WIFI-AAAA")].count("\n") + 1
        assert matched[0]["line"] == expected

    def test_reported_line_number_points_at_the_value(self) -> None:
        """Test the reported line is the value's line, not the block's first line."""
        html = (
            "<div>\n<div>\n"
            '<span class="readonlyLabel">Default Password:</span>\n'
            '<span class="value">orange4213table</span>\n</div>\n</div>'
        )
        findings = check_for_pii(html, "fixture.html")
        matched = [f for f in findings if f["pattern"] == "default_password_label"]
        assert len(matched) == 1
        assert matched[0]["line"] == 4


class TestIdempotencyBoundary:
    """Re-sanitizing must not re-hash a placeholder — except where it must.

    Passes emitting a ``PREFIX_<hash>`` placeholder skip values already
    recognized as redacted, so a sweep over already-sanitized fixtures is a
    no-op and a serial can never compound into ``SERIAL_<hash>_<hash>``.

    The format-preserving passes deliberately do **not** take that guard. Their
    placeholders are valid-looking values in reserved ranges and cannot be told
    apart from real ones: ``02:aa:bb:cc:dd:ee`` is a legitimate
    locally-administered MAC, ``10.255.62.183`` a legitimate private address.
    Skipping them to buy cosmetic stability would leak real values.
    """

    PREFIX_HASH_CASES = [
        ("<span>Serial Number:</span><span>4106844207105213</span>", "serial_sibling"),
        ("<td><strong>Serial Number</strong></td><td>4106844207105213</td>", "serial_table"),
        ("var o={serialNumber:'4106844207105213'};", "js_serial"),
        ("<span>WPS PIN:</span><span>18345592</span>", "wps_pin"),
        ("<p>Account ID: 998877665</p>", "account_id"),
        ("<p>password=hunter2xyz</p>", "password_inline"),
        ("<p>SSID: MyNet-5G</p>", "ssid_inline"),
        ("var o={password_24g:'hunter2xyz'};", "js_password"),
        ("<span>Default Password:</span><span>orange4213table</span>", "structural_password"),
        ('<input type="password" value="hunter2xyz">', "password_input"),
        ('<label>SSID</label><input value="MyNet">', "ssid_input"),
        ("var o={ssid_24g:'MyNet'};", "js_ssid"),
    ]

    @pytest.mark.parametrize(("html", "desc"), PREFIX_HASH_CASES, ids=[c[1] for c in PREFIX_HASH_CASES])
    def test_prefix_hash_passes_are_idempotent(self, html: str, desc: str) -> None:
        """Test re-sanitizing is a byte-level no-op under independent random salts.

        The default ``salt="auto"`` mints a fresh salt per call, so this also
        proves the guard skips the value rather than re-hashing it to the same
        string by luck.
        """
        once = sanitize_html(html)
        twice = sanitize_html(once)
        thrice = sanitize_html(twice)
        assert once == twice == thrice, f"{desc}: re-sanitizing should be a no-op"

    def test_serial_placeholder_does_not_compound(self) -> None:
        """Test a serial placeholder is never re-hashed into a chain.

        Pass 2's value class excluded ``_``, so it matched only the ``SERIAL``
        prefix of its own output and prepended a fresh hash on every run —
        ``SERIAL_9f8e3528_9f8e3528_60ec920f``, growing without bound.
        """
        html = "<span>Serial Number:</span><span>4106844207105213</span>"
        for _ in range(4):
            html = sanitize_html(html, salt="fixed-salt")
        assert html.count("SERIAL_") == 1, f"placeholder compounded: {html}"

    FORMAT_PRESERVING_CASES = [
        ("<p>02:aa:bb:cc:dd:ee</p>", "02:aa:bb:cc:dd:ee", "locally_administered_mac"),
        ("<p>10.255.62.183</p>", "10.255.62.183", "private_ip_in_placeholder_range"),
        ("<p>2001:db8::1</p>", "2001:db8::1", "ipv6_documentation_range"),
        ("<p>192.0.2.5</p>", "192.0.2.5", "public_ip_test_net"),
    ]

    @pytest.mark.parametrize(
        ("html", "value", "desc"),
        FORMAT_PRESERVING_CASES,
        ids=[c[2] for c in FORMAT_PRESERVING_CASES],
    )
    def test_format_preserving_passes_still_redact_real_values(
        self, html: str, value: str, desc: str
    ) -> None:
        """Test values inside placeholder ranges are still redacted, not skipped.

        These are real addresses a real capture can contain. Guarding them on
        ``is_redacted()`` for idempotency's sake would pass them through
        unredacted — a leak traded for cosmetic stability.
        """
        result = sanitize_html(html, salt="fixed-salt")
        assert value not in result, f"{desc}: must still be redacted"


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

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        html = 'localStorage.setItem("config_data", "xK9mP2qR7sT4wZ")'
        result = sanitize_html(html, salt="test", collector=collector, heuristics=HeuristicMode.FLAG)
        # In FLAG mode, value is preserved (not redacted) — flagged for review
        assert "config_data" in result, "key name should be preserved"


_CUSTOM_VENDORPW = {"fields": {"auto_redact_patterns": ["vendorpw"]}}

# (desc, html, custom_patterns, must_contain, must_not_contain)
# Each row asserts that the setItem scanner honors (or ignores) custom_patterns
# via the field-pattern ContextVar scope.
SANITIZE_HTML_CUSTOM_PATTERN_CASES = [
    (
        "unknown_key_preserved_by_default",
        'localStorage.setItem("vendorpw", "alsosecret")',
        None,
        ["alsosecret"],
        [],
    ),
    (
        "unknown_key_redacted_with_custom",
        'localStorage.setItem("vendorpw", "alsosecret")',
        _CUSTOM_VENDORPW,
        ["vendorpw"],
        ["alsosecret"],
    ),
    (
        "sessionstorage_custom_key_redacted",
        'sessionStorage.setItem("vendorpw", "alsosecret")',
        _CUSTOM_VENDORPW,
        ["vendorpw"],
        ["alsosecret"],
    ),
    (
        "builtin_sensitive_key_still_redacts_with_custom",
        'localStorage.setItem("PrivateKey", "secret_value_123")',
        _CUSTOM_VENDORPW,
        ["PrivateKey"],
        ["secret_value_123"],
    ),
    (
        "unrelated_key_unaffected_by_custom",
        'localStorage.setItem("safeKey", "benign_value")',
        _CUSTOM_VENDORPW,
        ["safeKey", "benign_value"],
        [],
    ),
]


class TestSanitizeHtmlCustomFieldPatterns:
    """Regression tests for sanitize_html honoring custom field patterns.

    sanitize_html's internal ``is_sensitive_field`` calls must honor
    ``custom_patterns`` via the field-pattern context scope. Guards against the
    prior bug where ``custom_patterns`` was loaded but the setItem scanner
    still used the module-global field regex.
    """

    @pytest.mark.parametrize(
        ("desc", "html", "custom_patterns", "must_contain", "must_not_contain"),
        SANITIZE_HTML_CUSTOM_PATTERN_CASES,
        ids=[c[0] for c in SANITIZE_HTML_CUSTOM_PATTERN_CASES],
    )
    def test_setitem_redaction_matrix(
        self,
        desc: str,
        html: str,
        custom_patterns: dict | None,
        must_contain: list[str],
        must_not_contain: list[str],
    ) -> None:
        """Table-driven: setItem scanner x (default, custom_patterns)."""
        result = sanitize_html(html, salt=None, custom_patterns=custom_patterns)
        for needle in must_contain:
            assert needle in result, f"{desc}: expected {needle!r} in {result!r}"
        for needle in must_not_contain:
            assert needle not in result, f"{desc}: {needle!r} should be redacted in {result!r}"

    def test_context_scope_does_not_leak_out(self) -> None:
        """After a custom_patterns call, a subsequent default call must behave as default."""
        custom_html = 'localStorage.setItem("vendorpw", "alsosecret")'
        default_html = 'localStorage.setItem("vendorpw", "baseline_value")'

        sanitize_html(custom_html, salt=None, custom_patterns=_CUSTOM_VENDORPW)
        result_after = sanitize_html(default_html, salt=None)

        assert "baseline_value" in result_after, (
            "Default call after a custom_patterns call must NOT inherit the override"
        )

    def test_scope_restored_when_inner_call_raises(self) -> None:
        """sanitize_html's try/finally must reset the ContextVar even on exception."""
        from unittest.mock import patch

        from har_capture.sanitization.har import (
            _DEFAULT_FIELD_PATTERNS,
            _FIELD_PATTERNS_CTX,
        )

        assert _FIELD_PATTERNS_CTX.get() is _DEFAULT_FIELD_PATTERNS

        # Force the inner impl to blow up; the outer sanitize_html must still
        # clean up the ContextVar.
        with (
            patch(
                "har_capture.sanitization.html._sanitize_html_impl",
                side_effect=RuntimeError("inner boom"),
            ),
            pytest.raises(RuntimeError, match="inner boom"),
        ):
            sanitize_html("<html></html>", salt=None, custom_patterns=_CUSTOM_VENDORPW)

        assert _FIELD_PATTERNS_CTX.get() is _DEFAULT_FIELD_PATTERNS, (
            "sanitize_html must reset the ContextVar even when the inner impl raises"
        )


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


# =============================================================================
# Serial Number Key False Positives (SNRLevel, SNMPEnable, etc.)
# =============================================================================


class TestSerialKeyFalsePositives:
    """Tests that SN-prefix identifiers like SNRLevel are not mangled."""

    @pytest.mark.parametrize(
        ("html", "preserved", "removed", "desc"),
        SERIAL_KEY_FP_CASES,
        ids=[c[3] for c in SERIAL_KEY_FP_CASES],
    )
    def test_serial_key_false_positive(
        self,
        html: str,
        preserved: str | None,
        removed: str | None,
        desc: str,
    ) -> None:
        """Test camelCase/PascalCase SN-prefix identifiers are not rewritten."""
        result = sanitize_html(html, salt="test")
        if preserved:
            assert preserved in result, f"{desc}: '{preserved}' should be preserved"
        if removed:
            assert removed not in result, f"{desc}: '{removed}' should be redacted"


# =============================================================================
# JavaScript Serial Number Variable Assignments
# =============================================================================


class TestJsSerialVariable:
    """Tests for JS variable assignments containing serial number indicators."""

    @pytest.mark.parametrize(
        ("html", "should_not_contain", "should_contain", "desc"),
        JS_SERIAL_VAR_CASES,
        ids=[c[3] for c in JS_SERIAL_VAR_CASES],
    )
    def test_js_serial_variable_redaction(
        self,
        html: str,
        should_not_contain: str | None,
        should_contain: str | None,
        desc: str,
    ) -> None:
        """Test serial number values in JS variable assignments are redacted."""
        result = sanitize_html(html, salt="test")
        if should_not_contain:
            assert should_not_contain not in result, f"{desc}: value should be redacted"
        if should_contain:
            assert should_contain in result, f"{desc}: expected prefix in output"
        if should_not_contain is None:
            assert result == html, f"{desc}: value should be preserved unchanged"


# =============================================================================
# Pipe-Delimited Per-Value Unit Tests (extracted _sanitize_pipe_value)
# =============================================================================

PIPE_VALUE_UNIT_CASES = [
    (c["value"], c["expected_unchanged"], c.get("expected_not_contain"), c.get("expected_contains"), c["id"])
    for c in _FIXTURE["pipe_value_unit_cases"]
]


class TestSanitizePipeValue:
    """Unit tests for _sanitize_pipe_value() — the extracted per-value processor."""

    @pytest.mark.parametrize(
        ("value", "expected_unchanged", "expected_not_contain", "expected_contains", "desc"),
        PIPE_VALUE_UNIT_CASES,
        ids=[c[4] for c in PIPE_VALUE_UNIT_CASES],
    )
    def test_pipe_value_processing(
        self,
        value: str,
        expected_unchanged: bool,
        expected_not_contain: str | None,
        expected_contains: str | None,
        desc: str,
    ) -> None:
        """Test individual pipe value sanitization decisions."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.html import _sanitize_pipe_value
        from har_capture.sanitization.report import HeuristicMode

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        safe_values = {
            "good",
            "locked",
            "not locked",
            "unknown",
            "operational",
            "ok",
            "none",
            "&nbsp;",
            "enabled",
            "disabled",
            "retail",
            "success",
            "primary",
            "enable",
            "off",
            "on",
            "both",
            "in progress",
            "synchronized",
            "not synchronized",
            "done",
        }

        result = _sanitize_pipe_value(
            value,
            hasher=hasher,
            collector=collector,
            safe_values=safe_values,
            extra_safe_patterns=[],
            compiled_detectors=[],
            heuristics=HeuristicMode.DISABLED,
            values_context=[],
            value_index=0,
        )

        if expected_unchanged:
            assert result == value, f"{desc}: value should be preserved"
        if expected_not_contain:
            assert expected_not_contain not in result, f"{desc}: original should be removed"
        if expected_contains:
            assert expected_contains in result, f"{desc}: expected prefix in output"


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
