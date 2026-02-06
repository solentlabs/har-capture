"""Tests for HeuristicMode functionality.

These tests verify the new heuristics parameter and its three modes:
- DISABLED: Skip heuristic analysis (default, backward compatible)
- FLAG: Flag suspicious values for manual review
- REDACT: Auto-redact suspicious values
"""

from __future__ import annotations

import re

from har_capture.patterns import Hasher
from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.html import sanitize_html
from har_capture.sanitization.report import HeuristicMode


class TestHeuristicModeDisabled:
    """Test default behavior: heuristics disabled."""

    def test_wifi_password_preserved_by_default(self) -> None:
        """WiFi credentials in tagValueList are preserved when heuristics disabled."""
        content = "var tagValueList = '0|Good||TestWiFiPass123|data';"
        result = sanitize_html(content)  # Default: DISABLED
        assert "TestWiFiPass123" in result

    def test_ssid_preserved_by_default(self) -> None:
        """SSID-like values are preserved when heuristics disabled."""
        content = "var tagValueList = 'HomeNetwork-5G|data';"
        result = sanitize_html(content)
        assert "HomeNetwork-5G" in result

    def test_device_name_preserved_by_default(self) -> None:
        """Device names are preserved when heuristics disabled."""
        content = "var tagValueList = '19|MyDevice|192.168.1.100|XX:XX:XX:XX:XX:XX';"
        result = sanitize_html(content)
        assert "MyDevice" in result

    def test_high_entropy_preserved_by_default(self) -> None:
        """High-entropy values are preserved when heuristics disabled."""
        content = "var tagValueList = '0|Good||P@ssw0rd!123|data';"
        result = sanitize_html(content)
        assert "P@ssw0rd!123" in result

    def test_macs_still_redacted_with_disabled(self) -> None:
        """Known patterns (MACs) are always redacted regardless of heuristics mode."""
        content = "var tagValueList = '0|AA:BB:CC:DD:EE:FF|data';"
        result = sanitize_html(content, salt="test")
        assert "AA:BB:CC:DD:EE:FF" not in result
        # Format-preserving MAC redaction (02:xx:xx:xx:xx:xx)
        assert re.search(r"02:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}", result)


class TestHeuristicModeRedact:
    """Test auto-redaction mode: heuristics enabled with auto-redact."""

    def test_wifi_password_redacted(self) -> None:
        """WiFi credentials are auto-redacted with REDACT mode."""
        content = "var tagValueList = '0|Good||TestWiFiPass123|data';"
        result = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt="test")
        assert "TestWiFiPass123" not in result
        # Should be redacted as CRED or WIFI
        assert "CRED_" in result or "WIFI_" in result

    def test_ssid_redacted(self) -> None:
        """SSID-like values are auto-redacted with REDACT mode."""
        content = "var tagValueList = 'HomeNetwork-5G|data';"
        result = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt="test")
        assert "HomeNetwork-5G" not in result
        assert "WIFI_" in result

    def test_device_name_redacted(self) -> None:
        """Device names are auto-redacted with REDACT mode."""
        content = "var tagValueList = '19|MyDevice|192.168.1.100';"
        result = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt="test")
        assert "MyDevice" not in result
        # "MyDevice" may be detected as wifi_ssid or device_name depending on heuristics
        assert "WIFI_" in result or "DEVICE_" in result

    def test_high_entropy_redacted(self) -> None:
        """High-entropy values are auto-redacted with REDACT mode."""
        content = "var tagValueList = '0|Good||P@ssw0rd!123|data';"
        result = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt="test")
        assert "P@ssw0rd!123" not in result
        assert "CRED_" in result

    def test_technical_values_preserved_with_redact(self) -> None:
        """Safe technical values are preserved even in REDACT mode."""
        content = "var tagValueList = 'Locked|OK|QAM256|123';"
        result = sanitize_html(content, heuristics=HeuristicMode.REDACT)
        assert "Locked" in result
        assert "OK" in result
        assert "QAM256" in result
        assert "123" in result

    def test_redact_with_salt_none(self) -> None:
        """REDACT mode with salt=None uses static placeholders."""
        content = "var tagValueList = '0|Good||MySSID-5G|data';"
        result = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt=None)
        assert "MySSID-5G" not in result
        assert "***WIFI***" in result

    def test_redact_records_auto_redaction(self) -> None:
        """REDACT mode records auto-redactions in collector."""
        collector = RedactionCollector(hasher=Hasher.create("test"))
        content = "var tagValueList = 'HomeNetwork|data';"
        sanitize_html(content, heuristics=HeuristicMode.REDACT, collector=collector)

        # Should have auto-redaction entry (not flagged entry)
        assert collector.auto_redacted_counts.get("wifi_ssid", 0) > 0
        assert len(collector.flagged) == 0  # Not flagged, just redacted


class TestHeuristicModeFlag:
    """Test flag mode: heuristics enabled but values preserved for review."""

    def test_wifi_password_flagged_not_redacted(self) -> None:
        """WiFi credentials are flagged but preserved with FLAG mode."""
        collector = RedactionCollector(hasher=Hasher.create("test"))
        content = "var tagValueList = '0|Good||TestWiFiPass123|data';"
        result = sanitize_html(content, heuristics=HeuristicMode.FLAG, collector=collector)

        assert "TestWiFiPass123" in result  # Preserved!
        assert len(collector.flagged) > 0  # But flagged

    def test_ssid_flagged_not_redacted(self) -> None:
        """SSID-like values are flagged but preserved with FLAG mode."""
        collector = RedactionCollector(hasher=Hasher.create("test"))
        content = "var tagValueList = 'HomeNetwork-5G|data';"
        result = sanitize_html(content, heuristics=HeuristicMode.FLAG, collector=collector)

        assert "HomeNetwork-5G" in result
        assert len(collector.flagged) > 0
        # Check category
        assert any("wifi" in f.category for f in collector.flagged)

    def test_flagged_values_have_context(self) -> None:
        """Flagged values include context for user review."""
        collector = RedactionCollector(hasher=Hasher.create("test"))
        content = "var tagValueList = 'SSID|MyNetwork-5G|data';"
        sanitize_html(content, heuristics=HeuristicMode.FLAG, collector=collector)

        assert len(collector.flagged) > 0
        flagged = collector.flagged[0]
        assert flagged.context  # Has context
        assert flagged.reason  # Has reason
        assert flagged.confidence  # Has confidence level


class TestHeuristicModeCorrelation:
    """Test that REDACT mode preserves correlation with salted hashes."""

    def test_same_value_same_hash(self) -> None:
        """Same flagged value should hash consistently within a session."""
        content1 = "var tagValueList = 'WiFi1|pass123|data';"
        content2 = "var tagValueList = 'WiFi2|pass123|other';"

        result1 = sanitize_html(content1, heuristics=HeuristicMode.REDACT, salt="test")
        result2 = sanitize_html(content2, heuristics=HeuristicMode.REDACT, salt="test")

        # Extract all hashes from both results
        hashes1 = re.findall(r"(CRED|WIFI)_([a-f0-9]{8})", result1)
        hashes2 = re.findall(r"(CRED|WIFI)_([a-f0-9]{8})", result2)

        # The second hash in each should be "pass123" (same in both)
        assert len(hashes1) >= 2
        assert len(hashes2) >= 2
        pass123_hash1 = f"{hashes1[1][0]}_{hashes1[1][1]}"
        pass123_hash2 = f"{hashes2[1][0]}_{hashes2[1][1]}"
        assert pass123_hash1 == pass123_hash2  # Same password → same hash

    def test_different_salts_different_hashes(self) -> None:
        """Different salts produce different hashes for same value."""
        content = "var tagValueList = '0|Good||MySSID|data';"

        result1 = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt="salt1")
        result2 = sanitize_html(content, heuristics=HeuristicMode.REDACT, salt="salt2")

        import re

        hash1 = re.search(r"WIFI_([a-f0-9]{8})", result1)
        hash2 = re.search(r"WIFI_([a-f0-9]{8})", result2)

        assert hash1 is not None
        assert hash2 is not None
        assert hash1.group(1) != hash2.group(1)  # Different salts → different hashes


class TestCustomPatternsDict:
    """Test custom_patterns parameter accepting dict."""

    def test_custom_patterns_as_dict(self) -> None:
        """custom_patterns can be passed as dict instead of file path."""
        patterns = {
            "patterns": {
                "test_pattern": {
                    "regex": r"TEST-\d{4}",
                    "replacement_prefix": "TEST",
                }
            }
        }
        content = "Device ID: TEST-1234"
        result = sanitize_html(content, custom_patterns=patterns, salt="test")

        # Pattern should be applied
        assert "TEST-1234" not in result
        assert "TEST_" in result

    def test_custom_patterns_dict_with_heuristics(self) -> None:
        """custom_patterns dict works together with heuristics."""
        patterns = {
            "patterns": {
                "modem_serial": {
                    "regex": r"SN[0-9]{10}",
                    "replacement_prefix": "MODEM_SN",
                }
            }
        }
        content = "var tagValueList = 'SN1234567890|MySSID-5G|data';"
        result = sanitize_html(
            content,
            custom_patterns=patterns,
            heuristics=HeuristicMode.REDACT,
            salt="test",
        )

        # Both custom pattern and heuristics should work
        assert "SN1234567890" not in result  # Custom pattern
        assert "MySSID-5G" not in result  # Heuristics
        assert "MODEM_SN_" in result
        assert "WIFI_" in result


class TestBackwardCompatibility:
    """Test that default behavior is backward compatible with v0.3.1."""

    def test_default_same_as_v031(self) -> None:
        """Default behavior (heuristics=DISABLED) matches v0.3.1."""
        # In v0.3.1, WiFi passwords were preserved by default
        content = "var tagValueList = '0|Good||happymango167|test';"
        result = sanitize_html(content)

        # Should be preserved (not redacted) by default
        assert "happymango167" in result

    def test_macs_still_redacted(self) -> None:
        """Known patterns (MACs) are still auto-redacted by default."""
        content = "MAC: AA:BB:CC:DD:EE:FF"
        result = sanitize_html(content, salt="test")

        assert "AA:BB:CC:DD:EE:FF" not in result
        # Format-preserving MAC redaction
        assert re.search(r"02:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}", result)

    def test_ips_still_redacted(self) -> None:
        """Known patterns (IPs) are still auto-redacted by default."""
        content = "IP: 192.168.1.100 and 8.8.8.8"
        result = sanitize_html(content, salt="test")

        assert "192.168.1.100" not in result
        assert "8.8.8.8" not in result
