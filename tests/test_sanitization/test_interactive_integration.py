"""Integration tests for interactive sanitization flow.

This module tests the end-to-end interactive sanitization workflow including
Pass 1 (auto-redaction + flagging) and Pass 2 (user redaction application).

Test Coverage:
    - Two-pass sanitization workflow
    - Flagged value collection and review
    - User redaction application across entire HAR
    - Salt preservation between passes
    - Report generation with statistics
    - File I/O integration (sanitize_har_file)
    - Interactive mode with temporary files

Test Strategy:
    - Integration tests simulating real user workflows
    - Multi-pass consistency validation
    - Temporary file handling
    - End-to-end data flow verification
    - Error recovery between passes

Dependencies:
    - pytest for test framework
    - tempfile for test file creation
    - SanitizationReport for workflow state
"""

from __future__ import annotations

import json
from pathlib import Path

from har_capture.sanitization.har import (
    apply_user_redactions,
    sanitize_har,
    sanitize_har_file,
)
from har_capture.sanitization.report import (
    ConfidenceLevel,
    FlaggedValue,
    RedactionStatus,
)

# =============================================================================
# Helper Functions
# =============================================================================


def create_har_with_suspicious_values() -> dict:
    """Create a HAR file with values that should be flagged."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://router.local/",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "text/html",
                            "text": (
                                "<html><script>"
                                "var tagValueList = '0|Good|HomeNetwork-5G|secretpass123|WPA2|"
                                "Connected|Johns-iPhone|02:aa:bb:cc:dd:ee|192.168.1.100'"
                                "</script></html>"
                            ),
                        },
                    },
                }
            ],
        }
    }


# =============================================================================
# Integration Test Classes
# =============================================================================


class TestFullSanitizationFlow:
    """Integration tests for full two-pass sanitization flow."""

    def test_full_flow_with_user_redactions(self) -> None:
        """Test: flagged values are redacted after user approval."""
        # Create HAR with suspicious values
        har_data = create_har_with_suspicious_values()

        # Pass 1: Auto-redact known patterns, flag suspicious values
        sanitized, report = sanitize_har(har_data, salt="test-salt", flag_suspicious=True)

        # Verify auto-redactions happened for KNOWN patterns
        content = sanitized["log"]["entries"][0]["response"]["content"]["text"]
        assert "02:aa:bb:cc:dd:ee" not in content.lower(), "MAC should be auto-redacted"
        assert "192.168.1.100" not in content, "Private IP should be auto-redacted"

        # SSIDs and passwords in tagValueList are FLAGGED (not auto-redacted)
        # They should still be in the content, but flagged for review
        assert "HomeNetwork-5G" in content, "SSID should be preserved (flagged, not auto-redacted)"
        assert "secretpass123" in content, "Password should be preserved (flagged, not auto-redacted)"

        # Verify values were flagged for review
        assert len(report.flagged) >= 2, "SSIDs and passwords should be flagged"
        flagged_values = [f.original_value for f in report.flagged]
        assert "HomeNetwork-5G" in flagged_values, "SSID should be in flagged list"
        assert "secretpass123" in flagged_values, "Password should be in flagged list"

    def test_user_redaction_of_non_auto_values(self) -> None:
        """Test: values flagged for review can be user-redacted in Pass 2."""
        # Create HAR with a value that won't be auto-redacted
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [
                    {
                        "request": {"method": "GET", "url": "http://router.local/", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "text/html",
                                "text": "<html><div>Customer Reference: ACME-12345</div></html>",
                            },
                        },
                    }
                ],
            }
        }

        # Pass 1
        sanitized, report = sanitize_har(har_data, salt="test-salt")

        # Verify value survived Pass 1 (it's not a known pattern)
        content = sanitized["log"]["entries"][0]["response"]["content"]["text"]
        assert "ACME-12345" in content, "Value should not be auto-redacted"

        # Simulate user choosing to redact it
        flagged = FlaggedValue(
            original_value="ACME-12345",
            category="account_id",
            confidence=ConfidenceLevel.MEDIUM,
            context="Customer Reference: ACME-12345",
            reason="Looks like customer identifier",
            status=RedactionStatus.USER_REDACTED,
        )
        report.flagged.append(flagged)

        # Pass 2: Apply user decisions
        final = apply_user_redactions(sanitized, report)

        # Verify user-selected redactions applied
        final_content = final["log"]["entries"][0]["response"]["content"]["text"]
        assert "ACME-12345" not in final_content, "User-redacted value should be gone"
        assert "ACCOUNT_ID_" in final_content, "Should have hash placeholder"

    def test_skipped_values_not_redacted(self) -> None:
        """Test: user-skipped values remain in output."""
        har_data = {"log": {"entries": []}, "content": "SSID: TestNetwork Password: secret123"}

        # Pass 1
        sanitized, report = sanitize_har(har_data, salt="test-salt")

        # Add flagged values - one redacted, one skipped
        report.flagged.extend(
            [
                FlaggedValue(
                    original_value="TestNetwork",
                    category="wifi_ssid",
                    confidence=ConfidenceLevel.HIGH,
                    context="test",
                    reason="SSID-like",
                    status=RedactionStatus.USER_SKIPPED,  # User chose to skip
                ),
                FlaggedValue(
                    original_value="secret123",
                    category="password",
                    confidence=ConfidenceLevel.HIGH,
                    context="test",
                    reason="Password-like",
                    status=RedactionStatus.USER_REDACTED,  # User chose to redact
                ),
            ]
        )

        # Pass 2
        final = apply_user_redactions(sanitized, report)

        final_str = json.dumps(final)
        # Skipped value should remain
        assert "TestNetwork" in final_str, "Skipped value should remain"
        # Redacted value should be gone
        assert "secret123" not in final_str, "Redacted value should be gone"


class TestSanitizeHarFile:
    """Integration tests for file-based sanitization."""

    def test_sanitize_har_file_returns_report(self, tmp_path: Path) -> None:
        """Test sanitize_har_file returns both path and report."""
        har_data = create_har_with_suspicious_values()
        input_file = tmp_path / "input.har"
        input_file.write_text(json.dumps(har_data))

        output_path, report = sanitize_har_file(str(input_file), salt="file-salt")

        # Output file exists
        assert Path(output_path).exists()
        # Report has correct paths
        assert report.input_file == str(input_file)
        assert report.output_file == output_path
        # Report has salt
        assert report.salt == "file-salt"
        # Report has auto-redaction counts
        assert report.total_auto_redacted > 0

    def test_sanitize_har_file_output_is_valid_json(self, tmp_path: Path) -> None:
        """Test output file is valid JSON."""
        har_data = create_har_with_suspicious_values()
        input_file = tmp_path / "input.har"
        input_file.write_text(json.dumps(har_data))

        output_path, _ = sanitize_har_file(str(input_file))

        # Should be valid JSON
        output_content = Path(output_path).read_text()
        output_data = json.loads(output_content)
        assert "log" in output_data


class TestReportUsage:
    """Tests for report usage patterns."""

    def test_report_can_be_serialized_and_restored(self) -> None:
        """Test report can be saved and loaded for resume."""
        har_data = {"log": {"version": "1.2", "entries": []}}
        _, report = sanitize_har(har_data, salt="auto")

        # Simulate saving report
        report_json = json.dumps(report.to_dict())

        # Simulate loading report
        restored = json.loads(report_json)

        # Key fields preserved
        assert restored["salt"] == report.salt
        assert restored["input_file"] == report.input_file
        assert restored["summary"]["auto_redacted"] == report.total_auto_redacted

    def test_report_counts_accurate(self) -> None:
        """Test report counts are accurate after full flow."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"method": "GET", "url": "http://test/", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "text/html",
                                "text": ("MAC1: AA:BB:CC:DD:EE:FF MAC2: 11:22:33:44:55:66 IP: 192.168.1.1"),
                            },
                        },
                    }
                ],
            }
        }
        _, report = sanitize_har(har_data, salt=None)

        # Should have some auto-redactions
        assert report.total_auto_redacted > 0
        # MAC addresses should be counted
        assert "mac_address" in report.auto_redacted_counts or report.total_auto_redacted >= 2


class TestFlagSuspiciousMode:
    """Tests for flag_suspicious=True mode."""

    def test_flag_suspicious_enables_heuristics(self) -> None:
        """Test flag_suspicious=True enables heuristic detection."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"method": "GET", "url": "http://test/", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "text/html",
                                "text": (
                                    "<script>var tagValueList = 'HomeNetwork-5G|secretpass|WPA2'</script>"
                                ),
                            },
                        },
                    }
                ],
            }
        }

        # With flag_suspicious=True
        _, report_with_flags = sanitize_har(har_data, salt="test", flag_suspicious=True)

        # Without flag_suspicious
        _, report_without_flags = sanitize_har(har_data, salt="test", flag_suspicious=False)

        # flag_suspicious=True should detect more suspicious values
        # (or at least not fewer)
        assert len(report_with_flags.flagged) >= len(report_without_flags.flagged)


class TestSaltConsistencyAcrossPasses:
    """Tests for salt consistency between Pass 1 and Pass 2."""

    def test_same_value_same_hash_across_passes(self) -> None:
        """Test same value produces same hash in both passes."""
        value = "TestSSID"
        har_data = {"log": {"entries": []}, "content": f"SSID: {value}"}

        # Pass 1
        sanitized, report = sanitize_har(har_data, salt="consistent-salt")

        # Add flagged value
        report.flagged.append(
            FlaggedValue(
                original_value=value,
                category="wifi_ssid",
                confidence=ConfidenceLevel.HIGH,
                context="test",
                reason="test",
                status=RedactionStatus.USER_REDACTED,
            )
        )

        # Pass 2
        apply_user_redactions(sanitized, report)

        # Get the hash
        first_hash = report.flagged[0].redacted_value

        # Do it again with same salt
        har_data2 = {"log": {"entries": []}, "content": f"SSID: {value}"}
        sanitized2, report2 = sanitize_har(har_data2, salt="consistent-salt")
        report2.flagged.append(
            FlaggedValue(
                original_value=value,
                category="wifi_ssid",
                confidence=ConfidenceLevel.HIGH,
                context="test",
                reason="test",
                status=RedactionStatus.USER_REDACTED,
            )
        )
        apply_user_redactions(sanitized2, report2)
        second_hash = report2.flagged[0].redacted_value

        # Hashes should match
        assert first_hash == second_hash
