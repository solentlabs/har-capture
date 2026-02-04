"""Tests for salt preservation across sanitization passes.

This module tests that the same salt is used across Pass 1 (auto-redaction)
and Pass 2 (user redaction) to maintain hash consistency and correlation.

Test Coverage:
    - Salt storage in SanitizationReport
    - Salt reuse in Pass 2 from Pass 1 report
    - Report JSON serialization with salt preservation
    - Salt=None handling (deterministic placeholders)
    - Hash consistency verification across passes
    - Correlation preservation for same values

Test Strategy:
    - Multi-pass workflow testing
    - Hash comparison across passes
    - JSON round-trip validation
    - Edge case testing (None salt, empty salt)
    - Integration with apply_user_redactions

Dependencies:
    - pytest for test framework
    - Hasher for hash generation
    - tempfile for test file creation
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from har_capture.patterns import Hasher
from har_capture.sanitization.har import apply_user_redactions, sanitize_har, sanitize_har_file
from har_capture.sanitization.report import (
    ConfidenceLevel,
    FlaggedValue,
    RedactionStatus,
    SanitizationReport,
)

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
SALT_VALUE_CASES = [
    # (salt_input, expected_not_empty, description)
    ("auto", True, "auto_generates_salt"),
    ("custom-salt-123", True, "custom_salt_preserved"),
    ("", True, "empty_string_salt"),  # Empty salt is valid
    ("a", True, "single_char_salt"),
]

HASH_CONSISTENCY_CASES = [
    # (value, category, salt)
    ("TestValue", "wifi_ssid", "consistent-salt"),
    ("Password123", "password", "another-salt"),
    ("Device-Name", "device_name", "third-salt"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestSaltStoredInReport:
    """Tests for salt storage in sanitization report."""

    @pytest.mark.parametrize(
        ("salt_input", "expected_not_empty", "desc"),
        SALT_VALUE_CASES,
        ids=[c[2] for c in SALT_VALUE_CASES],
    )
    def test_salt_stored_in_report(self, salt_input: str, expected_not_empty: bool, desc: str) -> None:
        """Test report stores the salt used in Pass 1."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [],
            }
        }
        _, report = sanitize_har(har_data, salt=salt_input)

        assert report.salt is not None, "Salt should be stored"
        if salt_input == "auto":
            # Auto should generate a non-empty salt
            assert len(report.salt) > 0, "Auto salt should be non-empty"
        else:
            # Custom salt should be preserved exactly
            assert report.salt == salt_input

    def test_auto_salt_is_random(self) -> None:
        """Test auto salt generates different values each time."""
        har_data = {"log": {"version": "1.2", "entries": []}}

        _, report1 = sanitize_har(har_data, salt="auto")
        _, report2 = sanitize_har(har_data, salt="auto")

        # Different calls should generate different salts
        assert report1.salt != report2.salt, "Auto should generate unique salts"

    def test_salt_from_sanitize_har_file(self, tmp_path: Path) -> None:
        """Test salt is stored when using sanitize_har_file."""
        har_data = {"log": {"version": "1.2", "entries": []}}
        input_file = tmp_path / "input.har"
        input_file.write_text(json.dumps(har_data))

        _, report = sanitize_har_file(str(input_file), salt="file-test-salt")

        assert report.salt == "file-test-salt"


class TestPass2UsesSameSalt:
    """Tests for Pass 2 using the same salt as Pass 1."""

    @pytest.mark.parametrize(
        ("value", "category", "salt"),
        HASH_CONSISTENCY_CASES,
        ids=[f"{c[0]}_{c[1]}" for c in HASH_CONSISTENCY_CASES],
    )
    def test_pass2_uses_same_salt(self, value: str, category: str, salt: str) -> None:
        """Test Pass 2 recreates hasher with same salt, producing identical hashes."""
        # Pass 1: Create a report with a known salt
        har_data = {"log": {"version": "1.2", "entries": []}, "content": f"data: {value}"}
        _, report = sanitize_har(har_data, salt=salt)

        # Manually add a flagged value (simulating heuristic detection)
        flagged = FlaggedValue(
            original_value=value,
            category=category,
            confidence=ConfidenceLevel.HIGH,
            context="test context",
            reason="test reason",
            status=RedactionStatus.USER_REDACTED,
        )
        report.flagged.append(flagged)

        # Pass 2: Apply user decisions
        result = apply_user_redactions({"log": {"content": f"data: {value}"}}, report)

        # Verify hash format matches the category
        assert flagged.redacted_value is not None
        expected_prefix = category.upper() + "_"
        assert flagged.redacted_value.startswith(expected_prefix)

        # Verify the value is actually replaced in result
        assert value not in json.dumps(result)
        assert flagged.redacted_value in json.dumps(result)

    def test_hash_matches_hasher_direct_call(self) -> None:
        """Test Pass 2 hash matches direct hasher call with same salt."""
        salt = "verification-salt"
        value = "TestValue"
        category = "wifi_ssid"

        # Create hasher directly
        hasher = Hasher.create(salt)
        expected_hash = hasher.hash_generic(value, category.upper())

        # Create report and apply redactions
        flagged = FlaggedValue(
            original_value=value,
            category=category,
            confidence=ConfidenceLevel.HIGH,
            context="ctx",
            reason="reason",
            status=RedactionStatus.USER_REDACTED,
        )
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt=salt,
            flagged=[flagged],
        )
        apply_user_redactions({"log": {"content": value}}, report)

        # Hashes should match
        assert flagged.redacted_value == expected_hash


class TestReportJSONRoundtrip:
    """Tests for salt preservation through JSON serialization."""

    def test_report_json_roundtrip_preserves_salt(self) -> None:
        """Test salt survives JSON serialization for resumable workflows."""
        har_data = {"log": {"version": "1.2", "entries": []}}
        _, report = sanitize_har(har_data, salt="roundtrip-test-salt")

        # Serialize to JSON
        json_str = json.dumps(report.to_dict())

        # Deserialize
        restored = json.loads(json_str)

        # Salt should be preserved
        assert restored["salt"] == "roundtrip-test-salt"

    def test_salt_enables_hash_reconstruction(self) -> None:
        """Test stored salt can be used to recreate matching hashes."""
        # Pass 1
        har_data = {"log": {"version": "1.2", "entries": []}}
        _, report = sanitize_har(har_data, salt="auto")

        # Store the salt (simulating writing to disk)
        stored_salt = report.salt

        # Later: Reconstruct hasher from stored salt
        reconstructed_hasher = Hasher.create(stored_salt)

        # Generate hash with reconstructed hasher
        hash1 = reconstructed_hasher.hash_generic("TestValue", "WIFI_SSID")

        # Generate hash with fresh hasher using same salt
        fresh_hasher = Hasher.create(stored_salt)
        hash2 = fresh_hasher.hash_generic("TestValue", "WIFI_SSID")

        # Hashes should match
        assert hash1 == hash2

    def test_flagged_values_preserved_in_json(self) -> None:
        """Test flagged values are preserved in JSON serialization."""
        flagged = FlaggedValue(
            original_value="TestNetwork",
            category="wifi_ssid",
            confidence=ConfidenceLevel.HIGH,
            context="...TestNetwork...",
            reason="SSID-like pattern",
            occurrences=3,
            status=RedactionStatus.USER_REDACTED,
        )
        report = SanitizationReport(
            input_file="in.har",
            output_file="out.har",
            salt="test-salt",
            flagged=[flagged],
        )

        # Serialize and deserialize
        json_str = json.dumps(report.to_dict())
        restored = json.loads(json_str)

        # Check flagged values
        assert len(restored["flagged"]) == 1
        assert restored["flagged"][0]["value"] == "TestNetwork"
        assert restored["flagged"][0]["category"] == "wifi_ssid"
        assert restored["flagged"][0]["confidence"] == "high"
        assert restored["flagged"][0]["occurrences"] == 3
        assert restored["flagged"][0]["status"] == "user"


class TestSaltWithNone:
    """Tests for salt=None behavior."""

    def test_none_salt_produces_static_placeholders(self) -> None:
        """Test None salt uses static placeholders (no correlation)."""
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
                                "text": "MAC: AA:BB:CC:DD:EE:FF",
                                "mimeType": "text/html",
                            },
                        },
                    }
                ],
            }
        }
        result, report = sanitize_har(har_data, salt=None)

        # Salt should be empty string
        assert report.salt == ""

        # MAC should be replaced with static placeholder
        content = result["log"]["entries"][0]["response"]["content"]["text"]
        assert "AA:BB:CC:DD:EE:FF" not in content
        # Static placeholder
        assert "XX:XX:XX:XX:XX:XX" in content
