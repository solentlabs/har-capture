"""Tests for CLI sanitize command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from har_capture.cli.main import app

runner = CliRunner()


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def valid_har(tmp_path: Path) -> Path:
    """Create a valid HAR file with PII for testing."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://192.168.1.1/",
                        "headers": [
                            {"name": "Cookie", "value": "session=secret123"},
                        ],
                    },
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
    har_file = tmp_path / "test.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


@pytest.fixture
def invalid_json_file(tmp_path: Path) -> Path:
    """Create an invalid JSON file."""
    invalid_file = tmp_path / "invalid.har"
    invalid_file.write_text("{not valid json")
    return invalid_file


@pytest.fixture
def invalid_har_structure(tmp_path: Path) -> Path:
    """Create a JSON file that's not valid HAR."""
    invalid_file = tmp_path / "invalid_structure.har"
    invalid_file.write_text('{"not": "a har file"}')
    return invalid_file


@pytest.fixture
def large_har(tmp_path: Path) -> Path:
    """Create a HAR file larger than 1MB for size limit testing."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {"method": "GET", "url": "http://test/", "headers": []},
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "text": "x" * 500000,  # 500KB of padding
                            "mimeType": "text/plain",
                        },
                    },
                }
            ]
            * 3,  # 1.5MB total
        }
    }
    har_file = tmp_path / "large.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


# =============================================================================
# Test Classes
# =============================================================================


class TestSanitizeBasic:
    """Basic sanitize command tests."""

    def test_sanitize_valid_har(self, valid_har: Path) -> None:
        """Test sanitizing a valid HAR file."""
        result = runner.invoke(app, ["sanitize", str(valid_har)])
        assert result.exit_code == 0
        assert "Sanitized:" in result.stdout

    def test_sanitize_with_output(self, valid_har: Path, tmp_path: Path) -> None:
        """Test sanitizing with explicit output path."""
        output = tmp_path / "output.har"
        result = runner.invoke(app, ["sanitize", str(valid_har), "-o", str(output)])
        assert result.exit_code == 0
        assert output.exists()

    def test_sanitize_file_not_found(self, tmp_path: Path) -> None:
        """Test error when file doesn't exist."""
        result = runner.invoke(app, ["sanitize", str(tmp_path / "nonexistent.har")])
        assert result.exit_code == 1
        assert "File not found" in (result.output)

    def test_sanitize_invalid_json(self, invalid_json_file: Path) -> None:
        """Test error on invalid JSON."""
        result = runner.invoke(app, ["sanitize", str(invalid_json_file)])
        assert result.exit_code == 1
        assert "Invalid JSON" in (result.output)

    def test_sanitize_invalid_har_structure(self, invalid_har_structure: Path) -> None:
        """Test error on invalid HAR structure."""
        result = runner.invoke(app, ["sanitize", str(invalid_har_structure)])
        assert result.exit_code == 1
        assert "Invalid HAR" in (result.output)


class TestSanitizeSaltOptions:
    """Tests for salt options."""

    def test_sanitize_with_auto_salt(self, valid_har: Path) -> None:
        """Test default auto salt mode."""
        result = runner.invoke(app, ["sanitize", str(valid_har)])
        assert result.exit_code == 0
        assert "random salt" in result.stdout

    def test_sanitize_with_no_salt(self, valid_har: Path) -> None:
        """Test --no-salt option for static placeholders."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--no-salt"])
        assert result.exit_code == 0
        assert "static placeholders" in result.stdout

    def test_sanitize_with_custom_salt(self, valid_har: Path) -> None:
        """Test --salt option with custom value."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--salt", "my-salt"])
        assert result.exit_code == 0
        assert "provided salt" in result.stdout


class TestSanitizeCompression:
    """Tests for compression options."""

    def test_sanitize_with_compress(self, valid_har: Path) -> None:
        """Test --compress option creates .har.gz file."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--compress"])
        assert result.exit_code == 0
        assert "Compressed:" in result.stdout

        # Check compressed file exists
        sanitized_path = valid_har.parent / "test.sanitized.har"
        compressed_path = sanitized_path.with_suffix(".har.gz")
        assert compressed_path.exists()

    def test_sanitize_compression_level(self, valid_har: Path) -> None:
        """Test --compression-level option."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--compress", "--compression-level", "1"])
        assert result.exit_code == 0

    def test_sanitize_invalid_compression_level_high(self, valid_har: Path) -> None:
        """Test error on compression level > 9."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--compression-level", "10"])
        assert result.exit_code == 1
        assert "compression-level must be 1-9" in (result.output)

    def test_sanitize_invalid_compression_level_low(self, valid_har: Path) -> None:
        """Test error on compression level < 1."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--compression-level", "0"])
        assert result.exit_code == 1
        assert "compression-level must be 1-9" in (result.output)


class TestSanitizeSizeLimit:
    """Tests for size limit options."""

    def test_sanitize_default_size_limit(self, large_har: Path) -> None:
        """Test default 100MB limit allows normal files."""
        # Our 1.5MB file should be fine with default 100MB limit
        result = runner.invoke(app, ["sanitize", str(large_har)])
        assert result.exit_code == 0

    def test_sanitize_small_size_limit(self, large_har: Path) -> None:
        """Test --max-size limit enforced."""
        # Set limit to 1MB, file is ~1.5MB
        result = runner.invoke(app, ["sanitize", str(large_har), "--max-size", "1"])
        assert result.exit_code == 1
        assert "File too large" in (result.output)

    def test_sanitize_unlimited_size(self, large_har: Path) -> None:
        """Test --max-size 0 disables limit."""
        result = runner.invoke(app, ["sanitize", str(large_har), "--max-size", "0"])
        assert result.exit_code == 0

    def test_sanitize_negative_size_limit(self, valid_har: Path) -> None:
        """Test error on negative max-size."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--max-size", "-1"])
        assert result.exit_code == 1
        assert "max-size must be >= 0" in (result.output)


class TestSanitizeCustomPatterns:
    """Tests for custom patterns option."""

    def test_sanitize_with_custom_patterns(self, valid_har: Path, tmp_path: Path) -> None:
        """Test --patterns option with valid custom patterns."""
        custom_patterns = tmp_path / "custom.json"
        custom_patterns.write_text(
            json.dumps(
                {
                    "patterns": {
                        "test_pattern": {
                            "regex": "test\\d+",
                            "replacement_prefix": "TEST",
                        }
                    }
                }
            )
        )
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", str(custom_patterns)])
        assert result.exit_code == 0

    def test_sanitize_invalid_patterns_file(self, valid_har: Path) -> None:
        """Test error on invalid patterns file."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "/nonexistent/patterns.json"])
        assert result.exit_code == 1


class TestSanitizeOutput:
    """Tests for output verification."""

    def test_sanitize_creates_sanitized_file(self, valid_har: Path) -> None:
        """Test sanitized file is created with correct name."""
        result = runner.invoke(app, ["sanitize", str(valid_har)])
        assert result.exit_code == 0

        sanitized_path = valid_har.parent / "test.sanitized.har"
        assert sanitized_path.exists()

    def test_sanitize_removes_pii(self, valid_har: Path) -> None:
        """Test PII is actually removed from output."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--no-salt"])
        assert result.exit_code == 0

        sanitized_path = valid_har.parent / "test.sanitized.har"
        content = sanitized_path.read_text()

        # Original MAC should be gone
        assert "AA:BB:CC:DD:EE:FF" not in content
        # Placeholder or hash should be present
        assert "XX:XX:XX:XX:XX:XX" in content or "02:" in content

    def test_sanitize_warning_message(self, valid_har: Path) -> None:
        """Test warning message is displayed."""
        result = runner.invoke(app, ["sanitize", str(valid_har)])
        assert result.exit_code == 0
        assert "WARNING: Automated sanitization is best-effort" in result.stdout
        assert "WiFi" in result.stdout
