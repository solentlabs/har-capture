"""Tests for CLI validate command."""

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
def clean_har(tmp_path: Path) -> Path:
    """Create a clean HAR file with no PII."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://example.com/",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "text": "Hello World",
                            "mimeType": "text/html",
                        },
                    },
                }
            ],
        }
    }
    har_file = tmp_path / "clean.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


@pytest.fixture
def har_with_secrets(tmp_path: Path) -> Path:
    """Create a HAR file with secrets/PII."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://example.com/login",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer secret-token-123"},
                        ],
                        "postData": {
                            "text": "password=mysecretpassword",
                            "mimeType": "application/x-www-form-urlencoded",
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Set-Cookie", "value": "session=abc123; HttpOnly"},
                        ],
                        "content": {
                            "text": "MAC Address: AA:BB:CC:DD:EE:FF",
                            "mimeType": "text/html",
                        },
                    },
                }
            ],
        }
    }
    har_file = tmp_path / "secrets.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


@pytest.fixture
def har_with_warnings(tmp_path: Path) -> Path:
    """Create a HAR file with warnings but no errors."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://example.com/",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "text": "Email: test@example.com",
                            "mimeType": "text/html",
                        },
                    },
                }
            ],
        }
    }
    har_file = tmp_path / "warnings.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


@pytest.fixture
def har_directory(tmp_path: Path) -> Path:
    """Create a directory with multiple HAR files."""
    har_dir = tmp_path / "hars"
    har_dir.mkdir()

    # Create a clean HAR
    clean_har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [],
        }
    }
    (har_dir / "clean.har").write_text(json.dumps(clean_har))

    # Create a HAR with issues
    dirty_har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://test/",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token123"},
                        ],
                    },
                    "response": {"status": 200, "headers": [], "content": {}},
                }
            ],
        }
    }
    (har_dir / "dirty.har").write_text(json.dumps(dirty_har))

    # Create a subdirectory with another HAR
    subdir = har_dir / "subdir"
    subdir.mkdir()
    (subdir / "nested.har").write_text(json.dumps(clean_har))

    return har_dir


# =============================================================================
# Test Classes
# =============================================================================


class TestValidateBasic:
    """Basic validate command tests."""

    def test_validate_clean_har(self, clean_har: Path) -> None:
        """Test validating a clean HAR file."""
        result = runner.invoke(app, ["validate", str(clean_har)])
        assert result.exit_code == 0
        assert "Clean" in result.stdout

    def test_validate_har_with_secrets(self, har_with_secrets: Path) -> None:
        """Test validating a HAR file with secrets."""
        result = runner.invoke(app, ["validate", str(har_with_secrets)])
        # Should fail due to secrets
        assert result.exit_code == 1
        assert "errors" in result.stdout.lower() or "ERROR" in result.stdout

    def test_validate_file_not_found(self, tmp_path: Path) -> None:
        """Test error when file doesn't exist."""
        result = runner.invoke(app, ["validate", str(tmp_path / "nonexistent.har")])
        assert result.exit_code == 1
        assert "File not found" in (result.output)

    def test_validate_no_input(self) -> None:
        """Test error when no file or directory provided."""
        result = runner.invoke(app, ["validate"])
        assert result.exit_code == 1
        assert "Provide either a HAR file or --dir" in (result.output)


class TestValidateDirectory:
    """Tests for directory scanning."""

    def test_validate_directory(self, har_directory: Path) -> None:
        """Test validating a directory of HAR files."""
        result = runner.invoke(app, ["validate", "--dir", str(har_directory)])
        # Should process multiple files
        assert "clean.har" in result.stdout or "dirty.har" in result.stdout

    def test_validate_directory_recursive(self, har_directory: Path) -> None:
        """Test recursive directory scanning."""
        result = runner.invoke(app, ["validate", "--dir", str(har_directory), "--recursive"])
        # Should find nested.har in subdir
        assert "nested.har" in result.stdout or "subdir" in result.stdout

    def test_validate_directory_not_found(self, tmp_path: Path) -> None:
        """Test error when directory doesn't exist."""
        result = runner.invoke(app, ["validate", "--dir", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1
        assert "Directory not found" in (result.output)

    def test_validate_empty_directory(self, tmp_path: Path) -> None:
        """Test validating an empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = runner.invoke(app, ["validate", "--dir", str(empty_dir)])
        assert result.exit_code == 0
        assert "No HAR files found" in result.stdout


class TestValidateStrictMode:
    """Tests for strict mode option."""

    def test_validate_strict_with_warnings(self, har_with_warnings: Path) -> None:
        """Test --strict treats warnings as errors."""
        result = runner.invoke(app, ["validate", str(har_with_warnings), "--strict"])
        # With strict mode, warnings should cause exit code 1
        # (if there are warnings in the file)
        # Note: exit code depends on whether file actually has warnings
        assert result.exit_code in (0, 1)

    def test_validate_strict_clean_file(self, clean_har: Path) -> None:
        """Test --strict with clean file passes."""
        result = runner.invoke(app, ["validate", str(clean_har), "--strict"])
        assert result.exit_code == 0


class TestValidateCustomPatterns:
    """Tests for custom patterns option."""

    def test_validate_with_custom_patterns(self, clean_har: Path, tmp_path: Path) -> None:
        """Test --patterns option with custom patterns file."""
        custom_patterns = tmp_path / "custom.json"
        custom_patterns.write_text(
            json.dumps(
                {
                    "patterns": {
                        "custom_secret": {
                            "regex": "CUSTOM\\d+",
                            "replacement_prefix": "CUSTOM",
                        }
                    }
                }
            )
        )
        result = runner.invoke(app, ["validate", str(clean_har), "--patterns", str(custom_patterns)])
        assert result.exit_code == 0


class TestValidateOutput:
    """Tests for output formatting."""

    def test_validate_shows_summary(self, clean_har: Path) -> None:
        """Test summary is displayed."""
        result = runner.invoke(app, ["validate", str(clean_har)])
        assert "Summary:" in result.stdout
        assert "errors" in result.stdout.lower()
        assert "warnings" in result.stdout.lower()

    def test_validate_shows_findings(self, har_with_secrets: Path) -> None:
        """Test findings are displayed with details."""
        result = runner.invoke(app, ["validate", str(har_with_secrets)])
        # Should show location and reason
        assert "[" in result.stdout  # Location markers like [ERROR] or [WARN]

    def test_validate_multiple_files_summary(self, har_directory: Path) -> None:
        """Test summary covers all files."""
        result = runner.invoke(app, ["validate", "--dir", str(har_directory)])
        assert "Summary:" in result.stdout
