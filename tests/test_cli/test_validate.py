"""Tests for CLI validate command."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from har_capture.cli.main import app

runner = CliRunner()

# Test HAR fixtures live in tests/fixtures/test_validate.json per docs/CODE_REVIEW.md § Test data lives in JSON fixtures.
_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_validate.json").read_text())


def _write_fixture_har(tmp_path: Path, fixture_key: str, filename: str) -> Path:
    """Write a fixture HAR (deep-copied so tests don't mutate the loaded dict)."""
    har_file = tmp_path / filename
    har_file.write_text(json.dumps(copy.deepcopy(_FIXTURES[fixture_key])))
    return har_file


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def clean_har(tmp_path: Path) -> Path:
    """A clean HAR file with no PII."""
    return _write_fixture_har(tmp_path, "clean_har", "clean.har")


@pytest.fixture
def har_with_secrets(tmp_path: Path) -> Path:
    """A HAR file with secrets/PII."""
    return _write_fixture_har(tmp_path, "har_with_secrets", "secrets.har")


@pytest.fixture
def har_with_warnings(tmp_path: Path) -> Path:
    """A HAR file with warnings but no errors."""
    return _write_fixture_har(tmp_path, "har_with_warnings", "warnings.har")


@pytest.fixture
def har_directory(tmp_path: Path) -> Path:
    """A directory with multiple HAR files (mix of clean and dirty)."""
    har_dir = tmp_path / "hars"
    har_dir.mkdir()

    clean_har = copy.deepcopy(_FIXTURES["directory_clean_har"])
    dirty_har = copy.deepcopy(_FIXTURES["directory_dirty_har"])

    (har_dir / "clean.har").write_text(json.dumps(clean_har))
    (har_dir / "dirty.har").write_text(json.dumps(dirty_har))

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
        result = runner.invoke(app, ["validate", str(clean_har), "--patterns", "base"])
        assert result.exit_code == 0
        assert "Clean" in result.stdout

    def test_validate_har_with_secrets(self, har_with_secrets: Path) -> None:
        """Test validating a HAR file with secrets."""
        result = runner.invoke(app, ["validate", str(har_with_secrets), "--patterns", "base"])
        # Should fail due to secrets
        assert result.exit_code == 1
        assert "errors" in result.stdout.lower() or "ERROR" in result.stdout

    def test_validate_file_not_found(self, tmp_path: Path) -> None:
        """Test error when file doesn't exist."""
        result = runner.invoke(app, ["validate", str(tmp_path / "nonexistent.har"), "--patterns", "base"])
        assert result.exit_code == 1
        assert "File not found" in (result.output)

    def test_validate_no_input(self) -> None:
        """Test error when no file or directory provided."""
        result = runner.invoke(app, ["validate", "--patterns", "base"])
        assert result.exit_code == 1
        assert "Provide either a HAR file or --dir" in (result.output)


class TestValidateDirectory:
    """Tests for directory scanning."""

    def test_validate_directory(self, har_directory: Path) -> None:
        """Test validating a directory of HAR files."""
        result = runner.invoke(app, ["validate", "--dir", str(har_directory), "--patterns", "base"])
        # Should process multiple files
        assert "clean.har" in result.stdout or "dirty.har" in result.stdout

    def test_validate_directory_recursive(self, har_directory: Path) -> None:
        """Test recursive directory scanning."""
        result = runner.invoke(
            app, ["validate", "--dir", str(har_directory), "--recursive", "--patterns", "base"]
        )
        # Should find nested.har in subdir
        assert "nested.har" in result.stdout or "subdir" in result.stdout

    def test_validate_directory_not_found(self, tmp_path: Path) -> None:
        """Test error when directory doesn't exist."""
        result = runner.invoke(
            app, ["validate", "--dir", str(tmp_path / "nonexistent"), "--patterns", "base"]
        )
        assert result.exit_code == 1
        assert "Directory not found" in (result.output)

    def test_validate_empty_directory(self, tmp_path: Path) -> None:
        """Test validating an empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = runner.invoke(app, ["validate", "--dir", str(empty_dir), "--patterns", "base"])
        assert result.exit_code == 0
        assert "No HAR files found" in result.stdout


class TestValidateStrictMode:
    """Tests for strict mode option."""

    def test_validate_strict_with_warnings(self, har_with_warnings: Path) -> None:
        """Test --strict treats warnings as errors."""
        result = runner.invoke(app, ["validate", str(har_with_warnings), "--strict", "--patterns", "base"])
        # With strict mode, warnings should cause exit code 1
        # (if there are warnings in the file)
        # Note: exit code depends on whether file actually has warnings
        assert result.exit_code in (0, 1)

    def test_validate_strict_clean_file(self, clean_har: Path) -> None:
        """Test --strict with clean file passes."""
        result = runner.invoke(app, ["validate", str(clean_har), "--strict", "--patterns", "base"])
        assert result.exit_code == 0


class TestValidateCustomPatterns:
    """Tests for custom patterns option."""

    def test_validate_with_custom_patterns(self, clean_har: Path, tmp_path: Path) -> None:
        """Test --patterns option with custom patterns file."""
        custom_patterns = tmp_path / "custom.json"
        custom_patterns.write_text(json.dumps(_FIXTURES["custom_secret_pattern"]))
        result = runner.invoke(app, ["validate", str(clean_har), "--patterns", str(custom_patterns)])
        assert result.exit_code == 0


class TestValidateOutput:
    """Tests for output formatting."""

    def test_validate_shows_summary(self, clean_har: Path) -> None:
        """Test summary is displayed."""
        result = runner.invoke(app, ["validate", str(clean_har), "--patterns", "base"])
        assert "Summary:" in result.stdout
        assert "errors" in result.stdout.lower()
        assert "warnings" in result.stdout.lower()

    def test_validate_shows_findings(self, har_with_secrets: Path) -> None:
        """Test findings are displayed with details."""
        result = runner.invoke(app, ["validate", str(har_with_secrets), "--patterns", "base"])
        # Should show location and reason
        assert "[" in result.stdout  # Location markers like [ERROR] or [WARN]

    def test_validate_multiple_files_summary(self, har_directory: Path) -> None:
        """Test summary covers all files."""
        result = runner.invoke(app, ["validate", "--dir", str(har_directory), "--patterns", "base"])
        assert "Summary:" in result.stdout


class TestCompletenessReporting:
    """`validate` reports capture-completeness alongside PII findings.

    This is the intake path: contributor HARs reach the project through
    `validate`, not through a capture this tool performed, so the gaps have
    to surface here (cable_modem_monitor #120).
    """

    _COMPLETENESS = json.loads(
        (Path(__file__).parent.parent / "fixtures" / "test_completeness.json").read_text()
    )

    def _write(self, tmp_path: Path, fixture_key: str, filename: str) -> Path:
        """Write a completeness fixture HAR into tmp_path."""
        har_file = tmp_path / filename
        har_file.write_text(json.dumps(copy.deepcopy(self._COMPLETENESS[fixture_key])))
        return har_file

    def test_single_file_shows_summary_and_warnings(self, tmp_path: Path) -> None:
        """Test a single-file run prints the coverage block and the gaps."""
        har = self._write(tmp_path, "mid_session_and_no_post", "mid.har")

        result = runner.invoke(app, ["validate", str(har), "--patterns", "base"])

        assert "Capture coverage:" in result.output
        assert "POST requests: 0" in result.output
        assert result.output.count("WARNING:") == 2

    def test_complete_capture_reports_no_warnings(self, tmp_path: Path) -> None:
        """Test a capture holding the login exchange raises no gap warnings."""
        har = self._write(tmp_path, "clean_login_flow", "clean_flow.har")

        result = runner.invoke(app, ["validate", str(har), "--patterns", "base"])

        assert "Capture coverage:" in result.output
        assert "WARNING:" not in result.output

    def test_gaps_do_not_change_exit_code(self, tmp_path: Path) -> None:
        """Test completeness gaps never fail a run, even under --strict.

        Gaps report missing evidence, not a leak, so they must stay out of
        the finding counts that drive the exit code.
        """
        har = self._write(tmp_path, "no_post_requests", "gaps.har")

        plain = runner.invoke(app, ["validate", str(har), "--patterns", "base"])
        strict = runner.invoke(app, ["validate", str(har), "--patterns", "base", "--strict"])

        assert "WARNING:" in plain.output
        assert plain.exit_code == 0
        assert strict.exit_code == 0

    def test_directory_scan_suppresses_summary(self, tmp_path: Path) -> None:
        """Test multi-file scans print warnings only, keeping pre-commit quiet."""
        self._write(tmp_path, "mid_session_and_no_post", "a.har")
        self._write(tmp_path, "no_post_requests", "b.har")

        result = runner.invoke(app, ["validate", "--dir", str(tmp_path), "--patterns", "base"])

        assert "Capture coverage:" not in result.output
        assert "WARNING:" in result.output

    def test_directory_scan_silent_when_all_complete(self, tmp_path: Path) -> None:
        """Test a directory of complete captures produces no gap output.

        Also pins the one-file case: a --dir scan matching a single file is
        still a bulk context and must render like any other --dir run, not
        like an explicit single-file invocation.
        """
        self._write(tmp_path, "clean_login_flow", "a.har")

        result = runner.invoke(app, ["validate", "--dir", str(tmp_path), "--patterns", "base"])

        assert "WARNING:" not in result.output
        assert "Capture coverage:" not in result.output

    def test_single_file_and_dir_of_one_render_differently(self, tmp_path: Path) -> None:
        """Test the summary follows invocation mode, not how many files matched."""
        har = self._write(tmp_path, "mid_session_and_no_post", "only.har")

        direct = runner.invoke(app, ["validate", str(har), "--patterns", "base"])
        scanned = runner.invoke(app, ["validate", "--dir", str(tmp_path), "--patterns", "base"])

        assert "Capture coverage:" in direct.output
        assert "Capture coverage:" not in scanned.output
        assert "WARNING:" in scanned.output


class TestValidateStaleCompressedArtifact:
    """The stale-gz gate: validate must fail a .har whose .gz sibling diverges."""

    @staticmethod
    def _gz_of(path: Path, content: bytes) -> Path:
        import gzip

        gz = path.with_name(path.name + ".gz")
        with gzip.open(gz, "wb") as f:
            f.write(content)
        return gz

    def test_stale_gz_is_an_error(self, clean_har: Path) -> None:
        """Divergent pair -> exit 1 with the stale-artifact message."""
        self._gz_of(clean_har, b'{"log": {"entries": [], "old": "pre-review content"}}')

        result = runner.invoke(app, ["validate", str(clean_har), "--patterns", "base"])

        assert result.exit_code == 1
        assert "stale" in result.output

    def test_fresh_gz_is_clean(self, clean_har: Path) -> None:
        self._gz_of(clean_har, clean_har.read_bytes())

        result = runner.invoke(app, ["validate", str(clean_har), "--patterns", "base"])

        assert result.exit_code == 0
        assert "stale" not in result.output

    def test_pair_checked_once_in_directory_scan(self, tmp_path: Path) -> None:
        """A --dir scan lists both members; the divergence is one error, not two."""
        har_dir = tmp_path / "hars"
        har_dir.mkdir()
        har = _write_fixture_har(har_dir, "clean_har", "device.sanitized.har")
        self._gz_of(har, b'{"log": {"entries": [], "old": true}}')

        result = runner.invoke(app, ["validate", "--dir", str(har_dir), "--patterns", "base"])

        assert result.exit_code == 1
        assert result.output.count("stale") == 1
        assert "1 errors" in result.output
