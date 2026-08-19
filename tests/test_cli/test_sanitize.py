"""Tests for CLI sanitize command."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from har_capture.cli.main import app

runner = CliRunner()

# Test HAR fixtures live in tests/fixtures/test_sanitize.json per docs/CODE_REVIEW.md § Test data lives in JSON fixtures.
_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_sanitize.json").read_text())


def _write_fixture_har(tmp_path: Path, fixture_key: str, filename: str) -> Path:
    """Write a fixture HAR (deep-copied so tests don't mutate the loaded dict)."""
    har_file = tmp_path / filename
    har_file.write_text(json.dumps(copy.deepcopy(_FIXTURES[fixture_key])))
    return har_file


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def valid_har(tmp_path: Path) -> Path:
    """A valid HAR file with PII for testing."""
    return _write_fixture_har(tmp_path, "valid_har", "test.har")


@pytest.fixture
def invalid_json_file(tmp_path: Path) -> Path:
    """An invalid JSON file (intentional malformed string, behavioural-inline per docs/CODE_REVIEW.md § Test data lives in JSON fixtures)."""
    invalid_file = tmp_path / "invalid.har"
    invalid_file.write_text("{not valid json")
    return invalid_file


@pytest.fixture
def invalid_har_structure(tmp_path: Path) -> Path:
    """A JSON file that's not valid HAR (intentional minimal not-a-HAR string, behavioural-inline)."""
    invalid_file = tmp_path / "invalid_structure.har"
    invalid_file.write_text('{"not": "a har file"}')
    return invalid_file


@pytest.fixture
def large_har(tmp_path: Path) -> Path:
    """A HAR file larger than 1MB for size limit testing.

    Loads the structural HAR template from the fixture, then fills the
    dynamic 500KB padding and multiplies the entries list to 1.5MB —
    the size construction is the test's behavioural point and stays in
    Python; only the static structure is fixture-driven.
    """
    har_data = copy.deepcopy(_FIXTURES["large_har_template"])
    har_data.pop("_dynamic", None)
    entry = har_data["log"]["entries"][0]
    entry["response"]["content"]["text"] = "x" * 500000  # 500KB of padding
    har_data["log"]["entries"] = [entry] * 3  # 1.5MB total
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
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])
        assert result.exit_code == 0
        assert "Sanitization Complete" in result.stdout

    def test_sanitize_with_output(self, valid_har: Path, tmp_path: Path) -> None:
        """Test sanitizing with explicit output path."""
        output = tmp_path / "output.har"
        result = runner.invoke(app, ["sanitize", str(valid_har), "-o", str(output), "--patterns", "base"])
        assert result.exit_code == 0
        assert output.exists()

    def test_sanitize_file_not_found(self, tmp_path: Path) -> None:
        """Test error when file doesn't exist."""
        result = runner.invoke(app, ["sanitize", str(tmp_path / "nonexistent.har"), "--patterns", "base"])
        assert result.exit_code == 1
        assert "File not found" in (result.output)

    def test_sanitize_invalid_json(self, invalid_json_file: Path) -> None:
        """Test error on invalid JSON."""
        result = runner.invoke(app, ["sanitize", str(invalid_json_file), "--patterns", "base"])
        assert result.exit_code == 1
        assert "Invalid JSON" in (result.output)

    def test_sanitize_invalid_har_structure(self, invalid_har_structure: Path) -> None:
        """Test error on invalid HAR structure."""
        result = runner.invoke(app, ["sanitize", str(invalid_har_structure), "--patterns", "base"])
        assert result.exit_code == 1
        assert "Invalid HAR" in (result.output)


class TestSanitizeSaltOptions:
    """Tests for salt options."""

    def test_sanitize_with_auto_salt(self, valid_har: Path) -> None:
        """Test default auto salt mode."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])
        assert result.exit_code == 0
        assert "random (correlation within file)" in result.stdout

    def test_sanitize_with_no_salt(self, valid_har: Path) -> None:
        """Test --no-salt option for static placeholders."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--no-salt", "--patterns", "base"])
        assert result.exit_code == 0
        assert "static placeholders" in result.stdout

    def test_sanitize_with_custom_salt(self, valid_har: Path) -> None:
        """Test --salt option with custom value."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--salt", "my-salt", "--patterns", "base"])
        assert result.exit_code == 0
        assert "provided (consistent across runs)" in result.stdout


class TestSanitizeCompression:
    """Tests for compression options."""

    def test_sanitize_with_compress(self, valid_har: Path) -> None:
        """Test --compress option creates .har.gz file."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--compress", "--patterns", "base"])
        assert result.exit_code == 0
        assert "Compressed:" in result.stdout

        # Check compressed file exists
        sanitized_path = valid_har.parent / "test.sanitized.har"
        compressed_path = sanitized_path.with_suffix(".har.gz")
        assert compressed_path.exists()

    def test_sanitize_compression_level(self, valid_har: Path) -> None:
        """Test --compression-level option."""
        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--compress", "--compression-level", "1", "--patterns", "base"]
        )
        assert result.exit_code == 0

    def test_sanitize_invalid_compression_level_high(self, valid_har: Path) -> None:
        """Test error on compression level > 9."""
        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--compression-level", "10", "--patterns", "base"]
        )
        assert result.exit_code == 1
        assert "compression-level must be 1-9" in (result.output)

    def test_sanitize_invalid_compression_level_low(self, valid_har: Path) -> None:
        """Test error on compression level < 1."""
        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--compression-level", "0", "--patterns", "base"]
        )
        assert result.exit_code == 1
        assert "compression-level must be 1-9" in (result.output)


class TestSanitizeSizeLimit:
    """Tests for size limit options."""

    def test_sanitize_default_size_limit(self, large_har: Path) -> None:
        """Test default 100MB limit allows normal files."""
        # Our 1.5MB file should be fine with default 100MB limit
        result = runner.invoke(app, ["sanitize", str(large_har), "--patterns", "base"])
        assert result.exit_code == 0

    def test_sanitize_small_size_limit(self, large_har: Path) -> None:
        """Test --max-size limit enforced."""
        # Set limit to 1MB, file is ~1.5MB
        result = runner.invoke(app, ["sanitize", str(large_har), "--max-size", "1", "--patterns", "base"])
        assert result.exit_code == 1
        assert "File too large" in (result.output)

    def test_sanitize_unlimited_size(self, large_har: Path) -> None:
        """Test --max-size 0 disables limit."""
        result = runner.invoke(app, ["sanitize", str(large_har), "--max-size", "0", "--patterns", "base"])
        assert result.exit_code == 0

    def test_sanitize_negative_size_limit(self, valid_har: Path) -> None:
        """Test error on negative max-size."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--max-size", "-1", "--patterns", "base"])
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
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])
        assert result.exit_code == 0

        sanitized_path = valid_har.parent / "test.sanitized.har"
        assert sanitized_path.exists()

    def test_sanitize_removes_pii(self, valid_har: Path) -> None:
        """Test PII is actually removed from output."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--no-salt", "--patterns", "base"])
        assert result.exit_code == 0

        sanitized_path = valid_har.parent / "test.sanitized.har"
        content = sanitized_path.read_text()

        # Original MAC should be gone
        assert "AA:BB:CC:DD:EE:FF" not in content
        # Placeholder or hash should be present
        assert "XX:XX:XX:XX:XX:XX" in content or "02:" in content

    def test_sanitize_warning_message(self, valid_har: Path) -> None:
        """Test warning message is displayed."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])
        assert result.exit_code == 0
        assert "WARNING: Automated sanitization is best-effort" in result.stdout
        # Verify output shows redacted categories
        assert "Auto-redacted" in result.stdout


# =============================================================================
# Branch coverage: already-sanitized detection, interactive review, exceptions
# =============================================================================
#
# These tests target the branches not exercised by the basic happy-path tests
# above. The ``_stdin_is_tty`` helper in cli/sanitize.py is monkeypatched
# where we need to simulate a real terminal — that's a single private
# seam, not a test override of internal state. Click's CliRunner replaces
# ``sys.stdin`` with a non-TTY stream during ``invoke``, so patching
# ``sys.stdin.isatty`` directly does not stick. The helper isolates that
# OS-level question into one stable patch point.


class TestSanitizeAlreadySanitized:
    """Branch: ``appears_sanitized`` returns True (lines 156-167)."""

    @pytest.fixture
    def already_redacted_har(self, tmp_path: Path) -> Path:
        """A HAR whose body contains 15 well-formed redaction placeholders.

        ``appears_sanitized`` counts patterns like ``MAC_[a-f0-9]{8}``
        and trips at >= 10 matches. Producing the placeholders directly
        avoids depending on the sanitizer's actual hash format and the
        threshold staying constant. The HAR structure is fixture-driven;
        the placeholder-string construction is the behavioural point and
        stays in Python.
        """
        har_data = copy.deepcopy(_FIXTURES["already_redacted_har_template"])
        har_data.pop("_dynamic", None)
        placeholders = " ".join(f"MAC_{i:08x}" for i in range(15))
        har_data["log"]["entries"][0]["response"]["content"]["text"] = placeholders
        har_file = tmp_path / "already_sanitized.har"
        har_file.write_text(json.dumps(har_data))
        return har_file

    def test_warning_printed_in_non_interactive_mode(self, already_redacted_har: Path) -> None:
        """Non-interactive (CliRunner) path: warn but proceed."""
        result = runner.invoke(app, ["sanitize", str(already_redacted_har), "--patterns", "base"])
        assert result.exit_code == 0
        assert "already be sanitized" in result.output
        assert "Non-interactive mode: proceeding anyway" in result.output

    def test_interactive_confirm_no_aborts(
        self,
        already_redacted_har: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """isatty=True + user answers "n" -> exit 0 with "Aborted"."""
        monkeypatch.setattr("har_capture.cli.sanitize._stdin_is_tty", lambda: True)
        result = runner.invoke(
            app, ["sanitize", str(already_redacted_har), "--patterns", "base"], input="n\n"
        )
        assert "already be sanitized" in result.output
        assert "Aborted" in result.output
        assert result.exit_code == 0

    def test_interactive_confirm_yes_continues(
        self,
        already_redacted_har: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """isatty=True + user answers "y" -> sanitization proceeds."""
        monkeypatch.setattr("har_capture.cli.sanitize._stdin_is_tty", lambda: True)
        result = runner.invoke(
            app, ["sanitize", str(already_redacted_har), "--patterns", "base"], input="y\n"
        )
        assert "already be sanitized" in result.output
        assert "Aborted" not in result.output
        assert result.exit_code == 0


class TestSanitizeInteractiveReview:
    r"""Branch: TTY + flagged values trigger ``run_interactive_review`` (184-201).

    The interactive review machinery itself lives in ``cli/interactive.py``
    and is tested separately. Here we only verify the wiring: that the
    sanitize command calls into it when the conditions are right, and
    skips it when they aren't.

    The fixture HAR uses form fields named ``username`` / ``login`` /
    ``account_id`` — these are the live "flag" field-name patterns
    (``\buser(?:_?name)?\b|login|...|account_id|...``) compiled at
    module load. Any value pinned to those keys gets flagged for review,
    so we get a populated ``report.flagged`` without mocking the core
    library.
    """

    @pytest.fixture
    def har_with_flagged_fields(self, tmp_path: Path) -> Path:
        return _write_fixture_har(tmp_path, "har_with_flagged_fields", "flagged.har")

    def test_review_invoked_when_tty_and_flagged(
        self,
        har_with_flagged_fields: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """isatty=True + non-empty ``report.flagged`` -> review runs.

        ``run_interactive_review`` is replaced at the import boundary
        (``har_capture.cli.interactive``) — that's a module-level seam,
        not internal state. ``display_summary`` and
        ``apply_reviewed_redactions`` get the same treatment so the
        test doesn't actually drive an interactive prompt loop.
        """
        from har_capture.cli import interactive as interactive_mod

        monkeypatch.setattr("har_capture.cli.sanitize._stdin_is_tty", lambda: True)

        review_calls: list[dict[str, Any]] = []
        summary_calls: list[Any] = []

        def fake_review(report: Any, **kwargs: Any) -> bool:
            review_calls.append(kwargs)
            # User reviewed but redacted nothing -> apply path skipped.
            return True

        monkeypatch.setattr(interactive_mod, "run_interactive_review", fake_review)
        monkeypatch.setattr(interactive_mod, "display_summary", summary_calls.append)
        monkeypatch.setattr(
            interactive_mod,
            "apply_reviewed_redactions",
            lambda *a, **k: pytest.fail("apply must not run when user redacted nothing"),
        )

        result = runner.invoke(app, ["sanitize", str(har_with_flagged_fields), "--patterns", "base"])

        assert result.exit_code == 0
        assert review_calls, "run_interactive_review was not invoked"
        assert summary_calls, "display_summary must run after review"
        # Review received the kwargs the CLI is contracted to pass.
        kwargs = review_calls[0]
        assert "input_path" in kwargs
        assert "output_path" in kwargs
        assert "salt_mode" in kwargs

    def test_apply_redactions_when_user_redacted(
        self,
        har_with_flagged_fields: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Branch 193->196: ``total_user_redacted > 0`` -> apply runs."""
        from har_capture.cli import interactive as interactive_mod

        monkeypatch.setattr("har_capture.cli.sanitize._stdin_is_tty", lambda: True)

        apply_calls: list[tuple[Any, str]] = []

        def fake_review(report: Any, **kwargs: Any) -> bool:
            # Force the post-review counter so the apply branch fires.
            for f in report.flagged:
                from har_capture.sanitization.report import RedactionStatus

                f.status = RedactionStatus.USER_REDACTED
                f.user_replacement = "REDACTED"
            return True

        def fake_apply(report: Any, path: str) -> None:
            apply_calls.append((report, path))

        monkeypatch.setattr(interactive_mod, "run_interactive_review", fake_review)
        monkeypatch.setattr(interactive_mod, "apply_reviewed_redactions", fake_apply)
        monkeypatch.setattr(interactive_mod, "display_summary", lambda r: None)

        result = runner.invoke(app, ["sanitize", str(har_with_flagged_fields), "--patterns", "base"])

        assert result.exit_code == 0
        assert apply_calls, "apply_reviewed_redactions must run when user redacted"


class TestSanitizeReportOption:
    """Branch: ``--report`` writes JSON report (lines 213-217)."""

    def test_report_written(self, valid_har: Path, tmp_path: Path) -> None:
        report_path = tmp_path / "report.json"
        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--report", str(report_path), "--patterns", "base"]
        )
        assert result.exit_code == 0
        assert report_path.exists()
        # Report is valid JSON.
        json.loads(report_path.read_text())

    def test_report_auto_path_in_non_interactive_mode(self, valid_har: Path) -> None:
        """Non-TTY without --report -> auto-named .review.json beside input."""
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])
        # The auto-path is created next to the input file.
        auto_path = Path(str(valid_har) + ".review.json")
        # Whether it actually exists depends on whether anything was
        # flagged — we assert only the no-crash path.
        assert result.exit_code == 0
        # If it does exist, it should be valid JSON.
        if auto_path.exists():
            json.loads(auto_path.read_text())


# Note on remaining uncovered lines in cli/sanitize.py
# -----------------------------------------------------
# Lines 239-243 (FileNotFoundError, PermissionError) and 247-252
# (PatternLoadError, OSError) are defensive exception handlers that
# are not naturally reachable from the CLI surface:
#
#   * typer's ``Path`` argument conversion rejects unreadable / missing
#     files at parse time (exit code 2), so the input-file branches
#     of these handlers never fire.
#   * ``resolve_patterns_arg`` is called outside the try block, so
#     bad ``--patterns`` paths propagate directly without hitting
#     line 247 — and the pattern loader inside ``sanitize_har_file``
#     is lenient with malformed-shape patterns rather than raising.
#
# These handlers exist as a safety net for downstream library callers
# that bypass typer's parameter validation, which is a reasonable
# defensive shape. Adding tests that mock low-level I/O to drag
# coverage over them would be theatrical (docs/CODE_REVIEW.md § Test
# overrides are a code smell). The per-module
# floor for cli/sanitize.py is set at the post-test coverage so any
# new uncovered code lowers the floor.


class TestCompletenessReporting:
    """`sanitize` reports completeness against the file it just produced."""

    _COMPLETENESS = json.loads(
        (Path(__file__).parent.parent / "fixtures" / "test_completeness.json").read_text()
    )

    def _write(self, tmp_path: Path, fixture_key: str, filename: str) -> Path:
        """Write a completeness fixture HAR into tmp_path."""
        har_file = tmp_path / filename
        har_file.write_text(json.dumps(copy.deepcopy(self._COMPLETENESS[fixture_key])))
        return har_file

    def test_reports_gaps_after_sanitizing(self, tmp_path: Path) -> None:
        """Test gaps surface even though sanitization redacted the cookie value.

        Sanitization replaces the cookie *value* but keeps the *name*, which
        is all the mid-session check reads.
        """
        har = self._write(tmp_path, "mid_session_and_no_post", "mid.har")

        result = runner.invoke(app, ["sanitize", str(har), "--patterns", "base"])

        assert result.exit_code == 0
        assert "Capture coverage:" in result.output
        assert result.output.count("WARNING: Recording began mid-session") == 1

    def test_complete_capture_reports_no_gaps(self, tmp_path: Path) -> None:
        """Test a capture holding the login exchange raises no gap warnings."""
        har = self._write(tmp_path, "clean_login_flow", "clean_flow.har")

        result = runner.invoke(app, ["sanitize", str(har), "--patterns", "base"])

        assert result.exit_code == 0
        assert "POST requests: 2" in result.output
        assert "Recording began mid-session" not in result.output


class TestStaleSiblingRefresh:
    """A sanitize run must refresh an existing .gz sibling it just made stale.

    Every sanitize pass rewrites the .sanitized.har (fresh salt), so a
    sibling .gz from an earlier --compress run diverges even when the
    review applies nothing. Without the refresh, the stale sibling — the
    upload artifact — survives silently (2026-08-19 CM2500 finding).
    """

    def test_existing_sibling_regenerated_without_compress(self, valid_har: Path) -> None:
        import gzip

        sanitized = valid_har.parent / "test.sanitized.har"
        sibling = valid_har.parent / "test.sanitized.har.gz"
        with gzip.open(sibling, "wb") as f:
            f.write(b'{"log": {"entries": [], "old": "pre-rewrite content"}}')

        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])

        assert result.exit_code == 0
        assert "Regenerated compressed file" in result.output
        with gzip.open(sibling, "rb") as f:
            assert f.read() == sanitized.read_bytes()

    def test_no_sibling_creates_nothing(self, valid_har: Path) -> None:
        result = runner.invoke(app, ["sanitize", str(valid_har), "--patterns", "base"])

        assert result.exit_code == 0
        assert not (valid_har.parent / "test.sanitized.har.gz").exists()
