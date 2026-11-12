"""Tests for CLI sanitize command."""

from __future__ import annotations

import copy
import json
import os
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
# above. The ``stdin_is_tty`` helper in cli/interactive.py is monkeypatched
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
        monkeypatch.setattr("har_capture.cli.interactive.stdin_is_tty", lambda: True)
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
        monkeypatch.setattr("har_capture.cli.interactive.stdin_is_tty", lambda: True)
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

    @pytest.mark.parametrize("redact", [False, True], ids=["nothing_redacted", "user_redacted"])
    def test_review_outcome_recorded_when_tty_and_flagged(
        self,
        har_with_flagged_fields: Path,
        monkeypatch: pytest.MonkeyPatch,
        redact: bool,
    ) -> None:
        """isatty=True + flagged -> review runs and its outcome is always saved.

        ``run_interactive_review`` is replaced at the import boundary
        (``har_capture.cli.interactive``) — a module-level seam, not
        internal state — so no prompt loop runs. The outcome is saved even
        when the user redacted nothing: that decision is what the file
        must record.
        """
        from har_capture.cli import interactive as interactive_mod
        from har_capture.sanitization.report import RedactionStatus, ReviewOutcome

        monkeypatch.setattr("har_capture.cli.interactive.stdin_is_tty", lambda: True)

        review_calls: list[dict[str, Any]] = []
        summary_calls: list[Any] = []

        def fake_review(report: Any, **kwargs: Any) -> ReviewOutcome:
            review_calls.append(kwargs)
            for f in report.flagged:
                f.status = RedactionStatus.USER_REDACTED if redact else RedactionStatus.USER_SKIPPED
            return ReviewOutcome.COMPLETED

        monkeypatch.setattr(interactive_mod, "run_interactive_review", fake_review)
        monkeypatch.setattr(interactive_mod, "display_summary", summary_calls.append)

        result = runner.invoke(app, ["sanitize", str(har_with_flagged_fields), "--patterns", "base"])

        assert result.exit_code == 0
        assert review_calls, "run_interactive_review was not invoked"
        assert summary_calls, "display_summary must run after review"
        assert {"input_path", "output_path", "salt_mode"} <= set(review_calls[0])
        written = json.loads(Path(str(har_with_flagged_fields).replace(".har", ".sanitized.har")).read_text())
        meta = written["log"]["_har_capture"]["sanitization"]
        assert meta["review"] == "completed"
        assert (meta["user_redacted"] > 0) == redact

    def test_no_tty_records_no_tty_and_writes_report(self, har_with_flagged_fields: Path) -> None:
        """Without a terminal the file records no_tty; sanitize still writes .review.json.

        The input is already on disk, so the report beside it adds no raw
        copy — unlike ``get``, which writes none.
        """
        result = runner.invoke(app, ["sanitize", str(har_with_flagged_fields), "--patterns", "base"])

        assert result.exit_code == 0
        written = json.loads(Path(str(har_with_flagged_fields).replace(".har", ".sanitized.har")).read_text())
        assert written["log"]["_har_capture"]["sanitization"]["review"] == "no_tty"
        assert Path(str(har_with_flagged_fields) + ".review.json").exists()
        assert "NOT reviewed" in result.output


class TestSanitizeApplyReview:
    """``--apply-review``: a decided review report stands in for the prompt."""

    @pytest.fixture
    def har_with_flagged_fields(self, tmp_path: Path) -> Path:
        return _write_fixture_har(tmp_path, "har_with_flagged_fields", "flagged.har")

    @staticmethod
    def _first_run(har: Path) -> tuple[Path, Path, dict]:
        """Sanitize without a terminal; return the output, the report path and the report."""
        assert runner.invoke(app, ["sanitize", str(har), "--patterns", "base"]).exit_code == 0
        report = Path(str(har) + ".review.json")
        return Path(str(har).replace(".har", ".sanitized.har")), report, json.loads(report.read_text())

    @pytest.mark.parametrize(
        ("status", "kept"),
        [("user", False), ("skipped", True)],
        ids=["every-value-redacted", "every-value-kept"],
    )
    def test_decided_report_completes_the_review(
        self, har_with_flagged_fields: Path, status: str, kept: bool
    ) -> None:
        output, report_path, report = self._first_run(har_with_flagged_fields)
        for item in report["flagged"]:
            item["status"] = status
        report_path.write_text(json.dumps(report))

        result = runner.invoke(
            app,
            [
                "sanitize",
                str(har_with_flagged_fields),
                "--patterns",
                "base",
                "--apply-review",
                str(report_path),
            ],
        )

        assert result.exit_code == 0, result.output
        text = output.read_text()
        meta = json.loads(text)["log"]["_har_capture"]["sanitization"]
        assert meta["review"] == "completed"
        assert meta["user_redacted" if status == "user" else "user_skipped"] == len(report["flagged"])
        assert all((json.dumps(item["value"])[1:-1] in text) is kept for item in report["flagged"])
        assert "No terminal detected" not in result.output

    def test_undecided_value_fails_and_writes_the_rest_back(self, har_with_flagged_fields: Path) -> None:
        output, report_path, report = self._first_run(har_with_flagged_fields)
        decided = har_with_flagged_fields.parent / "decided.json"
        decided.write_text(json.dumps(report))  # every item still "flagged"
        report_path.unlink()

        result = runner.invoke(
            app,
            ["sanitize", str(har_with_flagged_fields), "--patterns", "base", "--apply-review", str(decided)],
        )

        assert result.exit_code == 1
        assert "have no decision" in result.output
        assert json.loads(output.read_text())["log"]["_har_capture"]["sanitization"]["review"] == "cancelled"
        assert report_path.exists()

    def test_unusable_report_stops_before_any_output(self, har_with_flagged_fields: Path) -> None:
        bad = har_with_flagged_fields.parent / "bad.json"
        bad.write_text('{"flagged": [{"value": "x", "status": "redact"}]}')

        result = runner.invoke(
            app, ["sanitize", str(har_with_flagged_fields), "--patterns", "base", "--apply-review", str(bad)]
        )

        assert result.exit_code == 1
        assert "Cannot read review report" in result.output
        assert not Path(str(har_with_flagged_fields).replace(".har", ".sanitized.har")).exists()

    def test_nothing_flagged_needs_no_decisions(self, valid_har: Path, tmp_path: Path) -> None:
        empty = tmp_path / "empty.json"
        empty.write_text('{"flagged": []}')

        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--patterns", "base", "--apply-review", str(empty)]
        )

        assert result.exit_code == 0, result.output


class TestSanitizeReviewStreams:
    """``--report -`` and ``--apply-review -``: the review report never touches disk."""

    @pytest.fixture
    def har_with_flagged_fields(self, tmp_path: Path) -> Path:
        return _write_fixture_har(tmp_path, "har_with_flagged_fields", "flagged.har")

    @staticmethod
    def _run(har: Path, *options: str, stdin: str | None = None):
        return runner.invoke(app, ["sanitize", str(har), "--patterns", "base", *options], input=stdin)

    def _report(self, har: Path) -> dict:
        """The report of a no-terminal run, read from standard output."""
        result = self._run(har, "--report", "-")
        assert result.exit_code == 0, result.output
        return json.loads(result.stdout)

    def test_report_on_stdout_is_the_report_alone_and_no_file_is_written(
        self, har_with_flagged_fields: Path
    ) -> None:
        result = self._run(har_with_flagged_fields, "--report", "-")

        report = json.loads(result.stdout)  # nothing but the report on standard output
        assert report["flagged"]
        assert "NOT reviewed" in result.stderr
        assert "standard output" in result.stderr
        assert not list(har_with_flagged_fields.parent.glob("*.review.json"))

    @pytest.mark.parametrize(
        ("status", "kept"),
        [("user", False), ("skipped", True)],
        ids=["every-value-redacted", "every-value-kept"],
    )
    def test_decisions_on_stdin_complete_the_review(
        self, har_with_flagged_fields: Path, status: str, kept: bool
    ) -> None:
        report = self._report(har_with_flagged_fields)
        for item in report["flagged"]:
            item["status"] = status

        result = self._run(har_with_flagged_fields, "--apply-review", "-", stdin=json.dumps(report))

        assert result.exit_code == 0, result.output
        assert result.stdout == ""  # every value decided: nothing to hand back
        text = Path(str(har_with_flagged_fields).replace(".har", ".sanitized.har")).read_text()
        assert json.loads(text)["log"]["_har_capture"]["sanitization"]["review"] == "completed"
        assert all((json.dumps(item["value"])[1:-1] in text) is kept for item in report["flagged"])
        assert not list(har_with_flagged_fields.parent.glob("*.review.json"))

    def test_undecided_remainder_comes_back_on_stdout(self, har_with_flagged_fields: Path) -> None:
        report = self._report(har_with_flagged_fields)  # every item still "flagged"

        result = self._run(har_with_flagged_fields, "--apply-review", "-", stdin=json.dumps(report))

        assert result.exit_code == 1
        assert [item["status"] for item in json.loads(result.stdout)["flagged"]] == ["flagged"] * len(
            report["flagged"]
        )
        assert "the report on standard output" in result.stderr
        assert not list(har_with_flagged_fields.parent.glob("*.review.json"))

    def test_undecided_remainder_goes_to_a_named_report_file(self, har_with_flagged_fields: Path) -> None:
        report = self._report(har_with_flagged_fields)
        remainder = har_with_flagged_fields.parent / "remainder.json"

        result = self._run(
            har_with_flagged_fields,
            "--apply-review",
            "-",
            "--report",
            str(remainder),
            stdin=json.dumps(report),
        )

        assert result.exit_code == 1
        assert json.loads(remainder.read_text())["flagged"]
        assert str(remainder) in result.output

    @pytest.mark.parametrize(
        "stdin",
        ["{not json", '{"flagged": [{"value": "x", "status": "redact"}]}'],
        ids=["not-json", "unknown-status"],
    )
    def test_unusable_stdin_stops_before_any_output(self, har_with_flagged_fields: Path, stdin: str) -> None:
        result = self._run(har_with_flagged_fields, "--apply-review", "-", stdin=stdin)

        assert result.exit_code == 1
        assert "Cannot read review report from standard input" in result.output
        assert not Path(str(har_with_flagged_fields).replace(".har", ".sanitized.har")).exists()


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

    def test_report_written_with_lf_endings(
        self, valid_har: Path, tmp_path: Path, windows_text_mode: None
    ) -> None:
        """The report is LF-only even where text mode would write CRLF.

        Same reason as the sanitized HAR: it lands in repos that enforce LF.
        """
        report_path = tmp_path / "report.json"
        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--report", str(report_path), "--patterns", "base"]
        )

        assert result.exit_code == 0
        assert b"\r" not in report_path.read_bytes()

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


class TestSanitizeErrorHandlers:
    """Each failure the command catches is reported as one line and exits 1, with no traceback."""

    # ┌─────────────────────────────────┬──────────────────────────────┬─────────────────────────┐
    # │ what goes wrong                 │ how the run is set up        │ message                 │
    # ├─────────────────────────────────┼──────────────────────────────┼─────────────────────────┤
    # │ output folder does not exist    │ -o missing/out.har           │ File not found          │
    # │ output folder is read-only      │ -o readonly/out.har          │ Permission denied       │
    # │ output path is a folder         │ -o folder                    │ I/O error               │
    # │ pattern file is not JSON        │ --patterns broken.json       │ Failed to load patterns │
    # └─────────────────────────────────┴──────────────────────────────┴─────────────────────────┘
    @pytest.mark.parametrize(
        ("problem", "message"),
        [
            ("missing_output_folder", "Error: File not found"),
            ("read_only_output_folder", "Error: Permission denied"),
            ("output_is_a_folder", "Error: I/O error"),
            ("pattern_file_not_json", "Error: Failed to load patterns"),
        ],
    )
    def test_failure_is_reported_and_exits_1(
        self, valid_har: Path, tmp_path: Path, problem: str, message: str
    ) -> None:
        patterns = "base"
        output = tmp_path / "out.har"
        if problem == "missing_output_folder":
            output = tmp_path / "missing" / "out.har"
        elif problem == "read_only_output_folder":
            if os.geteuid() == 0:
                pytest.skip("root writes to a read-only folder")
            folder = tmp_path / "readonly"
            folder.mkdir()
            folder.chmod(0o555)
            output = folder / "out.har"
        elif problem == "output_is_a_folder":
            output = tmp_path / "folder"
            output.mkdir()
        else:
            broken = tmp_path / "broken.json"
            broken.write_text("{not json")
            patterns = str(broken)

        result = runner.invoke(
            app, ["sanitize", str(valid_har), "--patterns", patterns, "--output", str(output)]
        )

        assert result.exit_code == 1
        assert message in result.output
        assert "Traceback" not in result.output


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
        har = self._write(tmp_path, "mid_session_and_no_submission", "mid.har")

        result = runner.invoke(app, ["sanitize", str(har), "--patterns", "base"])

        assert result.exit_code == 0
        assert "Capture coverage:" in result.output
        assert result.output.count("WARNING: Recording began mid-session") == 1

    def test_complete_capture_reports_no_gaps(self, tmp_path: Path) -> None:
        """Test a capture holding the login exchange raises no gap warnings."""
        har = self._write(tmp_path, "clean_login_flow", "clean_flow.har")

        result = runner.invoke(app, ["sanitize", str(har), "--patterns", "base"])

        assert result.exit_code == 0
        assert "Credential submissions: 2" in result.output
        assert "Recording began mid-session" not in result.output


class TestStaleSiblingRefresh:
    """A sanitize run must refresh an existing .gz sibling it just made stale.

    Every sanitize pass rewrites the .sanitized.har (fresh salt), so a
    sibling .gz from an earlier --compress run diverges even when the
    review applies nothing. Without the refresh, the stale sibling — the
    upload artifact — survives silently.
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
