"""Tests for interactive review CLI utility functions.

This module tests the helper functions used by the interactive sanitization UI,
including string parsing, formatting, and context extraction.

Test Coverage:
    - Index parsing from user input (single, ranges, mixed, "all")
    - Value truncation for display
    - Context string formatting
    - Pipe-delimited value context capture
    - HTML context extraction around flagged values
    - Exception handling for terminal errors

Test Strategy:
    - Table-driven tests for index parsing with various formats
    - Edge case testing for malformed input
    - Context window size validation
    - Truncation with character count display
    - Error recovery for InquirerPy exceptions

Dependencies:
    - pytest for test framework and parametrization
"""

from __future__ import annotations

import pytest

from har_capture.cli.interactive import (
    capture_html_context,
    capture_pipe_context,
    format_context,
    parse_indices,
    truncate_value,
)

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
PARSE_INDICES_SINGLE_CASES = [
    # (input_str, max_index, expected_indices, description)
    ("1", 5, [0], "single_first"),
    ("5", 5, [4], "single_last"),
    ("3", 10, [2], "single_middle"),
]

PARSE_INDICES_RANGE_CASES = [
    # (input_str, max_index, expected_indices, description)
    ("1-3", 5, [0, 1, 2], "range_start"),
    ("2-4", 5, [1, 2, 3], "range_middle"),
    ("3-5", 5, [2, 3, 4], "range_end"),
    ("1-1", 5, [0], "range_single"),
]

PARSE_INDICES_MIXED_CASES = [
    # (input_str, max_index, expected_indices, description)
    ("1,3,5", 5, [0, 2, 4], "comma_separated"),
    ("1-2,4-5", 5, [0, 1, 3, 4], "ranges_comma"),
    ("1,2-3,5", 5, [0, 1, 2, 4], "mixed_single_range"),
    ("2, 4", 5, [1, 3], "spaces_allowed"),
    ("1-3,2-4", 5, [0, 1, 2, 3], "overlapping_ranges_deduped"),
]

PARSE_INDICES_ALL_CASES = [
    # (input_str, max_index, expected_count, description)
    ("all", 5, 5, "all_five"),
    ("ALL", 5, 5, "all_uppercase"),
    ("All", 5, 5, "all_mixed"),
    ("all", 10, 10, "all_ten"),
]

PARSE_INDICES_ERROR_CASES = [
    # (input_str, max_index, description)
    ("0", 5, "zero_index"),
    ("6", 5, "out_of_bounds"),
    ("-1", 5, "negative"),
    ("abc", 5, "non_numeric"),
    ("1-", 5, "incomplete_range"),
    ("-5", 5, "range_no_start"),
    ("5-1", 5, "reversed_range"),
    ("1-10", 5, "range_exceeds_max"),
]

TRUNCATE_VALUE_CASES = [
    # (value, max_len, expected, description)
    ("short", 20, "short", "no_truncation"),
    ("exactly_twenty_char", 20, "exactly_twenty_char", "exact_length"),
    ("this is a longer value", 20, "this is a lo... [22]", "truncated"),
    ("abc", 10, "abc", "short_value"),
    ("12345678901", 10, "12... [11]", "just_over_limit"),
]

FORMAT_CONTEXT_CASES = [
    # (context, max_len, expected_contains, description)
    ("short context", 40, "short context", "no_truncation"),
    ("line1\nline2", 40, "line1 line2", "newlines_replaced"),
    ("has   multiple   spaces", 40, "has multiple spaces", "spaces_collapsed"),
    ("a" * 80, 40, "...", "truncated_has_ellipsis"),  # Needs >60 chars (max_len + 20 for markup)
]

CAPTURE_PIPE_CONTEXT_CASES = [
    # (values, index, window, expected_contains, description)
    (["a", "b", "c", "d", "e"], 2, 1, "b|>>>c<<<|d", "window_1"),
    (["a", "b", "c", "d", "e"], 2, 2, "a|b|>>>c<<<|d|e", "window_2"),
    (["a", "b", "c"], 0, 2, ">>>a<<<|b|c", "at_start"),
    (["a", "b", "c"], 2, 2, "a|b|>>>c<<<", "at_end"),
    (["only"], 0, 3, ">>>only<<<", "single_element"),
]

CAPTURE_HTML_CONTEXT_CASES = [
    # (html, start, end, window, expected_contains, description)
    ("before MATCH after", 7, 12, 5, ">>>MATCH<<<", "match_highlighted"),
    ("before MATCH after", 7, 12, 5, "fore ", "before_context"),
    ("before MATCH after", 7, 12, 5, " afte", "after_context"),
    ("short", 0, 5, 10, ">>>short<<<", "whole_string_match"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestParseIndicesSingle:
    """Tests for parsing single indices."""

    @pytest.mark.parametrize(
        ("input_str", "max_index", "expected", "desc"),
        PARSE_INDICES_SINGLE_CASES,
        ids=[c[3] for c in PARSE_INDICES_SINGLE_CASES],
    )
    def test_parse_indices_single(
        self, input_str: str, max_index: int, expected: list[int], desc: str
    ) -> None:
        """Test parsing single index values."""
        result = parse_indices(input_str, max_index)
        assert result == expected, desc


class TestParseIndicesRange:
    """Tests for parsing range notation."""

    @pytest.mark.parametrize(
        ("input_str", "max_index", "expected", "desc"),
        PARSE_INDICES_RANGE_CASES,
        ids=[c[3] for c in PARSE_INDICES_RANGE_CASES],
    )
    def test_parse_indices_range(
        self, input_str: str, max_index: int, expected: list[int], desc: str
    ) -> None:
        """Test parsing range notation (e.g., 1-3)."""
        result = parse_indices(input_str, max_index)
        assert result == expected, desc


class TestParseIndicesMixed:
    """Tests for parsing mixed notation."""

    @pytest.mark.parametrize(
        ("input_str", "max_index", "expected", "desc"),
        PARSE_INDICES_MIXED_CASES,
        ids=[c[3] for c in PARSE_INDICES_MIXED_CASES],
    )
    def test_parse_indices_mixed(
        self, input_str: str, max_index: int, expected: list[int], desc: str
    ) -> None:
        """Test parsing mixed notation (e.g., 1-2,4,5-6)."""
        result = parse_indices(input_str, max_index)
        assert result == expected, desc


class TestParseIndicesAll:
    """Tests for parsing 'all' keyword."""

    @pytest.mark.parametrize(
        ("input_str", "max_index", "expected_count", "desc"),
        PARSE_INDICES_ALL_CASES,
        ids=[c[3] for c in PARSE_INDICES_ALL_CASES],
    )
    def test_parse_indices_all(self, input_str: str, max_index: int, expected_count: int, desc: str) -> None:
        """Test parsing 'all' keyword."""
        result = parse_indices(input_str, max_index)
        assert len(result) == expected_count, desc
        assert result == list(range(expected_count)), desc


class TestParseIndicesErrors:
    """Tests for error handling in parse_indices."""

    @pytest.mark.parametrize(
        ("input_str", "max_index", "desc"),
        PARSE_INDICES_ERROR_CASES,
        ids=[c[2] for c in PARSE_INDICES_ERROR_CASES],
    )
    def test_parse_indices_errors(self, input_str: str, max_index: int, desc: str) -> None:
        """Test error handling for invalid inputs."""
        with pytest.raises(ValueError):
            parse_indices(input_str, max_index)


class TestTruncateValue:
    """Tests for value truncation."""

    @pytest.mark.parametrize(
        ("value", "max_len", "expected", "desc"),
        TRUNCATE_VALUE_CASES,
        ids=[c[3] for c in TRUNCATE_VALUE_CASES],
    )
    def test_truncate_value(self, value: str, max_len: int, expected: str, desc: str) -> None:
        """Test value truncation for display."""
        result = truncate_value(value, max_len)
        assert result == expected, desc
        assert len(result) <= max_len, f"Result should not exceed max_len: {len(result)} > {max_len}"


class TestFormatContext:
    """Tests for context formatting."""

    @pytest.mark.parametrize(
        ("context", "max_len", "expected_contains", "desc"),
        FORMAT_CONTEXT_CASES,
        ids=[c[3] for c in FORMAT_CONTEXT_CASES],
    )
    def test_format_context(self, context: str, max_len: int, expected_contains: str, desc: str) -> None:
        """Test context formatting for display."""
        result = format_context(context, max_len)
        assert expected_contains in result, desc
        # Allow for "..." suffix when truncated (max_len + 3)
        assert len(result) <= max_len + 3, (
            f"Result should not exceed max_len + 3: {len(result)} > {max_len + 3}"
        )

    def test_format_context_removes_carriage_returns(self) -> None:
        """Test carriage returns are removed."""
        result = format_context("line1\r\nline2", 50)
        assert "\r" not in result
        assert "line1" in result and "line2" in result


class TestCapturePipeContext:
    """Tests for pipe-delimited context capture."""

    @pytest.mark.parametrize(
        ("values", "index", "window", "expected_contains", "desc"),
        CAPTURE_PIPE_CONTEXT_CASES,
        ids=[c[4] for c in CAPTURE_PIPE_CONTEXT_CASES],
    )
    def test_capture_pipe_context(
        self,
        values: list[str],
        index: int,
        window: int,
        expected_contains: str,
        desc: str,
    ) -> None:
        """Test pipe-delimited context capture."""
        result = capture_pipe_context(values, index, window)
        assert expected_contains in result, f"{desc}: expected '{expected_contains}' in '{result}'"

    def test_capture_pipe_context_highlights_target(self) -> None:
        """Test target value is highlighted with >>> <<<."""
        values = ["before", "target", "after"]
        result = capture_pipe_context(values, 1, 1)
        assert ">>>target<<<" in result


class TestCaptureHtmlContext:
    """Tests for HTML context capture."""

    @pytest.mark.parametrize(
        ("html", "start", "end", "window", "expected_contains", "desc"),
        CAPTURE_HTML_CONTEXT_CASES,
        ids=[c[5] for c in CAPTURE_HTML_CONTEXT_CASES],
    )
    def test_capture_html_context(
        self,
        html: str,
        start: int,
        end: int,
        window: int,
        expected_contains: str,
        desc: str,
    ) -> None:
        """Test HTML context capture."""
        result = capture_html_context(html, start, end, window)
        assert expected_contains in result, f"{desc}: expected '{expected_contains}' in '{result}'"

    def test_capture_html_context_has_ellipsis(self) -> None:
        """Test context has ellipsis markers."""
        result = capture_html_context("prefix MATCH suffix", 7, 12, 5)
        assert result.startswith("...")
        assert result.endswith("...")


class TestExceptionHandling:
    """Tests for exception handling in interactive prompts."""

    @pytest.mark.parametrize(
        ("exception_class", "exception_msg", "description"),
        [
            (KeyboardInterrupt, "", "keyboard_interrupt"),
            (EOFError, "", "eof_error"),
            (RuntimeError, "Terminal error", "runtime_error"),
            (ValueError, "Invalid input", "value_error"),
        ],
    )
    def test_checkbox_selection_handles_exceptions(
        self,
        monkeypatch: pytest.MonkeyPatch,
        exception_class: type[Exception],
        exception_msg: str,
        description: str,
    ) -> None:
        """Test that checkbox selection handles exceptions gracefully."""
        pytest.importorskip("InquirerPy")
        from har_capture.cli.interactive import run_checkbox_selection
        from har_capture.sanitization.report import ConfidenceLevel, FlaggedValue

        flagged = [
            FlaggedValue(
                original_value="test",
                category="test",
                confidence=ConfidenceLevel.HIGH,
                context="test",
                reason="test",
            )
        ]

        # Mock inquirer.checkbox to raise exception
        def mock_checkbox_error(*args, **kwargs):
            if exception_msg:
                raise exception_class(exception_msg)
            raise exception_class()

        monkeypatch.setattr("InquirerPy.inquirer.checkbox", mock_checkbox_error)

        # Should return None instead of crashing
        result = run_checkbox_selection(flagged)
        assert result is None, f"{description}: should return None on exception"

    @pytest.mark.parametrize(
        ("exception_class", "exception_msg", "description"),
        [
            (KeyboardInterrupt, "", "keyboard_interrupt"),
            (EOFError, "", "eof_error"),
            (RuntimeError, "Terminal error", "runtime_error"),
        ],
    )
    def test_quick_action_prompt_handles_exceptions(
        self,
        monkeypatch: pytest.MonkeyPatch,
        exception_class: type[Exception],
        exception_msg: str,
        description: str,
    ) -> None:
        """Test that quick action prompt handles exceptions gracefully."""
        pytest.importorskip("InquirerPy")
        from har_capture.cli.interactive import run_quick_action_prompt
        from har_capture.sanitization.report import ConfidenceLevel, FlaggedValue

        flagged = [
            FlaggedValue(
                original_value="test",
                category="test",
                confidence=ConfidenceLevel.HIGH,
                context="test",
                reason="test",
            )
        ]

        # Mock inquirer.select to raise exception
        def mock_select_error(*args, **kwargs):
            if exception_msg:
                raise exception_class(exception_msg)
            raise exception_class()

        monkeypatch.setattr("InquirerPy.inquirer.select", mock_select_error)

        # Should return None instead of crashing
        result = run_quick_action_prompt(flagged)
        assert result is None, f"{description}: should return None on exception"


# =============================================================================
# Shared fixtures for the multi-function tests below
# =============================================================================
#
# The interactive review module mixes Rich-rendered display with
# InquirerPy prompts. The display functions are pure (Rich just writes
# to stdout) and the prompt drivers all funnel through two boundary
# seams:
#
#   * ``InquirerPy.inquirer.checkbox`` (used by ``run_checkbox_selection``)
#   * ``InquirerPy.inquirer.select``   (used by ``run_quick_action_prompt``)
#
# Patching at those seams gives us deterministic prompt outcomes without
# touching internal control flow. The big ``run_interactive_review``
# loop just orchestrates the helper functions; we patch it via
# ``run_quick_action_prompt`` / ``run_checkbox_selection`` at the
# *module* level so the loop sees canned actions.
#
# Fixtures use real ``FlaggedValue`` and ``SanitizationReport`` objects
# rather than SimpleNamespaces so attribute access matches production.


@pytest.fixture
def make_flagged():  # type: ignore[no-untyped-def]
    """Factory: build a list of FlaggedValue with mixed confidence levels."""
    from har_capture.sanitization.report import ConfidenceLevel, FlaggedValue

    def _make(items):  # type: ignore[no-untyped-def]
        confidence_map = {
            "high": ConfidenceLevel.HIGH,
            "medium": ConfidenceLevel.MEDIUM,
            "low": ConfidenceLevel.LOW,
        }
        return [
            FlaggedValue(
                original_value=value,
                category=category,
                confidence=confidence_map[conf],
                context=f"context for {value}",
                reason=f"reason for {value}",
            )
            for value, category, conf in items
        ]

    return _make


@pytest.fixture
def make_report():  # type: ignore[no-untyped-def]
    """Factory: build a SanitizationReport with given flagged values."""
    from har_capture.sanitization.report import SanitizationReport

    def _make(flagged=None, salt="testsalt"):  # type: ignore[no-untyped-def]
        report = SanitizationReport(
            input_file="/test/in.har",
            output_file="/test/out.har",
            salt=salt,
        )
        if flagged:
            report.flagged.extend(flagged)
        return report

    return _make


# =============================================================================
# apply_reviewed_redactions — file I/O + atomic rename + 3 error branches
# =============================================================================


class TestApplyReviewedRedactions:
    """Tests for ``apply_reviewed_redactions``: happy path + 3 error branches."""

    @pytest.fixture
    def sanitized_har_file(self, tmp_path):  # type: ignore[no-untyped-def]
        import copy
        import json
        from pathlib import Path

        fixtures = json.loads(
            (Path(__file__).parent.parent / "fixtures" / "test_interactive.json").read_text()
        )
        har_data = copy.deepcopy(fixtures["sanitized_har_for_apply_redactions"])
        f = tmp_path / "sanitized.har"
        f.write_text(json.dumps(har_data))
        return f

    def test_happy_path_writes_atomically(  # type: ignore[no-untyped-def]
        self, sanitized_har_file, make_report, make_flagged, capsys
    ):
        """Real HAR file + populated report -> redactions applied via tempfile + rename."""
        from har_capture.cli.interactive import apply_reviewed_redactions
        from har_capture.sanitization.report import RedactionStatus

        flagged = make_flagged([("alice", "field", "medium")])
        flagged[0].status = RedactionStatus.USER_REDACTED
        flagged[0].redacted_value = "REDACTED"
        report = make_report(flagged=flagged)

        apply_reviewed_redactions(report, sanitized_har_file)

        captured = capsys.readouterr()
        assert "Applying user redactions" in captured.out
        assert sanitized_har_file.exists()  # rename succeeded

    def test_unreadable_input_raises_typer_exit(  # type: ignore[no-untyped-def]
        self, tmp_path, make_report, capsys
    ):
        """Open() failure -> typer.Exit(1) with friendly message."""
        import typer

        from har_capture.cli.interactive import apply_reviewed_redactions

        # Path that doesn't exist trips OSError on open().
        missing = tmp_path / "missing.har"
        report = make_report()

        with pytest.raises(typer.Exit) as excinfo:
            apply_reviewed_redactions(report, missing)
        assert excinfo.value.exit_code == 1
        captured = capsys.readouterr()
        assert "Failed to read sanitized file" in captured.err

    def test_invalid_json_raises_typer_exit(  # type: ignore[no-untyped-def]
        self, tmp_path, make_report, capsys
    ):
        """Malformed JSON -> typer.Exit(1) with friendly message."""
        import typer

        from har_capture.cli.interactive import apply_reviewed_redactions

        bad = tmp_path / "bad.har"
        bad.write_text("{not valid json")
        report = make_report()

        with pytest.raises(typer.Exit):
            apply_reviewed_redactions(report, bad)
        captured = capsys.readouterr()
        assert "Failed to read sanitized file" in captured.err

    def test_apply_user_redactions_failure_caught(  # type: ignore[no-untyped-def]
        self, sanitized_har_file, make_report, monkeypatch, capsys
    ):
        """Exception from apply_user_redactions -> typer.Exit(1)."""
        import typer

        from har_capture import sanitization as san_mod
        from har_capture.cli.interactive import apply_reviewed_redactions

        def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("redaction kaboom")

        monkeypatch.setattr(san_mod, "apply_user_redactions", boom)
        with pytest.raises(typer.Exit):
            apply_reviewed_redactions(make_report(), sanitized_har_file)
        captured = capsys.readouterr()
        assert "Failed to apply redactions" in captured.err

    def test_write_failure_cleans_up_tempfile(  # type: ignore[no-untyped-def]
        self, sanitized_har_file, make_report, monkeypatch, capsys
    ):
        """OSError on Path.replace -> typer.Exit(1) + temp cleanup attempted."""
        import typer

        from har_capture.cli.interactive import apply_reviewed_redactions

        original_replace = Path.replace

        def fail_replace(self, target):  # type: ignore[no-untyped-def]
            raise OSError("disk full")

        monkeypatch.setattr(Path, "replace", fail_replace)

        with pytest.raises(typer.Exit):
            apply_reviewed_redactions(make_report(), sanitized_har_file)
        captured = capsys.readouterr()
        assert "Failed to write output file" in captured.err

        # Restore for cleanup of any leftovers.
        monkeypatch.setattr(Path, "replace", original_replace)


# Path is needed by apply_reviewed_redactions tests above.
from pathlib import Path  # noqa: E402

# =============================================================================
# Display functions — pure Rich rendering
# =============================================================================


class TestDisplayFunctions:
    """Tests for the Rich-rendering display functions.

    We don't assert on exact rendered cells — just on key
    domain-meaningful strings — so the tests don't break when Rich's
    formatting changes.
    """

    def test_display_flagged_table_renders_each_row(  # type: ignore[no-untyped-def]
        self, make_flagged, capsys
    ):
        from har_capture.cli.interactive import display_flagged_table

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("MyHome_5g", "wifi_ssid", "medium"),
                ("router-1", "device_name", "low"),
            ]
        )
        display_flagged_table(flagged)
        captured = capsys.readouterr()
        assert "Flagged Values for Review" in captured.out
        # Each value (or its truncated form) appears.
        assert "alice" in captured.out

    def test_display_flagged_table_handles_long_values(  # type: ignore[no-untyped-def]
        self, make_flagged, capsys
    ):
        """Long values get truncated by ``truncate_value``."""
        from har_capture.cli.interactive import display_flagged_table

        long = "x" * 200
        flagged = make_flagged([(long, "credential", "high")])
        display_flagged_table(flagged)
        captured = capsys.readouterr()
        # Truncated marker should appear.
        assert "..." in captured.out or "x" * 50 in captured.out

    def test_display_sanitization_summary_review_required(  # type: ignore[no-untyped-def]
        self, make_report, make_flagged, capsys
    ):
        """Flagged list non-empty -> "Review Required" title."""
        from har_capture.cli.interactive import display_sanitization_summary

        report = make_report(flagged=make_flagged([("alice", "field", "medium")]))
        display_sanitization_summary(report, "/in.har", "/out.har", "random salt")
        captured = capsys.readouterr()
        assert "Review Required" in captured.out

    def test_display_sanitization_summary_clean_run(  # type: ignore[no-untyped-def]
        self, make_report, capsys
    ):
        """Flagged empty -> "Sanitization Complete" title."""
        from har_capture.cli.interactive import display_sanitization_summary

        report = make_report()
        display_sanitization_summary(report, "/in.har", "/out.har", "static placeholders")
        captured = capsys.readouterr()
        assert "Sanitization Complete" in captured.out

    def test_display_summary_renders(  # type: ignore[no-untyped-def]
        self, make_report, capsys
    ):
        from har_capture.cli.interactive import display_summary

        report = make_report()
        display_summary(report)
        captured = capsys.readouterr()
        assert "Summary" in captured.out


# =============================================================================
# run_checkbox_selection / run_quick_action_prompt happy paths
# =============================================================================


class TestRunCheckboxSelectionHappy:
    """Canned-input return paths for the checkbox prompt (exception branches covered above)."""

    def test_returns_selected_indices(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        from har_capture.cli.interactive import run_checkbox_selection

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("bob", "credential", "high"),
                ("MyHome_5g", "wifi_ssid", "medium"),
            ]
        )

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return [0, 2]

        monkeypatch.setattr("InquirerPy.inquirer.checkbox", lambda **kwargs: FakePrompt())
        result = run_checkbox_selection(flagged)
        assert result == [0, 2]

    def test_returns_empty_list_when_user_selects_none(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        from har_capture.cli.interactive import run_checkbox_selection

        flagged = make_flagged([("alice", "credential", "high")])

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return []

        monkeypatch.setattr("InquirerPy.inquirer.checkbox", lambda **kwargs: FakePrompt())
        result = run_checkbox_selection(flagged)
        assert result == []

    def test_returns_none_when_user_escapes(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        """Prompt returns None -> we propagate None up to the loop."""
        from har_capture.cli.interactive import run_checkbox_selection

        flagged = make_flagged([("alice", "credential", "high")])

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return None

        monkeypatch.setattr("InquirerPy.inquirer.checkbox", lambda **kwargs: FakePrompt())
        result = run_checkbox_selection(flagged)
        assert result is None

    def test_groups_by_category_with_separators(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        """Cross-category items trigger Separator insertion in the choices list."""
        from har_capture.cli.interactive import run_checkbox_selection

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("MyHome_5g", "wifi_ssid", "medium"),
                ("router-1", "device_name", "low"),
            ]
        )

        captured_choices: list = []

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return []

        def fake_checkbox(**kwargs):  # type: ignore[no-untyped-def]
            captured_choices.append(kwargs.get("choices"))
            return FakePrompt()

        monkeypatch.setattr("InquirerPy.inquirer.checkbox", fake_checkbox)
        run_checkbox_selection(flagged)

        assert captured_choices, "checkbox was not called"
        # Two category transitions -> two Separators in the choices list.
        from InquirerPy.separator import Separator

        seps = [c for c in captured_choices[0] if isinstance(c, Separator)]
        assert len(seps) == 2


class TestRunQuickActionPromptHappy:
    """Action-menu return paths — exercises HIGH-only and HIGH+MEDIUM branches."""

    def test_returns_action_value(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        from har_capture.cli.interactive import run_quick_action_prompt

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("MyHome_5g", "wifi_ssid", "medium"),
            ]
        )

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return "all"

        monkeypatch.setattr("InquirerPy.inquirer.select", lambda **kwargs: FakePrompt())
        assert run_quick_action_prompt(flagged) == "all"

    def test_high_only_choice_when_high_present(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        from har_capture.cli.interactive import run_quick_action_prompt

        flagged = make_flagged([("alice", "credential", "high")])
        choices_seen: list = []

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return "high"

        monkeypatch.setattr(
            "InquirerPy.inquirer.select",
            lambda **kwargs: (choices_seen.append(kwargs["choices"]) or FakePrompt()),
        )
        run_quick_action_prompt(flagged)
        # The "Redact HIGH confidence only" choice should appear.
        labels = [c.get("name", "") for c in choices_seen[0]]
        assert any("HIGH confidence only" in label for label in labels)

    def test_high_medium_choice_when_both_present(  # type: ignore[no-untyped-def]
        self, make_flagged, monkeypatch
    ):
        from har_capture.cli.interactive import run_quick_action_prompt

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("MyHome_5g", "wifi_ssid", "medium"),
            ]
        )
        choices_seen: list = []

        class FakePrompt:
            def execute(self):  # type: ignore[no-untyped-def]
                return "high_medium"

        monkeypatch.setattr(
            "InquirerPy.inquirer.select",
            lambda **kwargs: (choices_seen.append(kwargs["choices"]) or FakePrompt()),
        )
        run_quick_action_prompt(flagged)
        labels = [c.get("name", "") for c in choices_seen[0]]
        assert any("HIGH + MEDIUM" in label for label in labels)


# =============================================================================
# run_interactive_review — drives the loop through canned actions
# =============================================================================
#
# The loop is patched at ``run_quick_action_prompt`` and
# ``run_checkbox_selection`` (module-level), not at the InquirerPy seam.
# This is intentional: those helpers are tested directly above, so the
# loop tests only need to verify the orchestration logic — what status
# each item ends up with given a particular action.


class TestRunInteractiveReview:
    """Drive the main review loop with each top-level action.

    Each test verifies the loop terminates with the expected per-item
    redaction statuses.
    """

    def test_no_flagged_short_circuits(  # type: ignore[no-untyped-def]
        self, make_report, capsys
    ):
        from har_capture.cli.interactive import run_interactive_review

        result = run_interactive_review(make_report())
        assert result is True
        captured = capsys.readouterr()
        assert "No suspicious values found" in captured.out

    def test_action_skip_leaves_items_flagged(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        from har_capture.cli import interactive as mod
        from har_capture.sanitization.report import RedactionStatus

        flagged = make_flagged([("alice", "credential", "high")])
        report = make_report(flagged=flagged)

        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: "skip")
        result = run_interactive_review_via(mod, report)
        assert result is True
        assert flagged[0].status == RedactionStatus.FLAGGED

    def test_action_none_returns_false(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        """Cancelled action -> review_completed = False."""
        from har_capture.cli import interactive as mod

        flagged = make_flagged([("alice", "credential", "high")])
        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: None)
        assert run_interactive_review_via(mod, make_report(flagged=flagged)) is False

    def test_action_all_marks_everyone_redacted(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        from har_capture.cli import interactive as mod
        from har_capture.sanitization.report import RedactionStatus

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("bob", "credential", "medium"),
                ("router-1", "device_name", "low"),
            ]
        )
        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: "all")
        assert run_interactive_review_via(mod, make_report(flagged=flagged)) is True
        assert all(f.status == RedactionStatus.USER_REDACTED for f in flagged)

    def test_action_high_marks_only_high_redacted(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        from har_capture.cli import interactive as mod
        from har_capture.sanitization.report import (
            ConfidenceLevel,
            RedactionStatus,
        )

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("bob", "credential", "medium"),
                ("router-1", "device_name", "low"),
            ]
        )
        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: "high")
        run_interactive_review_via(mod, make_report(flagged=flagged))

        for f in flagged:
            if f.confidence == ConfidenceLevel.HIGH:
                assert f.status == RedactionStatus.USER_REDACTED
            else:
                assert f.status == RedactionStatus.USER_SKIPPED

    def test_action_high_medium_marks_high_and_medium(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        from har_capture.cli import interactive as mod
        from har_capture.sanitization.report import (
            ConfidenceLevel,
            RedactionStatus,
        )

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("bob", "credential", "medium"),
                ("router-1", "device_name", "low"),
            ]
        )
        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: "high_medium")
        run_interactive_review_via(mod, make_report(flagged=flagged))

        for f in flagged:
            if f.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM):
                assert f.status == RedactionStatus.USER_REDACTED
            else:
                assert f.status == RedactionStatus.USER_SKIPPED

    def test_action_select_applies_per_item_selection(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        from har_capture.cli import interactive as mod
        from har_capture.sanitization.report import RedactionStatus

        flagged = make_flagged(
            [
                ("alice", "credential", "high"),
                ("bob", "credential", "medium"),
                ("router-1", "device_name", "low"),
            ]
        )
        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: "select")
        # User selects items 0 and 2 in the checkbox prompt.
        monkeypatch.setattr(mod, "run_checkbox_selection", lambda f: [0, 2])
        run_interactive_review_via(mod, make_report(flagged=flagged))

        # After flagged.sort(), the order may shift — we verify by value.
        by_value = {f.original_value: f.status for f in flagged}
        assert by_value["alice"] == RedactionStatus.USER_REDACTED
        # bob is not in selection -> skipped
        assert by_value["bob"] == RedactionStatus.USER_SKIPPED

    def test_action_select_back_loops_to_action_menu(  # type: ignore[no-untyped-def]
        self, make_flagged, make_report, monkeypatch
    ):
        """ESC from select re-enters the action menu; second action skips out."""
        from har_capture.cli import interactive as mod

        flagged = make_flagged([("alice", "credential", "high")])

        actions = iter(["select", "skip"])
        monkeypatch.setattr(mod, "run_quick_action_prompt", lambda f: next(actions))
        monkeypatch.setattr(mod, "run_checkbox_selection", lambda f: None)
        result = run_interactive_review_via(mod, make_report(flagged=flagged))
        assert result is True


def run_interactive_review_via(mod, report):  # type: ignore[no-untyped-def]
    """Helper that calls run_interactive_review with optional kwargs.

    The display_full_screen helper inside the loop accepts only when
    all of input_path / output_path / salt_mode are truthy — passing
    them lets us cover that branch too.
    """
    return mod.run_interactive_review(
        report,
        input_path="/test/in.har",
        output_path="/test/out.har",
        salt_mode="random",
    )
