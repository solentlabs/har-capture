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
