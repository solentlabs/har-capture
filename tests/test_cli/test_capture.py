"""Tests for capture command CLI helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

# =============================================================================
# _display_header() test cases
# =============================================================================
#
# ┌─────────────────┬──────────┬───────────────────┬─────────────────────────────┐
# │ target          │ browser  │ output            │ description                 │
# ├─────────────────┼──────────┼───────────────────┼─────────────────────────────┤
# │ 192.168.1.1     │ chromium │ None              │ basic usage, no output path │
# │ example.com     │ firefox  │ output/test.har   │ with output path            │
# │ router.local    │ webkit   │ None              │ different browser           │
# └─────────────────┴──────────┴───────────────────┴─────────────────────────────┘
#
# fmt: off
DISPLAY_HEADER_CASES = [
    # (target,          browser,    output,                   expected_strs,                        not_expected,   desc)
    ("192.168.1.1",     "chromium", None,                     ["HAR CAPTURE", "192.168.1.1", "chromium"], ["Output:"], "basic usage no output"),
    ("example.com",     "firefox",  Path("output/test.har"),  ["example.com", "firefox", "output/test.har"], [],      "with output path"),
    ("router.local",    "webkit",   None,                     ["router.local", "webkit"],           ["Output:"],     "webkit browser"),
]
# fmt: on


@pytest.mark.parametrize(
    ("target", "browser", "output", "expected_strs", "not_expected", "desc"),
    DISPLAY_HEADER_CASES,
)
def test_display_header(
    target: str,
    browser: str,
    output: Path | None,
    expected_strs: list[str],
    not_expected: list[str],
    desc: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test _display_header output contains expected strings."""
    from har_capture.cli.capture import _display_header

    _display_header(target, browser, output)

    captured = capsys.readouterr()
    for s in expected_strs:
        assert s in captured.out, f"{desc}: expected '{s}' in output"
    for s in not_expected:
        assert s not in captured.out, f"{desc}: did not expect '{s}' in output"


# =============================================================================
# _display_instructions() test
# =============================================================================


def test_display_instructions(capsys: pytest.CaptureFixture[str]) -> None:
    """Test _display_instructions shows usage guidance."""
    from har_capture.cli.capture import _display_instructions

    _display_instructions()

    captured = capsys.readouterr()
    assert "Instructions:" in captured.out
    assert "browser" in captured.out.lower()
    assert "Close" in captured.out


# =============================================================================
# _display_results() test cases
# =============================================================================
#
# ┌──────────────────────┬────────────────────┬──────────────────┬─────────────────────────┐
# │ har_path             │ compressed_path    │ sanitized_path   │ description             │
# ├──────────────────────┼────────────────────┼──────────────────┼─────────────────────────┤
# │ output/capture.har   │ None               │ None             │ raw HAR only            │
# │ None                 │ output/c.har.gz    │ None             │ compressed only         │
# │ None                 │ None               │ output/c.san.har │ sanitized only          │
# │ output/capture.har   │ output/c.har.gz    │ output/c.san.har │ all paths               │
# └──────────────────────┴────────────────────┴──────────────────┴─────────────────────────┘
#
# fmt: off
DISPLAY_RESULTS_CASES = [
    # (har_path,               compressed_path,            sanitized_path,                   stats,                                                    expected_strs,                                       desc)
    (Path("output/capture.har"), None,                     None,                             {},                                                       ["CAPTURE COMPLETE", "output/capture.har", "har-capture sanitize"], "raw HAR only"),
    (None,                     Path("output/c.har.gz"),    None,                             {},                                                       ["Compressed:", "output/c.har.gz"],                  "compressed only"),
    (None,                     None,                       Path("output/c.sanitized.har"),   {},                                                       ["Sanitized:", "output/c.sanitized.har", "PII removed"], "sanitized only"),
    (Path("output/c.har"),     Path("output/c.har.gz"),    Path("output/c.sanitized.har"),   {},                                                       ["output/c.har", "output/c.har.gz", "output/c.sanitized.har"], "all paths"),
    (Path("output/c.har"),     None,                       None,                             {"removed_entries": 50, "original_entries": 100, "filtered_entries": 50}, ["Removed 50", "100 -> 50"], "with stats"),
]
# fmt: on


@pytest.mark.parametrize(
    ("har_path", "compressed_path", "sanitized_path", "stats", "expected_strs", "desc"),
    DISPLAY_RESULTS_CASES,
)
def test_display_results(
    har_path: Path | None,
    compressed_path: Path | None,
    sanitized_path: Path | None,
    stats: dict[str, Any],
    expected_strs: list[str],
    desc: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test _display_results shows expected output."""
    from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
    from har_capture.cli.capture import _display_results

    result = CaptureWorkflowResult(
        capture=CaptureResult(
            success=True,
            har_path=har_path,
            compressed_path=compressed_path,
            sanitized_path=sanitized_path,
            stats=stats,
        )
    )

    _display_results(result)

    captured = capsys.readouterr()
    for s in expected_strs:
        assert s in captured.out, f"{desc}: expected '{s}' in output"
