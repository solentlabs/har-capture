"""Tests for the shared capture-completeness renderer.

Test Coverage:
    - Coverage summary and warning blocks
    - summary=False (bulk scans) prints warnings only
    - None report renders nothing

Test Strategy:
    - Table-driven with @pytest.mark.parametrize
    - HAR fixtures shared with tests/fixtures/test_completeness.json so the
      rendered numbers stay tied to the analyzer's own test cases
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from har_capture.cli._completeness_display import display_completeness
from har_capture.validation.completeness import analyze_capture_completeness

FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_completeness.json").read_text())


def _report(fixture_key: str) -> Any:
    """Analyze a fixture HAR and return its completeness report."""
    return analyze_capture_completeness(copy.deepcopy(FIXTURES[fixture_key]))


# fmt: off
RENDER_CASES = [
    # (fixture_key,             summary, expected_present,                                          expected_absent,                    warnings, desc)
    ("mid_session_and_no_post", True,    ["Capture coverage:", "Requests:      1", "GET 1",
                                          "POST requests: 0", "sessionid"],                         [],                                 2,        "gaps_with_summary"),
    ("clean_login_flow",        True,    ["Capture coverage:", "POST requests: 2",
                                          "1 response(s) set a cookie"],                            ["WARNING:"],                       0,        "clean_with_summary"),
    ("mid_session_and_no_post", False,   ["WARNING:"],                                              ["Capture coverage:", "Requests:"], 2,        "gaps_summary_suppressed"),
    ("clean_login_flow",        False,   [],                                                        ["Capture coverage:", "WARNING:"],  0,        "clean_summary_suppressed"),
]
# fmt: on


class TestDisplayCompleteness:
    """Rendering of the capture-completeness report."""

    @pytest.mark.parametrize(
        ("fixture_key", "summary", "expected_present", "expected_absent", "warnings", "desc"),
        RENDER_CASES,
        ids=[c[5] for c in RENDER_CASES],
    )
    def test_render(
        self,
        fixture_key: str,
        summary: bool,
        expected_present: list[str],
        expected_absent: list[str],
        warnings: int,
        desc: str,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test each report/summary combination renders the expected lines."""
        display_completeness(_report(fixture_key), summary=summary)
        out = capsys.readouterr().out

        for text in expected_present:
            assert text in out, f"{desc}: expected '{text}'"
        for text in expected_absent:
            assert text not in out, f"{desc}: did not expect '{text}'"
        assert out.count("WARNING:") == warnings, desc
        assert out.count("→") == warnings, f"{desc}: one remedy per warning"

    def test_clean_capture_is_silent_in_bulk_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test a complete capture prints nothing at all when summary is off."""
        display_completeness(_report("clean_login_flow"), summary=False)

        assert capsys.readouterr().out == ""

    def test_missing_report_renders_nothing(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test a None report prints nothing rather than raising."""
        display_completeness(None)

        assert capsys.readouterr().out == ""
