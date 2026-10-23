"""Unit tests for the patch coverage gate's pure helpers in ``scripts/check_patch_coverage.py``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# scripts/ is not a package; add it to sys.path so we can import the gate.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from check_patch_coverage import (  # type: ignore[import-not-found]  # noqa: E402
    parse_added_lines,
    uncovered_in_diff,
)

_FIXTURE = json.loads((_REPO_ROOT / "tests" / "fixtures" / "test_patch_coverage.json").read_text())


class TestParseAddedLines:
    """Added line numbers come from the new-file side of each hunk."""

    @pytest.mark.parametrize("case", _FIXTURE["parse_cases"], ids=lambda c: c["id"])
    def test_parse(self, case: dict) -> None:
        expected = {path: set(lines) for path, lines in case["expect"].items()}
        assert parse_added_lines(case["diff"]) == expected


class TestUncoveredInDiff:
    """Only gaps on changed lines fail the gate."""

    @pytest.mark.parametrize("case", _FIXTURE["uncovered_cases"], ids=lambda c: c["id"])
    def test_uncovered(self, case: dict) -> None:
        assert (
            uncovered_in_diff(set(case["added"]), set(case["missing"]), set(case["partial"]))
            == case["expect"]
        )
