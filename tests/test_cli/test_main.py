"""Tests for CLI main module."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_main.json").read_text())
CLI_DISPATCH_CASES = _FIXTURES["cli_dispatch_cases"]["cases"]

# typer forces rich's colored output when GITHUB_ACTIONS (or FORCE_COLOR /
# PY_COLORS) is set, which splits "Usage: har-capture get" with escape codes.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


class TestCliDispatch:
    """The first argument picks the command; anything that isn't one means 'get'."""

    @pytest.mark.parametrize("case", CLI_DISPATCH_CASES, ids=[c["id"] for c in CLI_DISPATCH_CASES])
    def test_dispatch(self, case: dict) -> None:
        pytest.importorskip("typer")
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        result = CliRunner().invoke(app, case["argv"])

        output = _ANSI_ESCAPE_RE.sub("", result.output)
        assert result.exit_code == 0, output
        assert case["output_contains"] in output


class TestCliImport:
    """Tests for CLI import availability."""

    def test_can_import_cli_with_typer(self) -> None:
        """Test CLI can be imported when typer is available."""
        pytest.importorskip("typer")
        from har_capture.cli.main import app

        assert app is not None
