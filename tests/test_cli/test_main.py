"""Tests for CLI main module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_main.json").read_text())
CLI_DISPATCH_CASES = _FIXTURES["cli_dispatch_cases"]["cases"]


class TestCliDispatch:
    """The first argument picks the command; anything that isn't one means 'get'."""

    @pytest.mark.parametrize("case", CLI_DISPATCH_CASES, ids=[c["id"] for c in CLI_DISPATCH_CASES])
    def test_dispatch(self, case: dict) -> None:
        pytest.importorskip("typer")
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        result = CliRunner().invoke(app, case["argv"])

        assert result.exit_code == 0, result.output
        assert case["output_contains"] in result.output


class TestCliImport:
    """Tests for CLI import availability."""

    def test_can_import_cli_with_typer(self) -> None:
        """Test CLI can be imported when typer is available."""
        pytest.importorskip("typer")
        from har_capture.cli.main import app

        assert app is not None
