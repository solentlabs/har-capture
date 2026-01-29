"""Tests for CLI main module."""

from __future__ import annotations

import pytest


class TestCliImport:
    """Tests for CLI import availability."""

    def test_can_import_cli_with_typer(self) -> None:
        """Test CLI can be imported when typer is available."""
        pytest.importorskip("typer")
        from har_capture.cli.main import app

        assert app is not None

    def test_version_option(self) -> None:
        """Test version option works."""
        pytest.importorskip("typer")
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "har-capture" in result.stdout
