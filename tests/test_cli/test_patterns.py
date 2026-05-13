"""Tests for CLI patterns command.

The CLI ``patterns`` subcommand is a thin wrapper over
``har_capture.patterns.loader``. These tests run the command via
CliRunner against the real built-in ``network-device`` domain — no
mocks. Per docs/CODE_REVIEW.md § Test overrides are a code smell,
hitting coverage with real fixtures beats heavy mocking.

Pattern-file fixtures used by the ``--show`` tests live in
``tests/fixtures/test_patterns.json`` per docs/CODE_REVIEW.md
§ Test data lives in JSON fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from har_capture.cli.main import app

runner = CliRunner()

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_patterns.json").read_text())


class TestPatternsList:
    """Default invocation lists available built-in domains."""

    def test_list_lists_network_device_domain(self) -> None:
        result = runner.invoke(app, ["patterns"])
        assert result.exit_code == 0
        assert "Available pattern choices" in result.stdout
        assert "base" in result.stdout
        assert "network-device" in result.stdout

    def test_list_shows_usage_hints(self) -> None:
        result = runner.invoke(app, ["patterns"])
        assert "har-capture get" in result.stdout
        assert "har-capture sanitize" in result.stdout
        assert "--show" in result.stdout

    def test_list_empty_directory(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When no domain files exist, the no-domains branch fires.

        We override the loader's ``_get_domains_dir`` to point at an
        empty temp directory rather than mocking ``list_domains`` itself
        — this exercises the real glob+empty-result path.
        """
        from har_capture.patterns import loader

        monkeypatch.setattr(loader, "_get_domains_dir", lambda: tmp_path)
        result = runner.invoke(app, ["patterns"])
        assert result.exit_code == 0
        assert "No built-in pattern domains found." in result.stdout


class TestPatternsShow:
    """``--show <name>`` prints details of a single domain."""

    def test_show_builtin_domain(self) -> None:
        result = runner.invoke(app, ["patterns", "--show", "network-device"])
        assert result.exit_code == 0
        assert "Pattern: network-device" in result.stdout
        assert "File:" in result.stdout
        # network_device.json has a _description, so the line should appear.
        assert "Safe values for network devices" in result.stdout

    def test_show_lists_safe_value_patterns(self) -> None:
        result = runner.invoke(app, ["patterns", "--show", "network-device"])
        assert "Safe value patterns" in result.stdout

    def test_show_lists_tag_safe_values(self) -> None:
        result = runner.invoke(app, ["patterns", "--show", "network-device"])
        assert "Tag safe values" in result.stdout

    def test_show_unknown_domain_errors(self) -> None:
        result = runner.invoke(app, ["patterns", "--show", "nonexistent-domain-xyz"])
        assert result.exit_code == 1
        assert "Error:" in result.output

    def test_show_external_json_file(self, tmp_path: Path) -> None:
        """``--show`` accepts a path to an external JSON file."""
        custom = tmp_path / "custom.json"
        custom.write_text(json.dumps(_FIXTURES["show_external_full_domain"]))
        result = runner.invoke(app, ["patterns", "--show", str(custom)])
        assert result.exit_code == 0
        assert "Test fixture domain" in result.stdout
        assert "matches literal foo" in result.stdout
        assert "alpha, beta" in result.stdout

    def test_show_minimal_json_file_omits_optional_sections(self, tmp_path: Path) -> None:
        """A domain with no safe_value_patterns / tagValueList still renders."""
        minimal = tmp_path / "minimal.json"
        minimal.write_text(json.dumps(_FIXTURES["show_minimal_only_description"]))
        result = runner.invoke(app, ["patterns", "--show", str(minimal)])
        assert result.exit_code == 0
        assert "Bare-bones" in result.stdout
        # Sections are silently omitted when absent — neither header should appear.
        assert "Safe value patterns" not in result.stdout
        assert "Tag safe values" not in result.stdout

    def test_show_json_file_without_description(self, tmp_path: Path) -> None:
        """A domain JSON with no ``_description`` skips the description line."""
        no_desc = tmp_path / "no_desc.json"
        no_desc.write_text(json.dumps(_FIXTURES["show_no_description"]))
        result = runner.invoke(app, ["patterns", "--show", str(no_desc)])
        assert result.exit_code == 0
        # File line is still printed; description line is not.
        assert "File:" in result.stdout

    def test_show_safe_pattern_falls_back_to_regex_when_no_comment(self, tmp_path: Path) -> None:
        """Safe patterns without ``_comment`` show the raw regex instead."""
        custom = tmp_path / "no_comment.json"
        custom.write_text(json.dumps(_FIXTURES["show_safe_pattern_without_comment"]))
        result = runner.invoke(app, ["patterns", "--show", str(custom)])
        assert result.exit_code == 0
        assert "bareregex" in result.stdout
