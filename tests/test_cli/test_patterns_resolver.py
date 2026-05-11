"""Tests for the shared CLI ``--patterns`` resolver.

`require_patterns` is the single seam between the typer option list and
the library's `custom_patterns=` argument. It enforces the 0.9.0 contract
that every sanitization-running CLI invocation makes an explicit domain
choice (or opts into `base` for core-universal-PII-only).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from har_capture.cli._patterns_resolver import require_patterns

_FIXTURES = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "test_patterns_resolver.json").read_text()
)


class TestMissingPatternsExits:
    """`--patterns` is required; absence raises typer.Exit(2) with a listing."""

    def test_none_exits_with_code_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            require_patterns(None)
        assert exc_info.value.exit_code == 2
        err = capsys.readouterr().err
        assert "--patterns is required" in err
        assert "base" in err
        assert "network-device" in err

    def test_empty_list_exits_with_code_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            require_patterns([])
        assert exc_info.value.exit_code == 2
        err = capsys.readouterr().err
        assert "--patterns is required" in err


class TestBaseSentinel:
    """`base` is a no-op token meaning 'core universal PII only'."""

    def test_base_alone_returns_none(self) -> None:
        assert require_patterns(["base"]) is None

    def test_base_repeated_returns_none(self) -> None:
        assert require_patterns(["base", "base"]) is None

    def test_base_mixed_with_domain_strips_base(self) -> None:
        result = require_patterns(["base", "network-device"])
        assert isinstance(result, str)
        assert result.endswith("network_device.json")


class TestDomainResolution:
    """Resolution mirrors the prior `_resolve_custom_patterns` behavior."""

    def test_single_builtin_returns_path_string(self) -> None:
        result = require_patterns(["network-device"])
        assert isinstance(result, str)
        assert result.endswith("network_device.json")

    def test_single_file_path_returns_string(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom.json"
        custom.write_text(json.dumps(_FIXTURES["empty_custom_pattern_file"]))
        result = require_patterns([str(custom)])
        assert isinstance(result, str)
        assert result == str(custom)

    def test_multiple_patterns_merged_to_dict(self, tmp_path: Path) -> None:
        first = tmp_path / "first.json"
        first.write_text(json.dumps(_FIXTURES["merge_source_a"]))
        second = tmp_path / "second.json"
        second.write_text(json.dumps(_FIXTURES["merge_source_b"]))
        result = require_patterns([str(first), str(second)])
        assert isinstance(result, dict)
