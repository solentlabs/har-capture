"""Tests for the sanitizer-version provenance check."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from har_capture import __version__
from har_capture.validation import MIN_SANITIZER_VERSION, stale_sanitizer_version, validate_har
from har_capture.validation.provenance import _parse_version


def _log(version: Any = "unset") -> dict[str, Any]:
    if version == "unset":
        return {"entries": []}
    return {"entries": [], "_har_capture": {"sanitization": {"version": version}}}


class TestStaleSanitizerVersion:
    """A recorded version below the floor is reported; anything else is not."""

    @pytest.mark.parametrize(
        ("log", "expected"),
        [
            pytest.param(_log("0.0.1"), "0.0.1", id="older"),
            pytest.param(_log(MIN_SANITIZER_VERSION), None, id="at-floor"),
            pytest.param(_log("99.0.0"), None, id="newer"),
            pytest.param(_log("not-a-version"), None, id="unparseable"),
            pytest.param(_log(7), None, id="non-string"),
            pytest.param(_log(), None, id="no-metadata"),
            pytest.param({"_har_capture": "x"}, None, id="metadata-not-a-dict"),
            pytest.param({"_har_capture": {"sanitization": "x"}}, None, id="sanitization-not-a-dict"),
        ],
    )
    def test_cases(self, log: dict[str, Any], expected: str | None) -> None:
        assert stale_sanitizer_version(log) == expected


def test_floor_is_a_real_release_not_ahead_of_the_package() -> None:
    """A floor above the running version would flag this tool's own output."""
    floor = _parse_version(MIN_SANITIZER_VERSION)
    current = _parse_version(__version__)
    assert floor is not None
    assert current is not None
    assert floor <= current


def _write_har(path: Path, log: dict[str, Any]) -> Path:
    path.write_text(json.dumps({"log": {"version": "1.2", **log}}))
    return path


def test_validate_har_warns_on_stale_version(tmp_path: Path) -> None:
    har = _write_har(tmp_path / "old.har", _log("0.0.1"))
    findings = validate_har(har)
    stale = [f for f in findings if f.location == "Sanitization metadata"]
    assert len(stale) == 1
    assert stale[0].severity == "warning"
    assert stale[0].value == "0.0.1"


def test_validate_har_is_silent_on_current_version(tmp_path: Path) -> None:
    har = _write_har(tmp_path / "new.har", _log(__version__))
    assert not [f for f in validate_har(har) if f.location == "Sanitization metadata"]
