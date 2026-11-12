"""Tests for the sanitizer-version provenance check."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from har_capture import __version__
from har_capture.validation import (
    MIN_SANITIZER_VERSION,
    stale_sanitizer_version,
    unreviewed_flagged,
    validate_har,
)
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


def _reviewed(review: Any = "unset", flagged: Any = 3, **decided: Any) -> dict[str, Any]:
    sanitization: dict[str, Any] = {"version": __version__, "flagged_total": flagged, **decided}
    if review != "unset":
        sanitization["review"] = review
    return {"entries": [], "_har_capture": {"sanitization": sanitization}}


# ┌──────────────┬───────────────┬──────────────────┬──────────────────────────────────────────┐
# │ review       │ flagged_total │ reported         │ why                                      │
# ├──────────────┼───────────────┼──────────────────┼──────────────────────────────────────────┤
# │ no_tty       │ 3             │ ("no_tty", 3)    │ nobody was asked                         │
# │ cancelled    │ 1             │ ("cancelled", 1) │ the user left without deciding           │
# │ cancelled    │ 5, 3 decided  │ ("cancelled", 2) │ a review report decided only some        │
# │ completed    │ 3             │ None             │ every item was decided                   │
# │ skipped      │ 3             │ None             │ the user chose to keep every value       │
# │ none_flagged │ 0             │ None             │ nothing was offered                      │
# │ no_tty       │ 0             │ None             │ nothing was left unreviewed              │
# │ (absent)     │ 3             │ None             │ a library caller ran no review           │
# │ no_tty       │ not a count   │ None             │ nothing to count                         │
# └──────────────┴───────────────┴──────────────────┴──────────────────────────────────────────┘
class TestUnreviewedFlagged:
    """A file whose flagged values nobody reviewed says so itself; validate reports it."""

    @pytest.mark.parametrize(
        ("log", "expected"),
        [
            pytest.param(_reviewed("no_tty"), ("no_tty", 3), id="no-terminal"),
            pytest.param(_reviewed("cancelled", 1), ("cancelled", 1), id="cancelled"),
            pytest.param(
                _reviewed("cancelled", 5, user_redacted=1, user_skipped=2),
                ("cancelled", 2),
                id="partly-decided",
            ),
            pytest.param(_reviewed("cancelled", 3, user_redacted=1, user_skipped=2), None, id="all-decided"),
            pytest.param(
                _reviewed("no_tty", 3, user_redacted="1", user_skipped=True),
                ("no_tty", 3),
                id="counts-unreadable",
            ),
            pytest.param(_reviewed("completed"), None, id="completed"),
            pytest.param(_reviewed("skipped"), None, id="skipped-by-choice"),
            pytest.param(_reviewed("none_flagged", 0), None, id="none-flagged"),
            pytest.param(_reviewed("no_tty", 0), None, id="no-terminal-nothing-flagged"),
            pytest.param(_reviewed(), None, id="no-review-recorded"),
            pytest.param(_reviewed("no_tty", "3"), None, id="count-not-a-number"),
            pytest.param(_reviewed("no_tty", True), None, id="count-a-boolean"),
            pytest.param(_reviewed(["no_tty"]), None, id="outcome-not-a-string"),
            pytest.param({"entries": []}, None, id="no-metadata"),
            pytest.param({"_har_capture": "x"}, None, id="metadata-not-a-dict"),
            pytest.param({"_har_capture": {"sanitization": "x"}}, None, id="sanitization-not-a-dict"),
        ],
    )
    def test_cases(self, log: dict[str, Any], expected: tuple[str, int] | None) -> None:
        assert unreviewed_flagged(log) == expected


def test_validate_har_errors_on_unreviewed_flagged_values(tmp_path: Path) -> None:
    har = _write_har(tmp_path / "unreviewed.har", _reviewed("no_tty"))
    findings = [f for f in validate_har(har) if f.field == "review"]
    assert len(findings) == 1
    assert findings[0].severity == "error"
    assert findings[0].value == "no_tty"
    assert "3 flagged value(s) were never decided" in findings[0].reason


def test_validate_har_is_silent_on_a_completed_review(tmp_path: Path) -> None:
    har = _write_har(tmp_path / "reviewed.har", _reviewed("completed"))
    assert not [f for f in validate_har(har) if f.field == "review"]
