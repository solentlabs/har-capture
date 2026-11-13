"""sanitize --preserve-length: same-length stand-ins, recorded in the file.

SANITIZATION_SPEC "Length-Preserving Stand-ins" and ADR-25. The capture in
tests/fixtures/test_preserve_length.json carries every kind of value the
sanitizer replaces, so a body that changes length names a replacement site the
mode does not cover.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from har_capture.cli.main import app
from har_capture.patterns import is_stand_in, recorded_stand_ins, stand_ins_scope
from har_capture.patterns.loader import resolve_patterns_arg
from har_capture.patterns.redaction import is_fully_redacted, is_redacted
from har_capture.sanitization.har import appears_sanitized, apply_user_redactions, sanitize_har
from har_capture.sanitization.heuristics import is_safe_value
from har_capture.sanitization.report import HeuristicMode, RedactionStatus
from har_capture.validation.secrets import validate_har

_FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "test_preserve_length.json").read_text())
_PATTERNS = str(resolve_patterns_arg("network-device"))


def _capture() -> dict[str, Any]:
    return copy.deepcopy(_FIXTURE["capture"])


def _sanitize(
    har: dict[str, Any], heuristics: HeuristicMode = HeuristicMode.DISABLED
) -> tuple[dict[str, Any], Any]:
    return sanitize_har(
        har, salt="fixed", custom_patterns=_PATTERNS, heuristics=heuristics, preserve_length=True
    )


def _lengths(har: dict[str, Any]) -> dict[str, tuple[int, int, int]]:
    """Per entry URL in the input's order: body, URL and POST body byte lengths."""
    result = {}
    for index, entry in enumerate(har["log"]["entries"]):
        request = entry["request"]
        post = (request.get("postData") or {}).get("text", "")
        body = entry["response"]["content"].get("text", "")
        result[f"{index}:{_FIXTURE['capture']['log']['entries'][index]['request']['url']}"] = (
            len(body.encode()),
            len(request["url"].encode()),
            len(post.encode()),
        )
    return result


def _assert_lengths_kept(before: dict[str, Any], after: dict[str, Any], *, escaped_may_differ: bool) -> None:
    for key, lengths in _lengths(before).items():
        url = key.split(":", 1)[1]
        if escaped_may_differ and url in _FIXTURE["escaped_body_urls"]:
            continue
        assert _lengths(after)[key] == lengths, f"{url} changed length"


def _write(tmp_path: Path, har: dict[str, Any], name: str) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(har, ensure_ascii=False))
    return path


class TestPreserveLength:
    """A length-preserving run keeps every body's length and records its stand-ins."""

    def test_every_body_keeps_its_length(self) -> None:
        sanitized, _ = _sanitize(_capture())

        _assert_lengths_kept(_capture(), sanitized, escaped_may_differ=True)

    def test_escaped_non_ascii_value_is_the_stated_exception(self) -> None:
        r"""A JSON body that escapes a replaced non-ASCII value (é) is written shorter; nothing else is."""
        sanitized, _ = _sanitize(_capture())
        before, after = _lengths(_capture()), _lengths(sanitized)

        changed = sorted(key.split(":", 1)[1] for key in before if before[key] != after[key])

        assert changed == ["http://192.168.0.1/api/ascii.json"]

    def test_no_raw_value_survives(self) -> None:
        sanitized, _ = _sanitize(_capture())
        text = json.dumps(sanitized, ensure_ascii=False)

        assert [value for value in _FIXTURE["raw_values"] if value in text] == []

    def test_record_names_every_stand_in_the_file_carries(self) -> None:
        sanitized, _ = _sanitize(_capture())
        record = sanitized["log"]["_har_capture"]["sanitization"]
        text = json.dumps(sanitized["log"]["entries"], ensure_ascii=False)

        assert record["preserve_length"] is True
        assert record["stand_ins"] == sorted(record["stand_ins"])
        assert record["stand_ins"]
        assert all(stand_in in text for stand_in in record["stand_ins"])

    def test_validate_trusts_the_record_and_only_the_record(self, tmp_path: Path) -> None:
        """The file validates clean with its record; without it the stand-ins read as leaks."""
        sanitized, _ = _sanitize(_capture())
        stripped = copy.deepcopy(sanitized)
        del stripped["log"]["_har_capture"]["sanitization"]["stand_ins"]

        with_record = validate_har(_write(tmp_path, sanitized, "with.har"), _PATTERNS)
        without_record = validate_har(_write(tmp_path, stripped, "without.har"), _PATTERNS)

        assert [finding.reason for finding in with_record if finding.severity == "error"] == []
        assert any(finding.severity == "error" for finding in without_record)

    def test_second_run_changes_nothing(self) -> None:
        """A recorded stand-in is its own stand-in, so sanitizing the output again is a no-op on the entries."""
        once, _ = _sanitize(_capture())
        twice, _ = sanitize_har(
            copy.deepcopy(once), salt=None, custom_patterns=_PATTERNS, preserve_length=True
        )

        assert twice["log"]["entries"] == once["log"]["entries"]
        assert (
            twice["log"]["_har_capture"]["sanitization"]["stand_ins"]
            == once["log"]["_har_capture"]["sanitization"]["stand_ins"]
        )

    def test_stand_ins_are_not_offered_for_review(self) -> None:
        sanitized, report = _sanitize(_capture(), HeuristicMode.FLAG)
        stand_ins = set(sanitized["log"]["_har_capture"]["sanitization"]["stand_ins"])

        assert [item.original_value for item in report.flagged if item.original_value in stand_ins] == []

    def test_review_writes_recorded_stand_ins(self, tmp_path: Path) -> None:
        """Confirmed review items become stand-ins of their length, added to the record, and the file validates."""
        sanitized, report = _sanitize(_capture(), HeuristicMode.FLAG)
        assert report.flagged
        for item in report.flagged:
            item.status = RedactionStatus.USER_REDACTED

        reviewed = apply_user_redactions(sanitized, report)
        text = json.dumps(reviewed["log"]["entries"], ensure_ascii=False)
        record = set(reviewed["log"]["_har_capture"]["sanitization"]["stand_ins"])

        _assert_lengths_kept(_capture(), reviewed, escaped_may_differ=True)
        for item in report.flagged:
            assert item.original_value not in text
            assert item.redacted_value in record
            assert len(item.redacted_value.encode()) == len(item.original_value.encode())
        record_review_free = [
            f for f in validate_har(_write(tmp_path, reviewed, "r.har"), _PATTERNS) if f.severity == "error"
        ]
        assert [f.reason for f in record_review_free if "flagged value" not in f.reason] == []

    def test_review_of_a_default_file_writes_placeholders(self) -> None:
        """Only a file that records the mode gets stand-ins from the review."""
        sanitized, report = sanitize_har(
            _capture(), salt="fixed", custom_patterns=_PATTERNS, heuristics=HeuristicMode.FLAG
        )
        for item in report.flagged:
            item.status = RedactionStatus.USER_REDACTED

        reviewed = apply_user_redactions(sanitized, report)

        assert "stand_ins" not in reviewed["log"]["_har_capture"]["sanitization"]
        assert all("_" in item.redacted_value for item in report.flagged)

    def test_appears_sanitized_counts_recorded_stand_ins(self) -> None:
        sanitized, _ = _sanitize(_capture())

        looks_sanitized, count = appears_sanitized(sanitized, threshold=1)

        assert looks_sanitized
        assert count >= len(sanitized["log"]["_har_capture"]["sanitization"]["stand_ins"])

    def test_cli_flag(self, tmp_path: Path) -> None:
        source = _write(tmp_path, _capture(), "raw.har")
        output = tmp_path / "out.har"

        result = CliRunner().invoke(
            app,
            ["sanitize", str(source), "--patterns", "network-device", "--preserve-length", "-o", str(output)],
        )

        assert result.exit_code == 0, result.output
        written = json.loads(output.read_text())
        assert written["log"]["_har_capture"]["sanitization"]["preserve_length"] is True
        _assert_lengths_kept(_capture(), written, escaped_may_differ=True)


class TestRecognitionScope:
    """Inside stand_ins_scope a recorded stand-in counts as redacted for every check that asks."""

    @pytest.mark.parametrize(
        "check",
        [is_redacted, is_fully_redacted, is_safe_value, is_stand_in],
        ids=["is_redacted", "is_fully_redacted", "is_safe_value", "is_stand_in"],
    )
    def test_recorded_value_inside_and_outside_the_scope(self, check: Any) -> None:
        assert not check("Zeitsbktq")
        with stand_ins_scope(frozenset({"Zeitsbktq"})):
            assert check("Zeitsbktq")
        assert not check("Zeitsbktq")

    @pytest.mark.parametrize(
        ("har", "expected"),
        [
            ({"log": {"_har_capture": {"sanitization": {"stand_ins": ["a1", "", 7, "b2"]}}}}, {"a1", "b2"}),
            ({"log": {"_har_capture": {"sanitization": {"stand_ins": "a1"}}}}, set()),
            ({"log": {"_har_capture": {"sanitization": {}}}}, set()),
            ({"log": []}, set()),
            ([], set()),
        ],
        ids=["strings_kept", "not_a_list", "no_record", "log_not_an_object", "not_a_har"],
    )
    def test_recorded_stand_ins_reads_only_a_list_of_strings(self, har: Any, expected: set[str]) -> None:
        assert recorded_stand_ins(har) == expected
