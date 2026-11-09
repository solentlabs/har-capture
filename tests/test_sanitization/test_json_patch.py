"""Tests for layout-preserving JSON rewriting (`_patch_json_strings`, `_rewrite_json`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from har_capture.patterns import Hasher
from har_capture.patterns.redaction import parse_json_container
from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.har import _patch_json_strings, _rewrite_json

_FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "test_json_patch.json").read_text("utf-8"))
_CASES = _FIXTURE["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_patch_json_strings(case: dict) -> None:
    """Only changed strings are rewritten; anything unpatchable returns None."""
    # These two are given a parsed value that does not match the text: the guard against a caller's mistake.
    mismatched = {"invalid_escape_not_patchable": {"u": "q"}, "text_and_parsed_data_disagree": {"u": "other"}}
    data = mismatched.get(case["id"]) or parse_json_container(case["text"])
    assert _patch_json_strings(case["text"], data, case["cleaned"]) == case["expect"]


@pytest.mark.parametrize("salt", [None, "s"], ids=["static", "salted"])
def test_rewrite_json_member_per_line_layout_survives(salt: str | None) -> None:
    """A body written one member per line, no space after the colon, keeps those bytes."""
    text = '{\n"model":"X1",\n"wan":"203.0.113.9",\n"lan":"00:00:5E:00:53:01"\n}\n'
    hasher = Hasher(salt=salt)
    data = parse_json_container(text)
    assert data is not None
    out = _rewrite_json(text, data, hasher, RedactionCollector(hasher=hasher), served=True)

    assert out.startswith('{\n"model":"X1",\n"wan":"') and out.endswith('"\n}\n')
    assert out.count("\n") == text.count("\n")
    assert "203.0.113.9" not in out and "00:00:5E:00:53:01" not in out
