"""Tests for ``keep_static_addresses``: example addresses in static script, CSS and text bodies."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from har_capture.cli.main import app
from har_capture.patterns import is_static_asset_mime, keeps_static_addresses
from har_capture.sanitization import sanitize_entry, sanitize_har, sanitize_har_file
from har_capture.validation.secrets import check_content, validate_har

_FIXTURE = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "test_static_assets.json").read_text("utf-8")
)
BODY_CASES = _FIXTURE["body_cases"]
MIME_CASES = _FIXTURE["mime_cases"]
IDS = [c["id"] for c in BODY_CASES]

runner = CliRunner()


def _entry(mime: str, text: str) -> dict[str, Any]:
    return {
        "request": {"method": "GET", "url": "http://192.168.0.1/asset", "headers": []},
        "response": {"status": 200, "headers": [], "content": {"text": text, "mimeType": mime}},
    }


def _har(mime: str, text: str) -> dict[str, Any]:
    return {
        "log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [_entry(mime, text)]}
    }


def _body(sanitized_entry: dict[str, Any]) -> str:
    return str(sanitized_entry["response"]["content"]["text"])


@pytest.mark.parametrize("case", MIME_CASES, ids=[c["mime"] or "empty" for c in MIME_CASES])
def test_static_asset_mime(case: dict) -> None:
    assert is_static_asset_mime(case["mime"]) is case["static"]


def test_keeps_static_addresses_needs_text_route() -> None:
    assert keeps_static_addresses("text/css", "text") is True
    assert keeps_static_addresses("text/css", "json") is False
    assert keeps_static_addresses("text/css", "html") is False


@pytest.mark.parametrize("case", BODY_CASES, ids=IDS)
def test_default_redacts_everything(case: dict) -> None:
    """Without the option nothing changes: every address is redacted."""
    text = _body(sanitize_entry(_entry(case["mime"], case["text"]), salt=None))
    for value in case["kept"] + case["always_redacted"]:
        assert value not in text


@pytest.mark.parametrize("case", BODY_CASES, ids=IDS)
def test_option_keeps_static_example_addresses(case: dict) -> None:
    text = _body(sanitize_entry(_entry(case["mime"], case["text"]), salt=None, keep_static_addresses=True))
    for value in case["kept"]:
        assert value in text
    for value in case["always_redacted"]:
        assert value not in text


def test_option_is_per_call_and_restored() -> None:
    """The scope ends with the call: a later default call redacts again."""
    entry = _entry("text/css", "/* 203.0.113.44 */")
    kept = _body(sanitize_entry(copy.deepcopy(entry), salt=None, keep_static_addresses=True))
    after = _body(sanitize_entry(copy.deepcopy(entry), salt=None))
    assert "203.0.113.44" in kept
    assert "203.0.113.44" not in after


def test_option_through_sanitize_har_and_file(tmp_path: Path) -> None:
    har = _har("text/css", "/* 203.0.113.44 */")
    sanitized, _ = sanitize_har(copy.deepcopy(har), salt=None, keep_static_addresses=True)
    assert "203.0.113.44" in _body(sanitized["log"]["entries"][0])
    src = tmp_path / "a.har"
    src.write_text(json.dumps(har))
    out, _ = sanitize_har_file(src, tmp_path / "o.har", salt=None, keep_static_addresses=True)
    assert (
        "203.0.113.44"
        in json.loads(Path(out).read_text())["log"]["entries"][0]["response"]["content"]["text"]
    )


@pytest.mark.parametrize("case", BODY_CASES, ids=IDS)
def test_validate_option_never_reports_kept_values(case: dict) -> None:
    """With the option, ``validate`` reports none of the addresses the sanitizer keeps."""
    findings: list = []
    check_content(case["text"], "loc", findings, mime_type=case["mime"], keep_static_addresses=True)
    for value in case["kept"]:
        assert not any(value in f.value for f in findings)


@pytest.mark.parametrize("case", [c for c in BODY_CASES if c["kept"]], ids=lambda c: c["id"])
def test_validate_default_still_reports_them(case: dict) -> None:
    """Without the option the same body is reported (public addresses and MACs warn)."""
    findings: list = []
    check_content(case["text"], "loc", findings, mime_type=case["mime"])
    assert any(value in f.value for f in findings for value in case["kept"])


def test_validate_option_silences_only_static_addresses() -> None:
    findings: list = []
    check_content(
        "var a='203.0.113.44'; var m='00:00:5E:00:53:2A'; var v='fe80::5eff:fe00:5301';",
        "l",
        findings,
        mime_type="text/javascript",
    )
    assert {f.reason for f in findings} >= {
        "Potential public IP address",
        "Potential real MAC address",
        "Potential IPv6 address",
    }
    findings = []
    check_content(
        "var a='203.0.113.44'; var m='00:00:5E:00:53:2A'; var v='fe80::5eff:fe00:5301';",
        "l",
        findings,
        mime_type="text/javascript",
        keep_static_addresses=True,
    )
    assert findings == []
    findings = []
    check_content("<p>203.0.113.44</p>", "l", findings, mime_type="text/html", keep_static_addresses=True)
    assert [f.reason for f in findings] == ["Potential public IP address"]


def test_cli_round_trip(tmp_path: Path) -> None:
    """``sanitize --keep-static-addresses`` then ``validate --keep-static-addresses`` is clean; plain validate warns."""
    har = _har("text/css", "/* 203.0.113.44 */")
    src = tmp_path / "a.har"
    src.write_text(json.dumps(har))
    out = tmp_path / "a.sanitized.har"
    result = runner.invoke(
        app,
        [
            "sanitize",
            str(src),
            "-o",
            str(out),
            "--patterns",
            "network-device",
            "--no-salt",
            "--keep-static-addresses",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "203.0.113.44" in out.read_text()
    kept = runner.invoke(
        app, ["validate", str(out), "--patterns", "network-device", "--keep-static-addresses", "--strict"]
    )
    assert kept.exit_code == 0, kept.output
    plain = runner.invoke(app, ["validate", str(out), "--patterns", "network-device", "--strict"])
    assert plain.exit_code == 1
    assert validate_har(out, keep_static_addresses=True) == []
