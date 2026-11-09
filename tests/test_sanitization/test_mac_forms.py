"""Tests for identifiers beyond the colon MAC: dollar-prefixed hex forms, standard-MIB serials, known MACs elsewhere."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from har_capture.cli._patterns_resolver import require_patterns
from har_capture.patterns import Hasher
from har_capture.sanitization import sanitize_entry, sanitize_har
from har_capture.sanitization.html import hex_placeholder
from har_capture.validation.secrets import check_content

_FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "test_mac_forms.json").read_text("utf-8"))
DOLLAR = _FIXTURE["dollar_cases"]
OIDS = _FIXTURE["oid_serial_cases"]
EMBEDDED = _FIXTURE["embedded_cases"]
SSIDS = _FIXTURE["ssid_cases"]
SALTS = [None, "fixed-salt"]
SALT_IDS = ["static", "salted"]

PATTERNS = require_patterns(["network-device"])


def _har(*bodies: str) -> dict[str, Any]:
    entries = [
        {
            "request": {"method": "GET", "url": "http://192.168.0.1/x", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": body, "mimeType": "application/json"},
            },
        }
        for body in bodies
    ]
    return {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}


def _json_body_values(salt: str | None, values: dict[str, str]) -> dict[str, str]:
    entry = _har(json.dumps(values))["log"]["entries"][0]
    out = sanitize_entry(entry, salt=salt, custom_patterns=PATTERNS)
    parsed: dict[str, str] = json.loads(out["response"]["content"]["text"])
    return parsed


@pytest.mark.parametrize("salt", SALTS, ids=SALT_IDS)
@pytest.mark.parametrize("case", DOLLAR, ids=[c["id"] for c in DOLLAR])
def test_dollar_forms(case: dict, salt: str | None) -> None:
    """A dollar-prefixed MAC or private address is replaced in its own layout; look-alikes are kept."""
    value = _json_body_values(salt, {"v": case["value"]})["v"]
    for leaked in case["leaked"]:
        assert leaked not in value
    assert re.search(case["shape"], value), value
    assert len(value) == len(case["value"]) or case["id"].startswith("ip_hex")


@pytest.mark.parametrize("case", DOLLAR[:2], ids=[c["id"] for c in DOLLAR[:2]])
def test_dollar_mac_correlates_with_colon_form(case: dict) -> None:
    """The same MAC as colon text and as ``$`` hex shares its digits under one salt."""
    colon = ":".join(case["value"][1 + i : 3 + i] for i in range(0, 12, 2))
    out = _json_body_values("fixed-salt", {"a": colon, "b": case["value"]})
    assert out["a"].replace(":", "").lower() == out["b"][1:].lower()


@pytest.mark.parametrize("case", OIDS, ids=[c["id"] for c in OIDS])
def test_standard_mib_serial_objects(case: dict) -> None:
    out = _json_body_values("fixed-salt", {case["key"]: case["value"]})
    assert (out[case["key"]] != case["value"]) is case["redacted"]


@pytest.mark.parametrize("salt", SALTS, ids=SALT_IDS)
@pytest.mark.parametrize("case", EMBEDDED, ids=[c["id"] for c in EMBEDDED])
def test_known_mac_inside_hex_token(case: dict, salt: str | None) -> None:
    """A MAC the run replaced is replaced inside a longer hex token too, keeping the token's length."""
    text = case["text"].replace("{HEX}", case["hex"])
    har = _har(json.dumps({"mac": case["mac"], "blob": text}))
    out, report = sanitize_har(har, salt=salt, custom_patterns=PATTERNS)
    blob = json.loads(out["log"]["entries"][0]["response"]["content"]["text"])["blob"]
    assert len(blob) == len(text)
    if case["leaked"] is None:
        assert blob == text
        assert "mac_derived" not in report.auto_redacted_counts
    else:
        assert case["leaked"].lower() not in blob.lower()
        assert report.auto_redacted_counts["mac_derived"] >= 1


def test_known_mac_in_text_body_across_entries() -> None:
    """The MAC is learned from one entry and found in another, in a non-JSON body."""
    har = _har(json.dumps({"mac": "00:00:5E:00:53:08"}), "x")
    har["log"]["entries"][1]["response"]["content"] = {
        "text": "id 00005e005308 end",
        "mimeType": "text/plain",
    }
    out, _ = sanitize_har(har, salt=None, custom_patterns=PATTERNS)
    assert out["log"]["entries"][1]["response"]["content"]["text"] == "id XXXXXXXXXXXX end"


def test_nothing_swept_without_a_known_mac() -> None:
    har = _har(json.dumps({"blob": "0106" + "00005E005309" + "0203", "name": "Brand-5309"}))
    out, report = sanitize_har(har, salt=None, custom_patterns=PATTERNS)
    body = json.loads(out["log"]["entries"][0]["response"]["content"]["text"])
    assert body == {"blob": "010600005E0053090203", "name": "Brand-5309"}
    assert "mac_derived" not in report.auto_redacted_counts


@pytest.mark.parametrize("salt", SALTS, ids=SALT_IDS)
@pytest.mark.parametrize("case", SSIDS, ids=[c["id"] for c in SSIDS])
def test_default_network_name_from_mac_tail(case: dict, salt: str | None) -> None:
    """A word-dash-tail equal to a known MAC's last four digits is a name derived from the MAC."""
    har = _har(json.dumps({"mac": case["mac"], "note": case["text"]}))
    out, _ = sanitize_har(har, salt=salt, custom_patterns=PATTERNS)
    note = json.loads(out["log"]["entries"][0]["response"]["content"]["text"])["note"]
    assert (note != case["text"]) is case["replaced"]
    if case["replaced"]:
        assert "WIFI" in note
        assert "53a1" not in note.lower()


@pytest.mark.parametrize(
    ("kind", "digits", "salt", "expected"),
    [
        ("mac", "00005E005301", None, "XXXXXXXXXXXX"),
        ("mac", "0000", "s", "XXXX"),
        ("ip_hex", "0A0B0C0D", None, "00000000"),
        ("ip_hex", "0A0B", "s", "XXXX"),
        ("ip_hex", "0A0B0C0D", "s", None),
        ("mac", "00005E005301", "s", None),
    ],
)
def test_hex_placeholder(kind: str, digits: str, salt: str | None, expected: str | None) -> None:
    out = hex_placeholder(kind, digits, Hasher(salt=salt))
    assert len(out) == len(digits)
    if expected is not None:
        assert out == expected
    else:
        assert out != digits and out.upper() == out


def test_validate_reports_unredacted_dollar_mac_and_accepts_placeholders() -> None:
    """``validate`` flags a raw ``$`` MAC and accepts what sanitize writes, salted or static."""
    findings: list = []
    check_content('{"v": "$00005E005301"}', "loc", findings, PATTERNS)
    assert [f.reason for f in findings] == ["Potential real MAC address"]
    for salt in SALTS:
        placeholder = _json_body_values(salt, {"v": "$00005E005301"})["v"]
        clean: list = []
        check_content(json.dumps({"v": placeholder}), "loc", clean, PATTERNS)
        assert clean == []
    skipped: list = []
    check_content(
        "var x = '$00005E005301';",
        "loc",
        skipped,
        PATTERNS,
        mime_type="text/javascript",
        keep_static_addresses=True,
    )
    assert skipped == []
