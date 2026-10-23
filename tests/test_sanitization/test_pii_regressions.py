"""Regression tests for real-world PII leaks reported by users.

Each case is a value the heuristic engine must flag for the Pass 2 review UI
with a meaningful category. Sources are issue numbers — add a new row when a
user reports a leak the engine missed.

Per docs/ARCHITECTURE.md § Confidence boundary, the heuristic layer is intentionally permissive:
detectors should flag aggressively, the UI is the filter, and the allowlist
absorbs reviewed-safe shapes. Failures here mean a detector entry is missing
or a regex backstop is needed, not that detector strictness should change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from har_capture.patterns.loader import (
    CompiledDetector,
    compile_detectors,
    load_sensitive_patterns,
    resolve_patterns_arg,
)
from har_capture.sanitization.har import sanitize_har
from har_capture.sanitization.heuristics import analyze_value
from har_capture.validation.secrets import validate_har

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_pii_regressions.json").read_text())

HEURISTIC_REGRESSION_CASES = [
    (c["value"], c["should_flag"], c["expected_category"], c.get("expected_confidence"), c["id"])
    for c in _FIXTURES["heuristic_regression_cases"]
]

REGEX_LAYER_REGRESSION_CASES = [
    (c["input_html"], c["leaked_value"], c["expected_prefix"], c["id"])
    for c in _FIXTURES["regex_layer_regression_cases"]
]

OID_KEYED_JSON_CASES = [
    (c["endpoint"], c["oid"], c["value"], c["redacted"], c["id"]) for c in _FIXTURES["oid_keyed_json_cases"]
]


@pytest.fixture(scope="module")
def network_detectors() -> list[CompiledDetector]:
    path = resolve_patterns_arg("network-device")
    sensitive = load_sensitive_patterns(str(path))
    return compile_detectors(sensitive)


@pytest.mark.parametrize(
    ("value", "should_flag", "expected_category", "expected_confidence", "desc"),
    HEURISTIC_REGRESSION_CASES,
    ids=[c[4] for c in HEURISTIC_REGRESSION_CASES],
)
def test_heuristic_engine_flags_reported_leaks(
    value: str,
    should_flag: bool,
    expected_category: str,
    expected_confidence: str | None,
    desc: str,
    network_detectors: list[CompiledDetector],
) -> None:
    flagged, confidence, category, reason = analyze_value(value, compiled_detectors=network_detectors)
    assert flagged is should_flag, (
        f"{desc}: '{value}' should {'be' if should_flag else 'not be'} flagged "
        f"(got flagged={flagged}, category={category!r}, reason={reason!r})"
    )
    if should_flag:
        assert category == expected_category, (
            f"{desc}: '{value}' expected category {expected_category!r}, got {category!r} (reason={reason!r})"
        )
    if expected_confidence is not None:
        # Confidence drives review pre-selection: HIGH is pre-checked in
        # the checkbox UI, MEDIUM is not (except credentials). A serial
        # that drops from high to medium silently reintroduces the
        # select-it-by-hand gap a CM2500 capture hit.
        assert confidence.value == expected_confidence, (
            f"{desc}: '{value}' expected confidence {expected_confidence!r}, got {confidence.value!r}"
        )


@pytest.mark.parametrize(
    ("input_html", "leaked_value", "expected_prefix", "desc"),
    REGEX_LAYER_REGRESSION_CASES,
    ids=[c[3] for c in REGEX_LAYER_REGRESSION_CASES],
)
def test_regex_layer_redacts_labeled_leaks(
    input_html: str,
    leaked_value: str,
    expected_prefix: str,
    desc: str,
) -> None:
    """The regex (Pass 0-16) layer must redact values whose label provides 100%-confidence context.

    Pure-digit values like WPS PINs can't be caught heuristically - they look
    identical to packet counters. The label is what makes a deterministic
    auto-redaction possible per docs/ARCHITECTURE.md § Confidence boundary.
    """
    from har_capture.sanitization.html import sanitize_html

    output = sanitize_html(input_html)
    assert leaked_value not in output, (
        f"{desc}: leaked value {leaked_value!r} still present in sanitized output: {output!r}"
    )
    assert expected_prefix in output, (
        f"{desc}: expected hash prefix {expected_prefix!r} not in sanitized output: {output!r}"
    )


def _snmp_har(endpoint: str, oid: str, value: str) -> dict[str, Any]:
    """A one-entry HAR whose JSON response holds ``value`` under a bare OID key."""
    body = json.dumps({oid: value})
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 1,
                    "request": {
                        "method": "GET",
                        "url": f"http://192.168.100.1:8080/{endpoint}?oids={oid};",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": 0,
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "cookies": [],
                        "content": {"size": len(body), "mimeType": "application/json", "text": body},
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": len(body),
                    },
                    "cache": {},
                    "timings": {"send": 0, "wait": 1, "receive": 0},
                }
            ],
        }
    }


@pytest.mark.parametrize(
    ("endpoint", "oid", "value", "redacted", "desc"),
    OID_KEYED_JSON_CASES,
    ids=[c[4] for c in OID_KEYED_JSON_CASES],
)
def test_oid_keyed_json_values(
    endpoint: str, oid: str, value: str, redacted: bool, desc: str, tmp_path: Path
) -> None:
    """Values under bare SNMP OID keys: the SSID column is redacted by sanitize and flagged by validate."""
    patterns = str(resolve_patterns_arg("network-device"))
    har = _snmp_har(endpoint, oid, value)

    sanitized, _report = sanitize_har(har, custom_patterns=patterns)
    sanitized_body = sanitized["log"]["entries"][0]["response"]["content"]["text"]
    assert (value not in sanitized_body) is redacted

    raw_path = tmp_path / "raw.har"
    raw_path.write_text(json.dumps(har))
    flagged = [f for f in validate_har(raw_path, custom_patterns=patterns) if f.field == oid]
    assert bool(flagged) is redacted
