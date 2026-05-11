"""Regression tests for real-world PII leaks reported by users.

Each case is a value the heuristic engine must flag for the Pass 2 review UI
with a meaningful category. Sources are issue numbers — add a new row when a
user reports a leak the engine missed.

Per CLAUDE.md principle #7, the heuristic layer is intentionally permissive:
detectors should flag aggressively, the UI is the filter, and the allowlist
absorbs reviewed-safe shapes. Failures here mean a detector entry is missing
or a regex backstop is needed, not that detector strictness should change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from har_capture.patterns.loader import (
    CompiledDetector,
    compile_detectors,
    load_sensitive_patterns,
    resolve_patterns_arg,
)
from har_capture.sanitization.heuristics import analyze_value

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_pii_regressions.json").read_text())

HEURISTIC_REGRESSION_CASES = [
    (c["value"], c["should_flag"], c["expected_category"], c["id"])
    for c in _FIXTURES["heuristic_regression_cases"]
]


@pytest.fixture(scope="module")
def network_detectors() -> list[CompiledDetector]:
    path = resolve_patterns_arg("network-device")
    sensitive = load_sensitive_patterns(str(path))
    return compile_detectors(sensitive)


@pytest.mark.parametrize(
    ("value", "should_flag", "expected_category", "desc"),
    HEURISTIC_REGRESSION_CASES,
    ids=[c[3] for c in HEURISTIC_REGRESSION_CASES],
)
def test_heuristic_engine_flags_reported_leaks(
    value: str,
    should_flag: bool,
    expected_category: str,
    desc: str,
    network_detectors: list[CompiledDetector],
) -> None:
    flagged, _confidence, category, reason = analyze_value(value, compiled_detectors=network_detectors)
    assert flagged is should_flag, (
        f"{desc}: '{value}' should {'be' if should_flag else 'not be'} flagged "
        f"(got flagged={flagged}, category={category!r}, reason={reason!r})"
    )
    if should_flag:
        assert category == expected_category, (
            f"{desc}: '{value}' expected category {expected_category!r}, got {category!r} (reason={reason!r})"
        )
