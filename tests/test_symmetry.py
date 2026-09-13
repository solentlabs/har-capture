"""ADR-14 symmetry harness: what validate reports on a raw capture, sanitize clears.

Every row in ``tests/fixtures/test_symmetry.json`` is a raw HAR carrying one leak.
Validate must report it, and after ``sanitize_har`` — in every heuristic mode —
validate must report nothing and the leaked value must be gone. A row that fails
the second half is a check that can fail with no remediation path, which ADR-14
forbids. A change that widens either tool adds its rows here.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from har_capture.patterns.loader import resolve_patterns_arg
from har_capture.sanitization import sanitize_har
from har_capture.sanitization.report import HeuristicMode
from har_capture.validation import Finding, validate_har

_FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "test_symmetry.json").read_text(encoding="utf-8"))
CASES: list[dict[str, Any]] = _FIXTURE["symmetry_cases"]
_IDS = [c["id"] for c in CASES]


def _patterns(case: dict[str, Any]) -> str | dict[str, Any] | None:
    if "custom_patterns" in case:
        return dict(case["custom_patterns"])
    name = case.get("patterns")
    return str(resolve_patterns_arg(name)) if name else None


def _validate(har: dict[str, Any], path: Path, patterns: str | dict[str, Any] | None) -> list[Finding]:
    path.write_text(json.dumps(har), encoding="utf-8")
    return validate_har(path, patterns)


def _raw_har(case: dict[str, Any]) -> dict[str, Any]:
    entries = copy.deepcopy(case["entries"])
    if "pad_chars" in case:
        content = entries[0]["response"]["content"]
        content["text"] = "var pad = '" + "x" * case["pad_chars"] + "'; " + content["text"]
    return {"log": {"version": "1.2", "entries": entries}}


# ┌───────────────────────────────┬──────────────────────────────────────────────┐
# │ assertion                     │ what it proves                               │
# ├───────────────────────────────┼──────────────────────────────────────────────┤
# │ raw file has the findings     │ the row exercises a real validate check      │
# │ sanitized file has none       │ every finding has a sanitize remediation     │
# │ leaked strings are gone       │ the remediation removed the value itself     │
# └───────────────────────────────┴──────────────────────────────────────────────┘


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_raw_capture_is_reported(case: dict[str, Any], tmp_path: Path) -> None:
    findings = _validate(_raw_har(case), tmp_path / "raw.har", _patterns(case))

    for expected in case["raw_findings"]:
        assert any(f.severity == expected["severity"] and expected["reason"] in f.reason for f in findings), (
            f"no {expected['severity']} matching {expected['reason']!r} in {findings}"
        )


@pytest.mark.parametrize("mode", list(HeuristicMode), ids=[m.value for m in HeuristicMode])
@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_sanitized_capture_is_clean(case: dict[str, Any], mode: HeuristicMode, tmp_path: Path) -> None:
    patterns = _patterns(case)
    sanitized, _ = sanitize_har(_raw_har(case), salt="symmetry", custom_patterns=patterns, heuristics=mode)

    assert _validate(sanitized, tmp_path / "sanitized.har", patterns) == []
    dumped = json.dumps(sanitized)
    for leaked in case["leaked"]:
        assert leaked not in dumped
