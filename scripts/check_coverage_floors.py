#!/usr/bin/env python3
"""Per-module coverage floor enforcement.

Reads coverage data produced by ``pytest --cov=har_capture`` (i.e. the
``.coverage`` file) and asserts that each module listed in ``FLOORS``
meets its minimum coverage percentage. Exits 1 with a diff if any
module has decayed below its floor.

Why per-module floors: the project-wide ``--cov-fail-under`` gate
averages high-coverage core modules against low-coverage CLI modules
and silently hides regressions. The CLI layer in particular has a
history of decay (cli/patterns.py at 7%, cli/capture.py at 38%,
cli/interactive.py at 48% before v0.8.1) while the project total
stayed above 75%. This script makes per-module decay a CI failure.

Floors are set strictly at the v0.8.1 post-refactor coverage. New
code that lowers a module's coverage either (a) adds tests to keep
the floor, or (b) explicitly raises the floor in the same PR with a
note explaining why.

Run locally::

    .venv/bin/python3 -m pytest -m "not integration" --cov=har_capture
    .venv/bin/python3 scripts/check_coverage_floors.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# fmt: off
# Floor = floor() of the v0.8.1 post-refactor coverage percentage as
# reported by coverage.py (line + branch combined). Update only alongside
# test additions that genuinely raise a module's coverage — never to
# paper over a regression. Floats avoid the round-vs-floor mismatch
# between pytest's terminal display (rounds) and the underlying value.
FLOORS: dict[str, float] = {
    "src/har_capture/cli/__init__.py":    100.0,
    "src/har_capture/cli/capture.py":      97.0,
    "src/har_capture/cli/interactive.py":  97.0,
    "src/har_capture/cli/main.py":         84.0,
    "src/har_capture/cli/patterns.py":    100.0,
    "src/har_capture/cli/sanitize.py":     92.0,
    "src/har_capture/cli/validate.py":     94.0,
}
# fmt: on


def _load_coverage() -> dict[str, float]:
    """Return per-file coverage percent matching pytest's combined line+branch display.

    Uses coverage.py's ``Analysis.numbers.pc_covered`` so the percentage
    matches the value pytest prints in its terminal report. A pure-line
    calculation diverges from the displayed value when the source has
    branches, leading to surprising floor failures.
    """
    try:
        from coverage import Coverage
    except ImportError:
        print("error: coverage.py is not installed", file=sys.stderr)
        sys.exit(2)

    cov = Coverage()
    cov.load()
    data = cov.get_data()

    repo_root = Path(__file__).resolve().parent.parent
    result: dict[str, float] = {}
    for filename in data.measured_files():
        try:
            rel = str(Path(filename).resolve().relative_to(repo_root))
        except ValueError:
            continue
        analysis = cov._analyze(filename)  # noqa: SLF001 — only public-ish path to branch totals
        if analysis.numbers.n_statements == 0:
            continue
        result[rel] = analysis.numbers.pc_covered
    return result


def main() -> int:
    """Compare per-module coverage against ``FLOORS`` and exit nonzero on regression."""
    actual = _load_coverage()
    if not actual:
        print(
            "error: no coverage data — run pytest with --cov=har_capture first",
            file=sys.stderr,
        )
        return 2

    failures: list[tuple[str, float, float]] = []
    missing: list[str] = []
    for path, floor in sorted(FLOORS.items()):
        if path not in actual:
            missing.append(path)
            continue
        if actual[path] < floor:
            failures.append((path, floor, actual[path]))

    if missing:
        for m in missing:
            print(
                f"error: {m} is in FLOORS but absent from coverage data",
                file=sys.stderr,
            )

    if failures:
        print("Coverage floor violations:", file=sys.stderr)
        for path, floor, got in failures:
            print(
                f"  {path}: required >= {floor:.1f}%, got {got:.2f}%",
                file=sys.stderr,
            )

    if failures or missing:
        return 1

    print(f"All {len(FLOORS)} module floors satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
