#!/usr/bin/env python3
"""Patch coverage gate: every changed source line is covered, or the build fails.

Reads the ``.coverage`` file produced by ``pytest --cov=har_capture`` and the
``git diff`` against the merge base with the target branch. Any added or
changed line under ``src/har_capture`` that coverage.py reports as unexecuted,
or as the origin of an untaken branch, fails the gate.

Why not rely on Codecov: its patch status is informational with an 80% target,
so a PR with uncovered lines still shows green while the Codecov comment lists
them. The 0.15.0 release shipped seven such lines. This gate uses the same
measure Codecov reports (missing lines plus partial branches) with a target of
zero, locally and in CI.

Run locally (after the pytest run)::

    .venv/bin/python3 scripts/check_patch_coverage.py [--base origin/main]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SOURCE_PREFIX = "src/har_capture/"
_FILE_RE = re.compile(r"^\+\+\+ b/(?P<path>.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def parse_added_lines(diff_text: str) -> dict[str, set[int]]:
    """Return the added or changed line numbers per file from ``git diff -U0`` output."""
    added: dict[str, set[int]] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        file_match = _FILE_RE.match(line)
        if file_match:
            current = file_match["path"]
            continue
        hunk_match = _HUNK_RE.match(line)
        if hunk_match and current is not None:
            start = int(hunk_match["start"])
            count = int(hunk_match["count"]) if hunk_match["count"] is not None else 1
            if count:
                added.setdefault(current, set()).update(range(start, start + count))
    return added


def uncovered_in_diff(added: set[int], missing_lines: set[int], partial_branch_lines: set[int]) -> list[int]:
    """Return the changed lines that are unexecuted or start an untaken branch."""
    return sorted(added & (missing_lines | partial_branch_lines))


def _git_diff(base: str) -> str:
    merge_base = subprocess.run(
        ["git", "merge-base", base, "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return subprocess.run(
        ["git", "diff", "-U0", "--no-color", merge_base, "--", SOURCE_PREFIX],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> int:
    """Fail when any changed source line lacks coverage."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="origin/main", help="branch the change merges into")
    args = parser.parse_args()

    try:
        from coverage import Coverage
    except ImportError:
        print("error: coverage.py is not installed", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parent.parent
    cov = Coverage()
    cov.load()
    measured = {
        str(Path(f).resolve().relative_to(repo_root)): f
        for f in cov.get_data().measured_files()
        if _inside(f, repo_root)
    }
    if not measured:
        print("error: no coverage data — run pytest with --cov=har_capture first", file=sys.stderr)
        return 2

    failures: list[str] = []
    checked = 0
    for path, lines in sorted(parse_added_lines(_git_diff(args.base)).items()):
        if not path.startswith(SOURCE_PREFIX) or not path.endswith(".py"):
            continue
        if path not in measured:
            failures.append(f"  {path}: changed but absent from coverage data")
            continue
        analysis = cov._analyze(measured[path])  # noqa: SLF001 — only public-ish path to branch data
        partial = set(analysis.missing_branch_arcs())
        checked += len(lines & (set(analysis.statements) | partial))
        failures.extend(f"  {path}:{n}" for n in uncovered_in_diff(lines, set(analysis.missing), partial))

    if failures:
        print(f"Patch coverage: {len(failures)} changed line(s) not covered (target: none):", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Patch coverage: all {checked} changed executable line(s) covered.")
    return 0


def _inside(filename: str, root: Path) -> bool:
    try:
        Path(filename).resolve().relative_to(root)
    except ValueError:
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())
