#!/usr/bin/env python3
"""Post-merge release tagging script for har-capture.

Validates that a merged PR is ready to tag by checking:
1. On the main branch with clean working directory
2. Version format is valid semver (X.Y.Z)
3. Tag doesn't already exist
4. CI passed on HEAD commit
5. Version is consistent across pyproject.toml, __init__.py, CHANGELOG.md
6. Tests pass and code quality checks pass

Then creates and pushes the annotated tag to trigger the GitHub Actions
release workflow (which publishes to PyPI).

Workflow:
    1. Do all work in your feature branch (code, tests, changelog, version bump)
    2. Merge the PR to main
    3. Run: python scripts/release.py X.Y.Z
    4. GitHub Actions creates the verified release and publishes to PyPI

Usage:
    python scripts/release.py 0.4.4                  # Validate and tag
    python scripts/release.py 0.4.4 --dry-run        # Validate only, don't tag
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path


def print_error(msg: str) -> None:
    """Print error message in red."""
    print(f"\033[91m✗ {msg}\033[0m", file=sys.stderr)


def print_success(msg: str) -> None:
    """Print success message in green."""
    print(f"\033[92m✓ {msg}\033[0m")


def print_info(msg: str) -> None:
    """Print info message in blue."""
    print(f"\033[94mℹ {msg}\033[0m")


def print_warning(msg: str) -> None:
    """Print warning message in yellow."""
    print(f"\033[93m⚠ {msg}\033[0m")


def validate_version(version: str) -> bool:
    """Validate that version follows semantic versioning (X.Y.Z)."""
    pattern = r"^\d+\.\d+\.\d+$"
    return bool(re.match(pattern, version))


def get_repo_root() -> Path:
    """Get the repository root directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to get repository root: {e}")
        sys.exit(1)


def get_current_branch() -> str:
    """Get the current git branch name."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


def check_git_clean() -> bool:
    """Check if git working directory is clean."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        )
        return not result.stdout.strip()
    except subprocess.CalledProcessError:
        return False


def check_tag_exists(version: str) -> bool:
    """Check if version tag already exists."""
    try:
        result = subprocess.run(
            ["git", "tag", "-l", f"v{version}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return bool(result.stdout.strip())
    except subprocess.CalledProcessError:
        return False


def _fetch_check_runs(head_sha: str) -> tuple[list[str], list[str], int] | None:
    """Query GitHub for check-run state on ``head_sha``.

    Returns ``(failed, in_progress, total_count)`` or ``None`` on transport
    error. Empty lists mean every check completed successfully.
    """
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{{owner}}/{{repo}}/commits/{head_sha}/check-runs"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print_error("GitHub CLI (gh) not found. Install it: https://cli.github.com/")
        return None
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to query GitHub CI status: {e.stderr.strip()}")
        return None

    data = json.loads(result.stdout)
    check_runs = data.get("check_runs", [])

    failed: list[str] = []
    in_progress: list[str] = []
    for run in check_runs:
        name = run.get("name", "unknown")
        status = run.get("status", "unknown")
        conclusion = run.get("conclusion")

        if status != "completed":
            in_progress.append(name)
        elif conclusion != "success":
            failed.append(f"{name} ({conclusion})")

    return failed, in_progress, len(check_runs)


# How long to wait for an in-progress CI run before giving up.
# Long enough to cover a typical full matrix + coverage run (~3-4 min)
# with headroom; short enough that a hung CI eventually fails the script
# instead of waiting forever.
_CI_WAIT_TIMEOUT_S = 600
_CI_POLL_INTERVAL_S = 20


def check_ci_passed_on_head() -> bool:
    """Verify that CI passed on the current HEAD commit.

    Polls the GitHub check-runs API for HEAD; if any check is still
    in-progress, waits up to ``_CI_WAIT_TIMEOUT_S`` seconds with
    progress feedback before giving up. The poll loop avoids the
    "rerun the script in 30 seconds" papercut that surfaced during
    the v0.8.1 / v0.8.2 releases — twice in the same session — where
    a stale-read of an in-flight CI run forced a manual retry.
    """
    print_info("Checking CI status on HEAD...")

    head_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    deadline = time.monotonic() + _CI_WAIT_TIMEOUT_S
    last_in_progress: list[str] = []

    while True:
        fetched = _fetch_check_runs(head_sha)
        if fetched is None:
            return False
        failed, in_progress, total = fetched

        if total == 0:
            print_error("No CI check runs found on HEAD commit.")
            print_error(f"  HEAD: {head_sha[:12]}")
            print_error("  Trigger CI manually: gh workflow run ci.yml --ref main")
            print_error("  Then wait for it to complete before re-running this script.")
            return False

        if not in_progress:
            break  # everything is completed; check failures next

        # Progress signal — only re-print when the in-progress set changes
        # so the log doesn't fill with duplicate lines on long runs.
        if in_progress != last_in_progress:
            print_info(f"  CI still running: {', '.join(in_progress)} (waiting up to {_CI_WAIT_TIMEOUT_S}s)")
            last_in_progress = in_progress

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print_error(f"CI did not complete within {_CI_WAIT_TIMEOUT_S}s: {', '.join(in_progress)}")
            print_error("  Investigate why CI is slow or stuck before re-running.")
            return False

        time.sleep(min(_CI_POLL_INTERVAL_S, remaining))

    if failed:
        print_error(f"CI failed: {', '.join(failed)}")
        print_error("  Fix CI failures before tagging.")
        return False

    print_success(f"CI passed on HEAD ({head_sha[:12]}, {total} check(s))")
    return True


def run_tests(repo_root: Path) -> bool:
    """Run the full test suite."""
    try:
        print_info("Running tests...")
        venv_python = repo_root / ".venv" / "bin" / "python"
        if not venv_python.exists():
            venv_python = Path("python")  # Fall back to system python

        subprocess.run(
            [str(venv_python), "-m", "pytest", "-v", "--no-cov"],
            cwd=repo_root,
            check=True,
        )
        print_success("All tests passed")
        return True
    except subprocess.CalledProcessError:
        print_error("Tests failed! Fix issues before releasing.")
        return False


def run_code_quality_checks(repo_root: Path) -> bool:
    """Run code quality checks (ruff, mypy)."""
    try:
        venv_python = repo_root / ".venv" / "bin" / "python"
        if not venv_python.exists():
            venv_python = Path("python")

        # Run ruff
        print_info("Running ruff...")
        subprocess.run(
            [str(venv_python), "-m", "ruff", "check", "."],
            cwd=repo_root,
            check=True,
        )
        print_success("Ruff checks passed")

        # Run mypy
        print_info("Running mypy...")
        subprocess.run(
            [str(venv_python), "-m", "mypy", "src/har_capture"],
            cwd=repo_root,
            check=True,
        )
        print_success("Mypy type checks passed")

        return True
    except subprocess.CalledProcessError:
        print_error("Code quality checks failed!")
        return False


def verify_version_consistency(repo_root: Path, version: str) -> bool:
    """Verify that all version files match the target version."""
    print_info("Verifying version consistency...")

    all_correct = True

    # Check pyproject.toml
    pyproject_path = repo_root / "pyproject.toml"
    try:
        content = pyproject_path.read_text(encoding="utf-8")
        if f'version = "{version}"' not in content:
            match = re.search(r'^version = "([^"]+)"', content, re.MULTILINE)
            current = match.group(1) if match else "unknown"
            print_error(f"pyproject.toml has {current}, expected {version}")
            all_correct = False
        else:
            print_success(f"pyproject.toml: {version}")
    except Exception as e:
        print_error(f"Failed to read pyproject.toml: {e}")
        all_correct = False

    # Check __init__.py
    init_path = repo_root / "src" / "har_capture" / "__init__.py"
    try:
        content = init_path.read_text(encoding="utf-8")
        if f'__version__ = "{version}"' not in content:
            match = re.search(r'__version__ = "([^"]+)"', content)
            current = match.group(1) if match else "unknown"
            print_error(f"__init__.py has {current}, expected {version}")
            all_correct = False
        else:
            print_success(f"__init__.py: {version}")
    except Exception as e:
        print_error(f"Failed to read __init__.py: {e}")
        all_correct = False

    # Check CHANGELOG.md
    changelog_path = repo_root / "CHANGELOG.md"
    try:
        content = changelog_path.read_text(encoding="utf-8")
        if not re.search(rf"## \[{re.escape(version)}\]", content):
            print_error(f"CHANGELOG.md missing ## [{version}] heading")
            all_correct = False
        else:
            print_success(f"CHANGELOG.md: [{version}]")

        # Check comparison link exists
        if not re.search(rf"^\[{re.escape(version)}\]:", content, re.MULTILINE):
            print_error(f"CHANGELOG.md missing [{version}] comparison link at bottom")
            all_correct = False
        else:
            print_success(f"CHANGELOG.md: [{version}] comparison link")
    except Exception as e:
        print_error(f"Failed to read CHANGELOG.md: {e}")
        all_correct = False

    if all_correct:
        print_success("All version files are consistent!")
    else:
        print_error("Version consistency check failed! Fix before tagging.")

    return all_correct


def create_and_push_tag(version: str) -> bool:
    """Create an annotated tag and push it."""
    tag_name = f"v{version}"
    try:
        subprocess.run(
            ["git", "tag", "-a", tag_name, "-m", f"Release {version}"],
            check=True,
        )
        print_success(f"Created tag: {tag_name}")

        subprocess.run(
            ["git", "push", "origin", tag_name],
            check=True,
        )
        print_success(f"Pushed tag: {tag_name}")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create/push tag: {e}")
        return False


# =============================================================================
# Release-discipline audit (gates A + B + E)
# =============================================================================
#
# Three reinforcing checks driven by the v0.8.1 → v0.8.3 case study, where
# we cut three releases for what should have been one. The pattern across
# all three: I (Claude) made decisions at the moment of "should I push?"
# that violated rules I had just written down — the AI knowing-not-applying
# flaw. Each individual check is rubber-stampable in isolation; the value
# is the combination plus Ken's external sign-off, which is the only
# component I cannot route around.
#
#   A. ``scan_for_anti_patterns`` — greps recent git log for known
#      anti-pattern signatures ("pre-existing" framing, retry-past
#      bypasses, deferral words). Reports findings. Catches naive-honest
#      Claude. Brittle to phrasing-drift but cheap and high-signal on
#      today's known modes.
#   B. ``print_audit_checklist`` — prints a diff-grounded checklist on
#      every invocation (including ``--dry-run``). Each question is tied
#      to today's failure modes. Visibility-to-Ken is the actual gate;
#      I answering "no" doesn't help if the answer is wrong.
#   E. ``require_signoff`` — blocks tag-push on Ken typing a per-release
#      phrase. The unfakeable component. Required only on real run, not
#      dry-run. No bypass flag — auto-release contexts need a different
#      code path.

# Anti-pattern signatures. ``BLOCK`` aborts the release; ``WARN`` prints
# a warning that's bundled into the checklist Ken reads before sign-off.
_ANTI_PATTERN_SCANS: list[tuple[str, str, str]] = [
    (
        "BLOCK",
        r"(?i)\bpre[-\s]?existing\b",
        '"pre-existing" framing in commit messages — every "pre-existing" '
        "item I noticed during this session is in-scope for this release. "
        "Either fix it inline or get explicit deferral sign-off.",
    ),
    (
        "WARN",
        r"--no-verify\b|--no-cov\b|--no-gpg-sign\b",
        "commit messages reference a quality-gate bypass flag — verify "
        "these weren't used to skip checks that would have caught issues.",
    ),
    (
        "WARN",
        r"(?i)\b(papercut|minor flake|deferred|retry past|retry-past)\b",
        "commit messages contain words that often mark deferred items "
        "(papercut / flake / deferred / retry past) — confirm the "
        "underlying issue is fixed in this release, not punted forward.",
    ),
]


def _commits_since_last_tag(repo_root: Path) -> tuple[str, str | None, int]:
    """Return ``(log_text, last_tag_or_None, commit_count)`` since last release."""
    tags = (
        subprocess.run(
            ["git", "tag", "--sort=-v:refname", "-l", "v*"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        .stdout.strip()
        .splitlines()
    )
    last_tag = tags[0] if tags and tags[0] else None

    log_range = f"{last_tag}..HEAD" if last_tag else "HEAD"
    log_args = ["git", "log", log_range, "--format=%H %s%n%b%n---"]
    log = subprocess.run(log_args, cwd=repo_root, capture_output=True, text=True, check=True).stdout

    count_args = ["git", "rev-list", "--count", log_range]
    count = int(
        subprocess.run(count_args, cwd=repo_root, capture_output=True, text=True, check=True).stdout.strip()
    )
    return log, last_tag, count


def scan_log_for_anti_patterns(log_text: str) -> tuple[list[str], list[str]]:
    """Pure: scan arbitrary log text for anti-pattern signatures.

    Returns ``(blockers, warnings)``. Extracted from
    ``scan_for_anti_patterns`` so the regex behaviour is unit-testable
    without git fixtures — the wrapper just fetches the log and
    delegates here.
    """
    blockers: list[str] = []
    warnings: list[str] = []
    for severity, pattern, message in _ANTI_PATTERN_SCANS:
        if re.search(pattern, log_text):
            (blockers if severity == "BLOCK" else warnings).append(message)
    return blockers, warnings


def scan_for_anti_patterns(repo_root: Path) -> tuple[list[str], list[str]]:
    """Scan commits since last tag for known anti-pattern signatures.

    Returns ``(blockers, warnings)``. ``blockers`` aborts the release
    unless ``--acknowledged "<reason>"`` is passed; ``warnings`` are
    advisory and printed in the audit Ken reads before signing off.
    """
    log, _, _ = _commits_since_last_tag(repo_root)
    return scan_log_for_anti_patterns(log)


def print_audit_checklist(
    target_version: str, repo_root: Path, blockers: list[str], warnings: list[str]
) -> None:
    """Print the diff-grounded release-discipline audit on stdout.

    Visibility to Ken is the actual gate — these questions are
    rubber-stampable when self-graded but become harder to ignore
    when tied to specific commit/diff context and printed in the
    log Ken reads before sign-off.
    """
    _, last_tag, count = _commits_since_last_tag(repo_root)
    files = (
        subprocess.run(
            ["git", "diff", "--name-only", f"{last_tag or 'HEAD~1'}..HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        .stdout.strip()
        .splitlines()
    )

    print()
    print("=" * 72)
    print(f"  Release-discipline audit — v{target_version}")
    print("=" * 72)
    print()
    print(
        f"  Diff context: {count} commit(s) since {last_tag or 'project start'}, "
        f"{len(files)} file(s) changed."
    )
    if files:
        preview = files[:8]
        for f in preview:
            print(f"    • {f}")
        if len(files) > 8:
            print(f"    … {len(files) - 8} more")
    print()
    print("  Self-audit (Claude must have answered NO to each before push):")
    print()
    print("    1. Did anything I'd frame as 'pre-existing' surface during this")
    print("       session? Every such item is in-scope for THIS release;")
    print("       deferral requires Ken's explicit sign-off, not silence.")
    print()
    print("    2. Did I introduce duplication or hidden contracts in files I")
    print("       touched? docs/ARCHITECTURE.md § Code Organization: DRY non-negotiable.")
    print()
    print("    3. Did I retry past any test failure / flake / CI papercut")
    print("       during this session? Root cause first, then ship.")
    print()
    print("    4. Does the CHANGELOG entry for this release conflate")
    print("       session-debt with pre-existing follow-ups? Separate them.")
    print()
    print("    5. Is this exactly one PR with code+tests+CHANGELOG+version?")
    print("       No parking on main as [Unreleased] between PRs.")
    print()

    if warnings:
        print("  Anti-pattern WARNINGS (advisory):")
        for w in warnings:
            print(f"    ⚠ {w}")
        print()
    if blockers:
        print("  Anti-pattern BLOCKERS (release will not proceed):")
        for b in blockers:
            print(f"    ✗ {b}")
        print()


def expected_signoff_phrase(target_version: str) -> str:
    """Pure: the exact phrase that authorizes ``target_version``."""
    return f"RELEASE OK {target_version}"


def check_signoff_phrase(target_version: str, response: str) -> bool:
    """Pure: does ``response`` match the expected phrase exactly (after strip)?"""
    return response.strip() == expected_signoff_phrase(target_version)


def require_signoff(target_version: str) -> bool:
    """Block tag-push until Ken types the per-release authorization phrase.

    The phrase is intentionally short enough that it doesn't induce
    bypass-frustration but specific enough (per-version) that muscle
    memory can't auto-confirm. There is no ``--yes`` / ``--no-confirm``
    flag — that escape hatch defeats the purpose. CI auto-release
    workflows are a separate concern that needs its own design.
    """
    expected = expected_signoff_phrase(target_version)
    print()
    print("To authorize the tag push, type the following exactly and press Enter:")
    print(f"    {expected}")
    print()
    sys.stdout.write("> ")
    sys.stdout.flush()
    try:
        response = sys.stdin.readline().rstrip("\n").rstrip("\r")
    except (EOFError, KeyboardInterrupt):
        print_error("Sign-off cancelled.")
        return False

    if not check_signoff_phrase(target_version, response):
        print_error(f"Sign-off phrase mismatch. Expected exactly: {expected!r}")
        print_error(f"Got: {response.strip()!r}")
        return False
    return True


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate and tag a release after merging to main",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workflow:
    1. Do all work in feature branch (code, tests, changelog, version bump)
    2. Merge PR to main
    3. git checkout main && git pull
    4. python scripts/release.py X.Y.Z
    5. GitHub Actions creates the release and publishes to PyPI
""",
    )
    parser.add_argument("version", help="Version to release (e.g., 0.4.4)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate only, don't create or push the tag",
    )
    parser.add_argument(
        "--acknowledged",
        metavar="REASON",
        help=(
            "Acknowledge a release-discipline BLOCKER and proceed anyway. "
            "REASON must explain why the blocker is acceptable for this "
            "release. Does not bypass Ken's sign-off (E)."
        ),
    )

    args = parser.parse_args()
    repo_root = get_repo_root()
    version = args.version

    print_info(f"Validating release v{version}")
    print()

    # === VALIDATION PHASE ===
    print_info("=== Pre-flight Checks ===")

    if not validate_version(version):
        print_error(f"Invalid version format: {version}. Must be X.Y.Z")
        sys.exit(1)
    print_success(f"Version format valid: {version}")

    if check_tag_exists(version):
        print_error(f"Tag v{version} already exists!")
        sys.exit(1)
    print_success(f"Tag v{version} does not exist yet")

    branch = get_current_branch()
    if branch != "main":
        print_error(f"Must be on main branch (currently on '{branch}')")
        print_error("  git checkout main && git pull")
        sys.exit(1)
    print_success("On main branch")

    if not check_git_clean():
        print_error("Git working directory is not clean")
        sys.exit(1)
    print_success("Working directory clean")
    print()

    # === CI VERIFICATION PHASE ===
    print_info("=== CI Verification ===")

    if not check_ci_passed_on_head():
        sys.exit(1)
    print()

    # === CONSISTENCY PHASE ===
    print_info("=== Version Consistency ===")

    if not verify_version_consistency(repo_root, version):
        sys.exit(1)
    print()

    # === QUALITY PHASE ===
    print_info("=== Quality Checks ===")

    if not run_tests(repo_root):
        sys.exit(1)

    if not run_code_quality_checks(repo_root):
        sys.exit(1)
    print()

    # === RELEASE-DISCIPLINE AUDIT (A + B) ===
    blockers, warnings = scan_for_anti_patterns(repo_root)
    print_audit_checklist(version, repo_root, blockers, warnings)

    if blockers and not args.acknowledged:
        print_error(
            "Release blocked by anti-pattern findings above. Either fix "
            "each finding inline or re-invoke with "
            '--acknowledged "<reason this is acceptable>".'
        )
        sys.exit(1)
    if blockers and args.acknowledged:
        print_info(f"Acknowledged blockers: {args.acknowledged}")
        print()

    # === TAG PHASE ===
    if args.dry_run:
        print_success(f"Dry run passed! v{version} is ready to tag.")
        print_info("  Run without --dry-run to create and push the tag.")
        return

    # === SIGN-OFF (E) — the unfakeable component ===
    if not require_signoff(version):
        print_error("Sign-off required to proceed; aborting.")
        sys.exit(1)
    print()

    print_info("=== Tagging ===")

    if not create_and_push_tag(version):
        sys.exit(1)
    print()

    print_success(f"Released v{version}!")
    print_info("GitHub Actions will now create the release and publish to PyPI.")
    print_info(f"  https://github.com/solentlabs/har-capture/releases/tag/v{version}")
    print_info(f"  https://pypi.org/project/har-capture/{version}/")


if __name__ == "__main__":
    main()
