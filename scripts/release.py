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


def check_ci_passed_on_head() -> bool:
    """Verify that CI passed on the current HEAD commit.

    Uses the GitHub CLI to query check runs on HEAD. Ensures at least one
    CI run exists and all completed successfully. This catches the failure
    mode where code is merged to main without CI running (e.g. --admin merge).
    """
    print_info("Checking CI status on HEAD...")

    head_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{{owner}}/{{repo}}/commits/{head_sha}/check-runs"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print_error("GitHub CLI (gh) not found. Install it: https://cli.github.com/")
        return False
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to query GitHub CI status: {e.stderr.strip()}")
        return False

    data = json.loads(result.stdout)
    check_runs = data.get("check_runs", [])

    if not check_runs:
        print_error("No CI check runs found on HEAD commit.")
        print_error(f"  HEAD: {head_sha[:12]}")
        print_error("  Trigger CI manually: gh workflow run ci.yml --ref main")
        print_error("  Then wait for it to complete before re-running this script.")
        return False

    failed = []
    in_progress = []
    for run in check_runs:
        name = run.get("name", "unknown")
        status = run.get("status", "unknown")
        conclusion = run.get("conclusion")

        if status != "completed":
            in_progress.append(name)
        elif conclusion != "success":
            failed.append(f"{name} ({conclusion})")

    if in_progress:
        print_error(f"CI still running: {', '.join(in_progress)}")
        print_error("  Wait for CI to complete before tagging.")
        return False

    if failed:
        print_error(f"CI failed: {', '.join(failed)}")
        print_error("  Fix CI failures before tagging.")
        return False

    print_success(f"CI passed on HEAD ({head_sha[:12]}, {len(check_runs)} check(s))")
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

    # === TAG PHASE ===
    if args.dry_run:
        print_success(f"Dry run passed! v{version} is ready to tag.")
        print_info("  Run without --dry-run to create and push the tag.")
        return

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
