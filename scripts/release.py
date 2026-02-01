#!/usr/bin/env python3
"""Release automation script for har-capture.

This script automates the complete release process by:
1. Validating the version format
2. Checking git working directory is clean
3. Running tests (pytest)
4. Running code quality checks (ruff, mypy)
5. Verifying CHANGELOG.md has entry for this version
6. Updating version in all required files:
   - pyproject.toml
   - src/har_capture/__init__.py
7. Verifying version consistency
8. Creating a git commit with all changes
9. Creating an annotated git tag
10. Pushing to remote (optional)

Usage:
    python scripts/release.py 0.2.4                    # Full release
    python scripts/release.py 0.2.4 --no-push          # Prepare without pushing
    python scripts/release.py 0.2.4 --skip-tests       # Skip tests (not recommended)
    python scripts/release.py 0.2.4 --skip-quality     # Skip code quality checks
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime
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


def check_changelog_has_version(repo_root: Path, version: str) -> bool:
    """Check that CHANGELOG.md has an entry for this version."""
    changelog_path = repo_root / "CHANGELOG.md"

    try:
        content = changelog_path.read_text(encoding="utf-8")

        # Look for ## [version] pattern
        pattern = rf"## \[{re.escape(version)}\]"
        if re.search(pattern, content):
            print_success(f"CHANGELOG.md has entry for version {version}")
            return True
        print_error(f"CHANGELOG.md missing entry for version {version}")
        print_error("Add changelog entry under ## [Unreleased] before releasing:")
        print_error(f"  ## [{version}] - {datetime.now().strftime('%Y-%m-%d')}")
        return False
    except Exception as e:
        print_error(f"Failed to read CHANGELOG.md: {e}")
        return False


def update_pyproject_toml(repo_root: Path, version: str) -> bool:
    """Update version in pyproject.toml."""
    pyproject_path = repo_root / "pyproject.toml"

    try:
        content = pyproject_path.read_text(encoding="utf-8")

        # Find current version
        match = re.search(r'^version = "([^"]+)"', content, re.MULTILINE)
        if not match:
            print_error("Could not find version in pyproject.toml")
            return False

        old_version = match.group(1)

        # Replace version
        new_content = re.sub(
            r'^version = "[^"]+"',
            f'version = "{version}"',
            content,
            count=1,
            flags=re.MULTILINE,
        )

        pyproject_path.write_text(new_content, encoding="utf-8")
        print_success(f"Updated pyproject.toml: {old_version} → {version}")
        return True
    except Exception as e:
        print_error(f"Failed to update pyproject.toml: {e}")
        return False


def update_init_py(repo_root: Path, version: str) -> bool:
    """Update __version__ in __init__.py."""
    init_path = repo_root / "src" / "har_capture" / "__init__.py"

    try:
        content = init_path.read_text(encoding="utf-8")

        # Find current version
        match = re.search(r'__version__ = "([^"]+)"', content)
        if not match:
            print_error("Could not find __version__ in __init__.py")
            return False

        old_version = match.group(1)

        # Replace version
        new_content = re.sub(
            r'__version__ = "[^"]+"',
            f'__version__ = "{version}"',
            content,
            count=1,
        )

        init_path.write_text(new_content, encoding="utf-8")
        print_success(f"Updated __init__.py: {old_version} → {version}")
        return True
    except Exception as e:
        print_error(f"Failed to update __init__.py: {e}")
        return False


def verify_version_consistency(repo_root: Path, version: str) -> bool:
    """Verify that all version files have been updated correctly."""
    print_info("Verifying version consistency...")

    all_correct = True

    # Check pyproject.toml
    pyproject_path = repo_root / "pyproject.toml"
    try:
        content = pyproject_path.read_text(encoding="utf-8")
        if f'version = "{version}"' not in content:
            print_error(f"pyproject.toml version mismatch: expected {version}")
            all_correct = False
        else:
            print_success(f"pyproject.toml version correct: {version}")
    except Exception as e:
        print_error(f"Failed to read pyproject.toml: {e}")
        all_correct = False

    # Check __init__.py
    init_path = repo_root / "src" / "har_capture" / "__init__.py"
    try:
        content = init_path.read_text(encoding="utf-8")
        if f'__version__ = "{version}"' not in content:
            print_error(f"__init__.py version mismatch: expected {version}")
            all_correct = False
        else:
            print_success(f"__init__.py version correct: {version}")
    except Exception as e:
        print_error(f"Failed to read __init__.py: {e}")
        all_correct = False

    # Check CHANGELOG.md
    changelog_path = repo_root / "CHANGELOG.md"
    try:
        content = changelog_path.read_text(encoding="utf-8")
        if not re.search(rf"## \[{re.escape(version)}\]", content):
            print_error(f"CHANGELOG.md missing entry for version {version}")
            all_correct = False
        else:
            print_success(f"CHANGELOG.md has entry for: {version}")
    except Exception as e:
        print_error(f"Failed to read CHANGELOG.md: {e}")
        all_correct = False

    if all_correct:
        print_success("All version files are consistent!")
    else:
        print_error("Version consistency check failed!")

    return all_correct


def create_commit(repo_root: Path, version: str) -> bool:
    """Create a git commit with version changes."""
    try:
        # Stage the files
        subprocess.run(
            [
                "git",
                "add",
                "pyproject.toml",
                "src/har_capture/__init__.py",
                "CHANGELOG.md",
            ],
            cwd=repo_root,
            check=True,
        )

        # Create commit with co-author
        commit_msg = f"""chore: release version {version}

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"""

        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=repo_root,
            check=True,
        )

        print_success(f"Created commit for version {version}")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create commit: {e}")
        return False


def create_tag(version: str) -> bool:
    """Create an annotated git tag."""
    try:
        tag_name = f"v{version}"
        tag_msg = f"Release {version}"

        subprocess.run(["git", "tag", "-a", tag_name, "-m", tag_msg], check=True)

        print_success(f"Created tag: {tag_name}")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create tag: {e}")
        return False


def push_changes(version: str) -> bool:
    """Push commit and tag to remote."""
    try:
        tag_name = f"v{version}"

        # Get current branch
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            check=True,
        )
        current_branch = result.stdout.strip()

        # Push commit
        subprocess.run(["git", "push", "origin", current_branch], check=True)
        print_success(f"Pushed commit to origin/{current_branch}")

        # Push tag
        subprocess.run(["git", "push", "origin", tag_name], check=True)
        print_success(f"Pushed tag {tag_name} to origin")

        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to push changes: {e}")
        return False


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Automate har-capture releases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/release.py 0.2.4              # Full release
    python scripts/release.py 0.2.4 --no-push    # Prepare without pushing
    python scripts/release.py 0.2.4 --skip-tests # Skip tests (not recommended)
""",
    )
    parser.add_argument("version", help="Version to release (e.g., 0.2.4)")
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Don't push to remote (for testing)",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip running tests (not recommended)",
    )
    parser.add_argument(
        "--skip-quality",
        action="store_true",
        help="Skip code quality checks (not recommended)",
    )

    args = parser.parse_args()
    repo_root = get_repo_root()
    version = args.version

    print_info(f"Starting release process for version {version}")
    print_info(f"Repository root: {repo_root}")
    print()

    # === VALIDATION PHASE ===
    print_info("=== Validation Phase ===")

    # Validate version format
    if not validate_version(version):
        print_error(f"Invalid version format: {version}. Must be X.Y.Z (e.g., 0.2.4)")
        sys.exit(1)
    print_success(f"Version format valid: {version}")

    # Check tag doesn't exist
    if check_tag_exists(version):
        print_error(f"Tag v{version} already exists!")
        sys.exit(1)
    print_success(f"Tag v{version} does not exist yet")

    # Check git is clean
    if not check_git_clean():
        print_error("Git working directory is not clean. Commit or stash changes first.")
        sys.exit(1)
    print_success("Git working directory is clean")
    print()

    # === QUALITY PHASE ===
    print_info("=== Quality Phase ===")

    # Run tests
    if not args.skip_tests:
        if not run_tests(repo_root):
            sys.exit(1)
    else:
        print_warning("Skipping tests (--skip-tests)")

    # Run code quality checks
    if not args.skip_quality:
        if not run_code_quality_checks(repo_root):
            sys.exit(1)
    else:
        print_warning("Skipping code quality checks (--skip-quality)")
    print()

    # === CHANGELOG PHASE ===
    print_info("=== Changelog Phase ===")

    # Check CHANGELOG has entry for this version
    if not check_changelog_has_version(repo_root, version):
        print()
        print_error("Release aborted. Update CHANGELOG.md first:")
        print_error("  1. Add changes under ## [Unreleased]")
        print_error(f"  2. Rename to ## [{version}] - {datetime.now().strftime('%Y-%m-%d')}")
        print_error("  3. Run this script again")
        sys.exit(1)
    print()

    # === UPDATE PHASE ===
    print_info("=== Update Phase ===")

    # Update version files
    if not update_pyproject_toml(repo_root, version):
        sys.exit(1)

    if not update_init_py(repo_root, version):
        sys.exit(1)

    # Verify consistency
    if not verify_version_consistency(repo_root, version):
        sys.exit(1)
    print()

    # === GIT PHASE ===
    print_info("=== Git Phase ===")

    # Create commit
    if not create_commit(repo_root, version):
        sys.exit(1)

    # Create tag
    if not create_tag(version):
        sys.exit(1)

    # Push if not --no-push
    if not args.no_push:
        if not push_changes(version):
            sys.exit(1)
    else:
        print_warning("Skipping push (--no-push)")
        print_info("To complete the release manually:")
        print_info("  git push origin main")
        print_info(f"  git push origin v{version}")
    print()

    # === DONE ===
    if args.no_push:
        print_success(f"Release {version} prepared! Push manually to complete.")
    else:
        print_success(f"Release {version} complete!")
        print_info(f"PyPI publish will be triggered by the v{version} tag")
        print_info(f"Check: https://pypi.org/project/har-capture/{version}/")


if __name__ == "__main__":
    main()
