"""Test version consistency across package files."""

from __future__ import annotations

import re
from pathlib import Path


def test_version_matches_pyproject() -> None:
    """Ensure __version__ in __init__.py matches pyproject.toml."""
    from har_capture import __version__

    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    pyproject_text = pyproject_path.read_text()

    # Parse version from pyproject.toml using regex (avoids tomllib/tomli dependency)
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE)
    assert match, "Could not find version in pyproject.toml"
    pyproject_version = match.group(1)

    assert __version__ == pyproject_version, (
        f"Version mismatch: __init__.py has {__version__!r}, pyproject.toml has {pyproject_version!r}"
    )
