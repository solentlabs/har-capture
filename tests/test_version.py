"""Test version consistency across package files."""

from __future__ import annotations

from pathlib import Path


def test_version_matches_pyproject() -> None:
    """Ensure __version__ in __init__.py matches pyproject.toml."""
    import tomllib

    from har_capture import __version__

    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)

    pyproject_version = pyproject["project"]["version"]

    assert __version__ == pyproject_version, (
        f"Version mismatch: __init__.py has {__version__!r}, "
        f"pyproject.toml has {pyproject_version!r}"
    )
