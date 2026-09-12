"""The commit hooks, CI and the local CI mirror run the same tools on the same inputs.

See docs/CODE_REVIEW.md, "Quality Gates". Each rule here spans two or three
config files that change independently, so it is checked rather than trusted.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

_ROOT = Path(__file__).resolve().parent.parent
_FIXTURES = json.loads((_ROOT / "tests" / "fixtures" / "test_tooling.json").read_text())
PINNED_TOOLS = _FIXTURES["pinned_tools"]["cases"]

_PYPROJECT = tomllib.loads((_ROOT / "pyproject.toml").read_text())
_PRECOMMIT = yaml.safe_load((_ROOT / ".pre-commit-config.yaml").read_text())
_EXTRAS = _PYPROJECT["project"]["optional-dependencies"]


def _repo(url: str) -> dict[str, Any]:
    """Return one ``repos`` entry from .pre-commit-config.yaml."""
    return next(r for r in _PRECOMMIT["repos"] if r["repo"] == url)


def _dev_pin(package: str) -> str:
    """Return the exact version pyproject.toml's dev extra pins for a package."""
    for requirement in _PYPROJECT["project"]["optional-dependencies"]["dev"]:
        match = re.fullmatch(rf"{re.escape(package)}==(\S+)", requirement)
        if match:
            return match.group(1)
    pytest.fail(f"{package} is not pinned with == in the dev extra")


@pytest.mark.parametrize("tool", PINNED_TOOLS, ids=[t["id"] for t in PINNED_TOOLS])
def test_hook_rev_matches_dev_pin(tool: dict) -> None:
    assert _repo(tool["hook_repo"])["rev"].removeprefix("v") == _dev_pin(tool["package"])


def test_mypy_hook_installs_the_cli_and_capture_extras() -> None:
    """The mypy hook type-checks against the same third-party packages CI installs."""
    (hook,) = _repo("https://github.com/pre-commit/mirrors-mypy")["hooks"]
    assert set(hook["additional_dependencies"]) == set(_EXTRAS["cli"]) | set(_EXTRAS["capture"])


def test_full_extra_is_cli_plus_capture() -> None:
    assert set(_EXTRAS["full"]) == set(_EXTRAS["cli"]) | set(_EXTRAS["capture"])


def test_local_mirror_covers_the_ci_matrix() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    ci_versions = re.search(r"python-version:\s*\[([^\]]+)\]", workflow)
    mirror_versions = re.search(
        r'^MATRIX_VERSIONS="([^"]+)"', (_ROOT / "scripts" / "ci-local.sh").read_text(), re.MULTILINE
    )
    assert ci_versions is not None
    assert mirror_versions is not None
    assert re.findall(r'"([^"]+)"', ci_versions.group(1)) == mirror_versions.group(1).split()
