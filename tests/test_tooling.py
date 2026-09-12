"""The shared developer tooling agrees with itself and with the code.

The commit hooks, CI and the local CI mirror run the same tools on the same
inputs (docs/CODE_REVIEW.md, "Quality Gates"), and the shared VS Code tasks and
launch configs call the CLI and tools the way they currently exist. Each rule
spans config files that change independently, so it is checked rather than
trusted.
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


# ── Shared VS Code tasks and launch configs ──────────────────────────────────
# They are developer tools other contributors run, so every har-capture call in
# them must parse against the current CLI, and every `python -m` module must be
# installed by the dev profile.

_VSCODE = _ROOT / ".vscode"
_CLI_MODULES = {"har_capture", "har_capture.cli.main"}


def _vscode(name: str) -> dict[str, Any]:
    return json.loads((_VSCODE / name).read_text())


def _with_inputs(args: list[str], inputs: list[dict[str, Any]]) -> list[str]:
    """Replace ``${input:id}`` with that input's default, as VS Code would prefill it."""
    defaults = {i["id"]: i.get("default", "") for i in inputs}
    return [re.sub(r"\$\{input:(\w+)\}", lambda m: defaults[m.group(1)], a) for a in args]


def _cli_invocations() -> list[tuple[str, list[str]]]:
    calls = []
    tasks = _vscode("tasks.json")
    for task in tasks["tasks"]:
        if task["command"].endswith("/har-capture"):
            calls.append(
                (f"task: {task['label']}", _with_inputs(task.get("args", []), tasks.get("inputs", [])))
            )
    launch = _vscode("launch.json")
    for config in launch["configurations"]:
        if config.get("module") in _CLI_MODULES:
            calls.append(
                (f"launch: {config['name']}", _with_inputs(config["args"], launch.get("inputs", [])))
            )
    return calls


CLI_INVOCATIONS = _cli_invocations()


def _test_id(where: str) -> str:
    return re.sub(r"[^\x20-\x7e]", "", where).replace("  ", " ").strip()


def test_every_cli_use_is_parse_checked() -> None:
    """A task or config that calls the CLI some other way would dodge the parse test."""
    covered = {where for where, _ in CLI_INVOCATIONS}
    uses = [
        f"task: {t['label']}"
        for t in _vscode("tasks.json")["tasks"]
        if re.search(r"har.capture", json.dumps(t))
    ]
    uses += [
        f"launch: {c['name']}"
        for c in _vscode("launch.json")["configurations"]
        if re.search(r"har.capture", json.dumps(c))
    ]
    assert uses, "no task or launch config calls the CLI"
    assert set(uses) == covered


@pytest.mark.parametrize(("where", "argv"), CLI_INVOCATIONS, ids=[_test_id(c[0]) for c in CLI_INVOCATIONS])
def test_vscode_cli_invocation_parses(where: str, argv: list[str]) -> None:
    """Parse, don't run: an unknown option or a missing required one fails here.

    ``--patterns`` is required by the commands themselves (``require_patterns``),
    not by the parser, so that check is applied to the parsed value too.
    """
    typer = pytest.importorskip("typer")
    from har_capture.cli._patterns_resolver import require_patterns
    from har_capture.cli.main import app

    group = typer.main.get_command(app)
    parent = group.context_class(group, info_name="har-capture")
    command = group.get_command(parent, argv[0])
    assert command is not None, f"{where}: no command {argv[0]!r}"
    ctx = command.make_context(argv[0], argv[1:], parent=parent)
    if "patterns" in ctx.params:
        require_patterns(ctx.params["patterns"])


def test_vscode_python_modules_are_installed() -> None:
    import importlib.util

    commands = [t["command"] for t in _vscode("tasks.json")["tasks"]]
    modules = {m for c in commands for m in re.findall(r"\bpython3? -m ([\w.]+)", c)} - {"venv"}
    modules |= {c["module"] for c in _vscode("launch.json")["configurations"] if "module" in c}
    missing = sorted(m for m in modules if importlib.util.find_spec(m) is None)
    assert missing == []
