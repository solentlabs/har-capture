#!/usr/bin/env bash
# Single source of truth for the CI install profile.
#
# Used by:
#   * scripts/ci-local.sh     (matrix-parity pre-push hook)
#   * .github/workflows/ci.yml ``test`` matrix job
#   * .github/workflows/ci.yml ``coverage`` job
#   * .github/workflows/ci.yml ``test-lowest-deps`` job (``lowest`` mode)
#
# Why this script exists: the v0.8.1 → v0.8.2 push regression happened
# because ``ci-local.sh``'s install profile (``[dev,cli,capture]``) and
# the matrix workflow's install profile (``[dev,cli]``) had drifted —
# local-parity claimed "mirrors CI" while running a different profile.
# Extracting the install line here is the structural fix: there is one
# install command, and it is executed verbatim by every consumer.
#
# Usage:
#   ./scripts/install-ci-deps.sh                # uses ``python`` from PATH
#   ./scripts/install-ci-deps.sh /path/to/python  # uses a specific interpreter
#   ./scripts/install-ci-deps.sh /path/to/python lowest
#       every direct dependency at the lowest version pyproject.toml allows
#       (uv ``--resolution lowest-direct``; transitive ones resolve normally),
#       so a declared floor that no longer works fails a job instead of a
#       user's install.
#
# The chromium browser binary is *not* installed here — only the
# ``playwright`` Python package via the ``[capture]`` extra. Jobs that
# need real browser launches (the ``coverage`` job's integration tests)
# must run ``playwright install chromium`` separately.

set -e

TARGET_PYTHON="${1:-python}"
RESOLUTION="${2:-highest}"

"$TARGET_PYTHON" -m pip install --upgrade pip --quiet
if [ "$RESOLUTION" = "lowest" ]; then
    "$TARGET_PYTHON" -m pip install uv --quiet
    # uv reads a bare name like ``python`` as "find a virtual environment";
    # an absolute interpreter path installs into that interpreter, venv or not.
    INTERPRETER="$("$TARGET_PYTHON" -c 'import sys; print(sys.executable)')"
    "$TARGET_PYTHON" -m uv pip install --python "$INTERPRETER" --resolution lowest-direct -e ".[dev,cli,capture]" --quiet
else
    "$TARGET_PYTHON" -m pip install -e ".[dev,cli,capture]" --quiet
fi
