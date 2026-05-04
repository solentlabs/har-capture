#!/usr/bin/env bash
# Single source of truth for the CI install profile.
#
# Used by:
#   * scripts/ci-local.sh     (matrix-parity pre-push hook)
#   * .github/workflows/ci.yml ``test`` matrix job
#   * .github/workflows/ci.yml ``coverage`` job
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
#
# The chromium browser binary is *not* installed here — only the
# ``playwright`` Python package via the ``[capture]`` extra. Jobs that
# need real browser launches (the ``coverage`` job's integration tests)
# must run ``playwright install chromium`` separately.

set -e

TARGET_PYTHON="${1:-python}"

"$TARGET_PYTHON" -m pip install --upgrade pip --quiet
"$TARGET_PYTHON" -m pip install -e ".[dev,cli,capture]" --quiet
