#!/usr/bin/env bash
# Run the same checks as the GitHub Actions ``test`` matrix locally.
#
# Usage: ./scripts/ci-local.sh [--quick] [--integration] [--matrix]
#
# --quick:        Skip slow tests
# --integration:  Also run integration tests (requires Playwright chromium)
# --matrix:       Run the unit suite, coverage gate and floors on every
#                 Python version in CI's matrix, plus CI's lowest-dependencies
#                 job, instead of on the host Python alone (needs uv to
#                 provision the interpreters). The pre-push hook passes this.
#
# Why this script uses its own venvs (.venv-ci*/) instead of .venv/:
#
#   CI installs exactly what scripts/install-ci-deps.sh installs, freshly
#   resolved. The developer's .venv/ accumulates everything (other extras,
#   ad-hoc packages, whatever versions were current when it was built) and
#   lies about what CI will see — a coverage gate once passed at 94% here and
#   failed CI at 88% for that reason. These venvs are built by the same
#   install script and rebuilt daily, so they resolve what CI resolves.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─── Install profile is sourced from scripts/install-ci-deps.sh ─────────────
# That script is the single source of truth used by both this hook and
# .github/workflows/ci.yml. A venv's cache key covers the install script,
# pyproject.toml, the Python version and today's date, so it is rebuilt when
# the profile changes and once a day to pick up new dependency releases.
CI_INSTALL_SCRIPT="$SCRIPT_DIR/install-ci-deps.sh"
CI_VENV="$REPO_ROOT/.venv-ci"
HASH_FILE="$CI_VENV/.profile-hash"

PROFILE_HASH="$(
    {
        cat "$CI_INSTALL_SCRIPT"
        cat "$REPO_ROOT/pyproject.toml"
        python3 --version
        date +%F
    } | sha256sum | cut -d' ' -f1
)"

# Keep in sync with ``matrix.python-version`` in .github/workflows/ci.yml.
MATRIX_VERSIONS="3.10 3.11 3.12 3.13"

# Parse arguments
QUICK=false
INTEGRATION=false
MATRIX=false
for arg in "$@"; do
    case $arg in
        --quick)       QUICK=true ;;
        --integration) INTEGRATION=true ;;
        --matrix)      MATRIX=true ;;
    esac
done

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  Local CI — mirrors GitHub Actions ``test`` matrix     ${NC}"
echo -e "${YELLOW}  Install via: scripts/install-ci-deps.sh               ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ─── Bootstrap or reuse the isolated venv ───────────────────────────────────
if [ ! -f "$HASH_FILE" ] || [ "$(cat "$HASH_FILE" 2>/dev/null)" != "$PROFILE_HASH" ] \
    || ! "$CI_VENV/bin/python" -c "" >/dev/null 2>&1; then
    echo -e "\n${YELLOW}Bootstrapping ${CI_VENV}...${NC}"
    rm -rf "$CI_VENV"
    python3 -m venv "$CI_VENV"
    "$CI_INSTALL_SCRIPT" "$CI_VENV/bin/python"
    echo "$PROFILE_HASH" > "$HASH_FILE"
    echo -e "${GREEN}✓ venv ready${NC}"
else
    echo -e "\n${GREEN}✓ Reusing cached ${CI_VENV} (profile unchanged)${NC}"
fi

PYTHON="$CI_VENV/bin/python"
FAILED=0

# The variables GitHub Actions sets. Tools change behavior on them — typer,
# for one, forces colored output under GITHUB_ACTIONS — so tests run here see
# what they see in CI.
export CI=true GITHUB_ACTIONS=true

# ─── Step 1: ruff and mypy (match CI's lint, format and type-check steps) ──
echo -e "\n${YELLOW}[1/3] ruff check, ruff format --check, mypy${NC}"
if "$PYTHON" -m ruff check . && "$PYTHON" -m ruff format --check . && "$PYTHON" -m mypy src/; then
    echo -e "${GREEN}✓ ruff + mypy${NC}"
else
    echo -e "${RED}✗ ruff + mypy${NC}"
    FAILED=1
fi

MARKER="not integration"
[ "$QUICK" = true ] && MARKER="not integration and not slow"

# ─── Step 2: unit tests + coverage gate, then floors ──────────────────────
#
# One run is one CI ``test`` job: the unit suite under the coverage gate, then
# the per-module floors. Without --matrix it runs on the host Python in
# .venv-ci; with --matrix, once per Python in CI's matrix and once for CI's
# ``test-lowest-deps`` job, in parallel.
if [ "$MATRIX" = false ]; then
    echo -e "\n${YELLOW}[2/3] unit tests + coverage gate, then floors${NC}"
    if "$PYTHON" -m pytest --tb=short -q -m "$MARKER" --cov=har_capture --cov-report=term-missing; then
        echo -e "${GREEN}✓ unit tests${NC}"
    else
        echo -e "${RED}✗ unit tests / coverage gate${NC}"
        FAILED=1
    fi

    if "$PYTHON" scripts/check_coverage_floors.py; then
        echo -e "${GREEN}✓ floors${NC}"
    else
        echo -e "${RED}✗ floors${NC}"
        FAILED=1
    fi
else
    echo -e "\n${YELLOW}[2/3] unit tests + coverage gate + floors: Python ${MATRIX_VERSIONS}, and lowest dependencies${NC}"
    if ! command -v uv >/dev/null 2>&1; then
        echo -e "${RED}✗ --matrix needs uv (https://docs.astral.sh/uv/) to provision the interpreters${NC}"
        FAILED=1
    else
        # Build (or reuse) every venv before starting any test, so a failed
        # build can't leave earlier runs going with no one waiting on them.
        # A venv is rebuilt when the install profile changes, once a day (so
        # new dependency releases land here the same day they land in CI),
        # and whenever its interpreter no longer runs.
        RUNS=""
        for RUN in $MATRIX_VERSIONS lowest; do
            VENV="$REPO_ROOT/.venv-ci-$RUN"
            if [ "$RUN" = lowest ]; then PYVER=3.10; MODE=lowest; else PYVER=$RUN; MODE=highest; fi
            VHASH="$({ cat "$CI_INSTALL_SCRIPT"; cat "$REPO_ROOT/pyproject.toml"; echo "$RUN"; date +%F; } | sha256sum | cut -d' ' -f1)"
            if [ ! -f "$VENV/.profile-hash" ] || [ "$(cat "$VENV/.profile-hash")" != "$VHASH" ] \
                || ! "$VENV/bin/python" -c "" >/dev/null 2>&1; then
                rm -rf "$VENV"
                if uv venv --quiet --seed --python "$PYVER" "$VENV" && "$CI_INSTALL_SCRIPT" "$VENV/bin/python" "$MODE"; then
                    echo "$VHASH" > "$VENV/.profile-hash"
                else
                    echo -e "${RED}✗ could not build ${VENV}${NC}"
                    FAILED=1
                    continue
                fi
            fi
            RUNS="$RUNS $RUN"
        done

        PIDS=""
        for RUN in $RUNS; do
            VENV="$REPO_ROOT/.venv-ci-$RUN"
            (
                export COVERAGE_FILE="$VENV/.coverage"
                "$VENV/bin/python" -m pytest -q -p no:cacheprovider -m "$MARKER" \
                    --cov=har_capture --cov-report=term --cov-report="html:$VENV/htmlcov" \
                    && "$VENV/bin/python" scripts/check_coverage_floors.py
            ) > "$VENV/.last-run.log" 2>&1 &
            PIDS="$PIDS $!:$RUN"
        done
        for ENTRY in $PIDS; do
            PID="${ENTRY%%:*}"
            RUN="${ENTRY##*:}"
            LABEL="Python $RUN"
            [ "$RUN" = lowest ] && LABEL="lowest dependencies (Python 3.10)"
            if wait "$PID"; then
                echo -e "${GREEN}✓ ${LABEL}${NC}"
            else
                echo -e "${RED}✗ ${LABEL}${NC}"
                cat "$REPO_ROOT/.venv-ci-$RUN/.last-run.log"
                FAILED=1
            fi
        done
    fi
fi

# ─── Step 3: integration (optional; requires chromium) ──────────────────────
#
# ``--cov-append`` mirrors CI's ``coverage`` job, which runs the unit suite with
# ``--cov`` and then the integration suite with ``--cov-append`` so the gate
# sees *combined* coverage. Without it, pytest's default ``addopts`` starts a
# fresh coverage run over 26 tests and ``fail_under = 90`` rejects it at ~29% —
# ``--integration`` could never pass, no matter the state of the tree.
if [ "$INTEGRATION" = true ]; then
    echo -e "\n${YELLOW}[3/3] integration tests${NC}"
    if "$PYTHON" -m pytest --tb=short -q -m "integration" \
        --cov=har_capture --cov-append --cov-report=term-missing; then
        echo -e "${GREEN}✓ integration${NC}"
    else
        echo -e "${RED}✗ integration${NC}"
        FAILED=1
    fi
else
    echo -e "\n${YELLOW}[3/3] integration skipped (use --integration)${NC}"
fi


# ─── Summary ────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ matrix profile passes — safe to push${NC}"
    exit 0
else
    echo -e "${RED}✗ matrix profile failing — fix before push${NC}"
    exit 1
fi
