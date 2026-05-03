#!/usr/bin/env bash
# Run the same checks as the GitHub Actions ``test`` matrix locally.
#
# Usage: ./scripts/ci-local.sh [--quick] [--integration]
#
# --quick:        Skip slow tests
# --integration:  Also run integration tests (requires Playwright chromium)
#
# Why this script uses its own venv (.venv-ci/) instead of .venv/:
#
#   The CI matrix installs a deliberately-reduced set of extras (see
#   ``CI_EXTRAS`` below — keep it in sync with .github/workflows/ci.yml).
#   The developer's .venv/ accumulates everything (dev tools, optional
#   extras, ad-hoc packages) and *lies* about what the matrix will see.
#
#   v0.8.1 push regression: a coverage-gate bump from 75 to 90 passed
#   locally at 94% in .venv/ (with [capture] installed) but failed CI
#   at 88% (matrix has no [capture], so 169 Playwright-using unit tests
#   import-skipped and capture/browser.py dropped 87% → 36%). The old
#   ci-local.sh used .venv/ and silently passed. This rewrite isolates
#   the matrix profile so divergence is caught pre-push.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─── Single source of truth for the matrix install profile ──────────────────
# This MUST match the ``test`` job's ``pip install -e ".[...]"`` line in
# .github/workflows/ci.yml. When the workflow changes, change this too.
CI_EXTRAS="dev,cli,capture"
CI_VENV="$REPO_ROOT/.venv-ci"
HASH_FILE="$CI_VENV/.profile-hash"

# Hash inputs that determine what should be in the venv. If any of them
# changes (extras list, pyproject.toml dependencies, Python version),
# rebuild from scratch.
PROFILE_HASH="$(
    {
        echo "$CI_EXTRAS"
        cat "$REPO_ROOT/pyproject.toml"
        python3 --version
    } | sha256sum | cut -d' ' -f1
)"

# Parse arguments
QUICK=false
INTEGRATION=false
for arg in "$@"; do
    case $arg in
        --quick)       QUICK=true ;;
        --integration) INTEGRATION=true ;;
    esac
done

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  Local CI — mirrors GitHub Actions ``test`` matrix     ${NC}"
echo -e "${YELLOW}  Install profile: [${CI_EXTRAS}]                       ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ─── Bootstrap or reuse the isolated venv ───────────────────────────────────
if [ ! -f "$HASH_FILE" ] || [ "$(cat "$HASH_FILE" 2>/dev/null)" != "$PROFILE_HASH" ]; then
    echo -e "\n${YELLOW}Bootstrapping ${CI_VENV} with [${CI_EXTRAS}]...${NC}"
    rm -rf "$CI_VENV"
    python3 -m venv "$CI_VENV"
    "$CI_VENV/bin/python" -m pip install --upgrade pip --quiet
    "$CI_VENV/bin/pip" install -e ".[${CI_EXTRAS}]" --quiet
    echo "$PROFILE_HASH" > "$HASH_FILE"
    echo -e "${GREEN}✓ venv ready${NC}"
else
    echo -e "\n${GREEN}✓ Reusing cached ${CI_VENV} (profile unchanged)${NC}"
fi

PYTHON="$CI_VENV/bin/python"
FAILED=0

# ─── Step 1: ruff (matches CI ``Lint with ruff`` step) ──────────────────────
echo -e "\n${YELLOW}[1/4] ruff check${NC}"
if "$PYTHON" -m ruff check .; then
    echo -e "${GREEN}✓ ruff${NC}"
else
    echo -e "${RED}✗ ruff${NC}"
    FAILED=1
fi

# ─── Step 2: unit tests (matches CI ``Run unit tests`` step) ────────────────
echo -e "\n${YELLOW}[2/4] unit tests + coverage gate${NC}"
MARKER="not integration"
[ "$QUICK" = true ] && MARKER="not integration and not slow"

if "$PYTHON" -m pytest --tb=short -q -m "$MARKER" --cov=har_capture --cov-report=term-missing; then
    echo -e "${GREEN}✓ unit tests${NC}"
else
    echo -e "${RED}✗ unit tests / coverage gate${NC}"
    FAILED=1
fi

# ─── Step 3: per-module floors (matches CI ``Enforce ... floors`` step) ─────
echo -e "\n${YELLOW}[3/4] per-module coverage floors${NC}"
if "$PYTHON" scripts/check_coverage_floors.py; then
    echo -e "${GREEN}✓ floors${NC}"
else
    echo -e "${RED}✗ floors${NC}"
    FAILED=1
fi

# ─── Step 4: integration (optional; requires chromium) ──────────────────────
if [ "$INTEGRATION" = true ]; then
    echo -e "\n${YELLOW}[4/4] integration tests${NC}"
    if "$PYTHON" -m pytest --tb=short -q -m "integration"; then
        echo -e "${GREEN}✓ integration${NC}"
    else
        echo -e "${RED}✗ integration${NC}"
        FAILED=1
    fi
else
    echo -e "\n${YELLOW}[4/4] integration skipped (use --integration)${NC}"
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
