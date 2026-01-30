#!/usr/bin/env bash
# Run the same checks as CI locally
# Usage: ./scripts/ci-local.sh [--quick] [--integration]
#
# --quick: Skip slow tests
# --integration: Also run integration tests (requires Playwright)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Auto-activate virtual environment if not already active
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -z "$VIRTUAL_ENV" ]; then
    if [ -f "$REPO_ROOT/.venv/bin/activate" ]; then
        source "$REPO_ROOT/.venv/bin/activate"
    elif [ -f "$REPO_ROOT/venv/bin/activate" ]; then
        source "$REPO_ROOT/venv/bin/activate"
    fi
fi

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  Local CI - mirrors GitHub Actions                    ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Parse arguments
QUICK=false
INTEGRATION=false
for arg in "$@"; do
    case $arg in
        --quick)
            QUICK=true
            ;;
        --integration)
            INTEGRATION=true
            ;;
    esac
done

# Track failures
FAILED=0

# Step 1: Ruff lint (same as CI)
echo -e "\n${YELLOW}[1/3] Running ruff check...${NC}"
if ruff check .; then
    echo -e "${GREEN}✓ Ruff check passed${NC}"
else
    echo -e "${RED}✗ Ruff check failed${NC}"
    FAILED=1
fi

# Step 2: Unit tests (same as CI: pytest -m "not integration")
echo -e "\n${YELLOW}[2/3] Running unit tests...${NC}"
PYTEST_ARGS="--tb=short -q -m 'not integration'"
if [ "$QUICK" = true ]; then
    PYTEST_ARGS="$PYTEST_ARGS -m 'not integration and not slow'"
    echo -e "${YELLOW}  (quick mode - skipping slow tests)${NC}"
fi

if pytest --tb=short -q -m "not integration"; then
    echo -e "${GREEN}✓ Unit tests passed${NC}"
else
    echo -e "${RED}✗ Unit tests failed${NC}"
    FAILED=1
fi

# Step 3: Integration tests (optional, requires Playwright)
if [ "$INTEGRATION" = true ]; then
    echo -e "\n${YELLOW}[3/3] Running integration tests...${NC}"
    if pytest --tb=short -q -m "integration"; then
        echo -e "${GREEN}✓ Integration tests passed${NC}"
    else
        echo -e "${RED}✗ Integration tests failed${NC}"
        FAILED=1
    fi
else
    echo -e "\n${YELLOW}[3/3] Skipping integration tests${NC}"
    echo -e "  (use --integration to run them)"
fi

# Summary
echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All CI checks passed - safe to push${NC}"
    exit 0
else
    echo -e "${RED}✗ CI checks failed - fix before pushing${NC}"
    exit 1
fi
