#!/usr/bin/env bash
# Run the same checks as CI locally
# Usage: ./scripts/ci-local.sh [--quick]
#
# --quick: Skip slow tests (pytest -m "not slow")

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
echo -e "${YELLOW}  Running local CI checks                              ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Parse arguments
QUICK=false
for arg in "$@"; do
    case $arg in
        --quick)
            QUICK=true
            shift
            ;;
    esac
done

# Track failures
FAILED=0

# Step 1: Ruff lint
echo -e "\n${YELLOW}[1/3] Running ruff check...${NC}"
if ruff check .; then
    echo -e "${GREEN}✓ Ruff check passed${NC}"
else
    echo -e "${RED}✗ Ruff check failed${NC}"
    FAILED=1
fi

# Step 2: Ruff format check
echo -e "\n${YELLOW}[2/3] Checking ruff format...${NC}"
if ruff format --check .; then
    echo -e "${GREEN}✓ Ruff format check passed${NC}"
else
    echo -e "${RED}✗ Ruff format check failed${NC}"
    echo -e "${YELLOW}  Run 'ruff format .' to fix${NC}"
    FAILED=1
fi

# Step 3: Pytest
echo -e "\n${YELLOW}[3/3] Running pytest...${NC}"
if [ "$QUICK" = true ]; then
    echo -e "${YELLOW}  (quick mode - skipping slow tests)${NC}"
    if pytest --tb=short -q -m "not slow"; then
        echo -e "${GREEN}✓ Tests passed${NC}"
    else
        echo -e "${RED}✗ Tests failed${NC}"
        FAILED=1
    fi
else
    if pytest --tb=short -q; then
        echo -e "${GREEN}✓ Tests passed${NC}"
    else
        echo -e "${RED}✗ Tests failed${NC}"
        FAILED=1
    fi
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
