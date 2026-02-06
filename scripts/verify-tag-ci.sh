#!/usr/bin/env bash
# Verify CI passed before allowing tag push
# Used by pre-commit hook

set -e

# Check if we're on a detached HEAD (tag push scenario)
if git symbolic-ref -q HEAD >/dev/null; then
  # Normal push, not a tag
  exit 0
fi

# Get the tag name if this is a tag
TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")

if [ -z "$TAG" ]; then
  # Not a tag push
  exit 0
fi

COMMIT=$(git rev-parse HEAD)

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Verifying CI for tag: $TAG"
echo "Commit: $COMMIT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if gh CLI is installed
if ! command -v gh >/dev/null 2>&1; then
  echo "⚠️  WARNING: GitHub CLI (gh) not found"
  echo "Cannot verify CI status automatically."
  echo ""
  echo "Install: https://cli.github.com/"
  exit 0
fi

# Check CI status
echo "Checking CI status..."
CI_STATUS=$(gh run list --commit "$COMMIT" --limit 1 --json conclusion --jq ".[0].conclusion" 2>/dev/null || echo "unknown")

if [ "$CI_STATUS" != "success" ]; then
  echo "❌ ERROR: CI has not passed on commit $COMMIT"
  echo "   Status: $CI_STATUS"
  echo ""
  echo "Please wait for CI to complete successfully before pushing tags."
  echo ""
  echo "Check status: gh run list --commit $COMMIT"
  exit 1
fi

echo "✅ CI passed on commit $COMMIT"
echo "Safe to push tag $TAG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit 0
