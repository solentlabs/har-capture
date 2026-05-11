# Tag Protection Setup

This project has multiple layers of tag protection to ensure releases only happen from verified commits.

## Protection Layers

### 1. Pre-Commit Hook (Local)

**File:** `.pre-commit-config.yaml` (hook: `verify-tag-ci`)

**What it does:**

- Runs automatically when you `git push` a tag
- Verifies CI passed on the tagged commit using GitHub CLI
- Blocks the push if CI hasn't passed or if `gh` is not installed (with warning)

**Requirements:**

- Install GitHub CLI: `brew install gh` or https://cli.github.com/
- Authenticate: `gh auth login`

### 2. GitHub Actions Workflow (Remote)

**File:** `.github/workflows/tag-protection.yml`

**What it does:**

- Runs after tag is pushed to GitHub
- Validates:
  - ✅ Commit is on main branch
  - ✅ CI passed on the commit
  - ✅ Version in `pyproject.toml` matches tag
  - ✅ Version in `__init__.py` matches tag
- **Workflow will FAIL if validation fails**

**Note:** This runs *after* the tag is pushed, so if validation fails, you'll need to delete the tag manually.

### 3. GitHub Tag Protection Rules (Optional - Manual Setup)

Recommended for production repos.

#### Setup Steps:

1. Go to **Settings** → **Tags** → **Add rule**

1. **Tag name pattern:** `v*`

1. **Enable:**

   - ☑️ Require status checks to pass
     - Add required checks:
       - `CI`
       - `test (3.10)`
       - `test (3.11)`
       - `test (3.12)`
       - `coverage`
   - ☑️ Require signed commits (optional but recommended)

1. **Restrict who can push:**

   - ☑️ Restrict tag creation to administrators only

1. Click **Create**

#### Requirements:

- GitHub Pro, Team, or Enterprise (not available on free personal repos)
- Repository admin access

______________________________________________________________________

## Release Workflow

### Correct Process

```bash
# 1. Ensure you're on main and up-to-date
git checkout main
git pull

# 2. Verify CI passed on latest commit
gh run list --limit 1
# Look for: "✓ completed  success"

# 3. Create tag
git tag -a v1.0.0 -m "Release v1.0.0"

# 4. Push tag (pre-commit hook will verify CI)
git push origin v1.0.0

# 5. Tag protection workflow validates
# 6. Release workflow builds and publishes
```

### Common Mistakes to Avoid

❌ **Creating tag before merging to main**

```bash
# Wrong:
git checkout feature-branch
git tag v1.0.0
git push origin v1.0.0  # ← Pre-commit hook will block this
```

❌ **Creating tag before CI passes**

```bash
# Wrong:
git push  # Push commit to main
git tag v1.0.0  # ← Don't do this immediately!
git push origin v1.0.0  # ← Pre-commit hook will block if CI hasn't passed
```

✅ **Correct: Wait for CI then tag**

```bash
git push  # Push commit to main
# Wait for CI to pass (check with: gh run list)
git tag v1.0.0
git push origin v1.0.0  # ← Safe, CI has passed
```

______________________________________________________________________

## Troubleshooting

### "gh not found" warning

**Install GitHub CLI:**

```bash
# macOS
brew install gh

# Linux
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh
```

**Authenticate:**

```bash
gh auth login
```

### Tag push blocked by pre-commit hook

If the pre-commit hook blocks your tag push:

1. Check CI status:

   ```bash
   gh run list --commit $(git rev-parse HEAD) --limit 5
   ```

1. Wait for CI to complete:

   ```bash
   gh run watch $(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')
   ```

1. Try pushing the tag again once CI passes

### Tag protection workflow failed

If the tag was pushed but the validation workflow failed:

1. Check the workflow logs:

   ```bash
   gh run view --log
   ```

1. Fix the issue (version mismatch, CI failure, etc.)

1. Delete the tag:

   ```bash
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```

1. Fix and recreate the tag following the correct process

______________________________________________________________________

## Testing Tag Protection

To test the tag protection without actually releasing:

```bash
# Create a test tag (not following v* pattern)
git tag test-tag-protection
git push origin test-tag-protection

# This won't trigger release workflows (they only run on v* tags)
# But you can verify the pre-commit hook works

# Clean up
git tag -d test-tag-protection
git push origin :refs/tags/test-tag-protection
```

______________________________________________________________________

## Bypassing Protection (Emergency Only)

**⚠️ Only use in emergencies!**

If you absolutely must push a tag without waiting for CI:

```bash
# Skip pre-commit hooks
git push origin v1.0.0 --no-verify

# Note: The GitHub Actions workflow will still validate and may fail
```

**This is not recommended and should only be used in extreme circumstances.**

______________________________________________________________________

## See Also

- [Release Workflow](../.github/workflows/release.yml) - Automated release process
- [Contributing Guidelines](../CONTRIBUTING.md) - Development workflow
