# Release Flow

All work ships in **one PR**: code + tests + changelog + version bump.
No separate release PR. No tagging from feature branches.

## PR Checklist (before merge)

- [ ] Version bumped in **both** `pyproject.toml` and `src/har_capture/__init__.py`
- [ ] `CHANGELOG.md` has a `## [X.Y.Z] - YYYY-MM-DD` section with changes
- [ ] `CHANGELOG.md` has a `[X.Y.Z]` comparison link at the bottom
- [ ] `CHANGELOG.md` `[unreleased]` link updated to compare from `vX.Y.Z`
- [ ] Tests pass: `.venv/bin/python3 -m pytest tests/ -v --tb=short -m "not integration"`
- [ ] Pre-commit hooks pass: `.venv/bin/python3 -m pre_commit run --all-files`
- [ ] Commit message follows conventional format: `type(scope): message`

## Pipeline: PR → PyPI

```text
1. Push to feature branch
   └─ No CI (only main + PRs trigger CI)

2. Create PR targeting main
   └─ ci.yml triggers: tests on Python 3.10-3.13, coverage + integration tests
   └─ PR must pass before merge

3. Merge PR to main (developer only)
   └─ ci.yml triggers again on the merge commit
   └─ This is the commit release.py will validate

4. Run release script (developer only)
   $ git checkout main && git pull
   $ python scripts/release.py X.Y.Z        # or --dry-run first
   └─ Validates: on main, clean worktree, no existing tag
   └─ Validates: CI passed on HEAD commit (via GitHub API)
   └─ Validates: version consistent across pyproject.toml, __init__.py, CHANGELOG.md
   └─ Runs tests + ruff + mypy locally
   └─ Creates and pushes annotated tag vX.Y.Z

5. Tag push triggers three GitHub Actions workflows:
   ├─ tag-protection.yml: verifies tag → main, CI passed, version matches
   ├─ release.yml: extracts CHANGELOG section → creates GitHub Release
   └─ publish.yml: builds sdist+wheel → publishes to PyPI (trusted publishing)
```

## CHANGELOG Format

Uses [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Update in
the same PR as the code change. Don't forget the comparison link at the
bottom and the `[unreleased]` link update.

## Recovery

If tag push doesn't trigger workflows within ~60s, delete and re-push:

```bash
git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z
git tag -a vX.Y.Z -m "Release X.Y.Z" && git push origin vX.Y.Z
```
