# Release Flow

All work ships in **one PR**: code + tests + changelog + version bump. No separate release PR. No tagging from feature
branches.

## Version Numbering

Pre-1.0 policy. Once we reach 1.0 this becomes standard [Semantic Versioning](https://semver.org/).

- **Minor (0.x.0)** — breaking change (any conventional-commit `!` marker, e.g. `feat(cli)!:`), new user-facing feature,
  new public API surface, or new CLI subcommand.
- **Patch (0.x.y)** — refinement to existing behavior, fix, internal improvement, test/coverage addition, doc change.

A `feat:` conventional-commit prefix does **not** automatically mean minor pre-1.0. The CHANGELOG section header is the
binding signal: a `feat(scope):` commit that refines existing behavior and lands under `Changed` (non-breaking) is a
**patch**.

| CHANGELOG section        | Version bump                   |
| ------------------------ | ------------------------------ |
| `Added`                  | Minor                          |
| `Changed (BREAKING)`     | Minor                          |
| `Changed` (non-breaking) | Patch                          |
| `Deprecated` / `Removed` | Minor                          |
| `Fixed`                  | Patch                          |
| `Security`               | Patch (unless behavior change) |

When a release PR carries mixed sections, the highest-ranked section wins (`Added` or `Changed (BREAKING)` → minor
regardless of what else is in the PR).

**Examples from project history:**

- `0.8.0 → 0.8.1`: popup traffic fix + CLI coverage → patch
- `0.8.2 → 0.8.3`: release-discipline gates + CI tooling → patch
- `0.8.3 → 0.9.0`: `feat(cli)!:` mandatory `--patterns` (breaking) plus heuristic detectors (new feature) → **minor**
- `0.9.0 → 0.9.1`: `feat(sanitization):` Authorization scheme preservation (refinement, lands under `Changed`) plus test
  coverage and doc audit → patch

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

## Branching and Merging

### One PR per release

All in-flight work for the next release lands on a single PR. Before opening a new branch or PR, check open PRs already
targeting the next release and bundle into the existing one:

```bash
gh pr list --state open
```

If an open PR is targeting the same release (visible in the PR description's "Release target" line, or implied by the
upcoming version number), cherry-pick your commit onto that branch and push. The PR auto-updates. Don't open a parallel
PR for the same release.

### Consolidate unpushed local branches before pushing

When multiple local branches all target the same release, consolidate to one before pushing. Cherry-pick the loose work
onto the canonical branch and delete the redundant locals. Don't push parallel branches that will then need to merge
separately.

### Cherry-pick onto in-flight branches; rebase across release lines

Cherry-picking is fine when consolidating onto an in-flight branch off the same base, or when backporting across release
lines (a hotfix from `main` into an older release line). For branches with a shared upstream history, rebase to avoid
duplicate commits.

### Merge strategy

- **Bundled release PR** (multiple commits, the common case here): merge-commit. Preserves the per-commit story — the
  CHANGELOG is the user-facing summary; `git log` is the engineering record.
- **Single-feature / single-fix PR**: squash-merge for a clean main history.

### Delete merged branches

After a merge succeeds (PR merged, CI green on the merge commit), delete the feature branch — remote and local — as part
of the same flow, not as later cleanup:

```bash
git push origin --delete <branch>
git branch -d <branch>    # squash-merges need -D; verify first: git diff <branch-tip> main must be empty
```

Orphaned remote branches have already cost an audit finding (see the 0.9.1 doc audit); deletion is part of the release
process, not optional hygiene.

## CHANGELOG Format

Uses [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Update in the same PR as the code change. Don't forget
the comparison link at the bottom and the `[unreleased]` link update.

## Recovery

If tag push doesn't trigger workflows within ~60s, delete and re-push:

```bash
git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z
git tag -a vX.Y.Z -m "Release X.Y.Z" && git push origin vX.Y.Z
```
