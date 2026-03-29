# Claude Rules

> **This file**: Core principles, behavioral constraints, and development rules.
> The principles section is the foundation — internalize it before any work.

## Core Principles

These principles govern every change to this project. They are not
guidelines — they are hard constraints. When in doubt, the principle
wins over convenience.

### Architecture

1. **Separation of Concerns is non-negotiable.** Each module does one
   thing. `patterns/` loads and merges patterns. `sanitization/` removes
   PII. `capture/` records traffic. `validation/` checks results.
   `cli/` wires commands. No module reaches across boundaries.

1. **DRY is non-negotiable.** If the same logic appears in 2+ places,
   extract a shared helper. Duplicated pattern loading, redaction
   checks, or detection logic are architecture bugs, not tech debt.

1. **The core library has no CLI dependency.** `cli/` is a thin
   wrapper over the library. If a CLI command requires non-trivial
   logic, it belongs in the library, not the CLI module. API consumers
   (`sanitize_har_file()`, `validate_har()`) never import from `cli/`.

1. **New features are additive only.** New domain pattern, new
   heuristic detector, new PII pattern, new scanner pass — none of
   these change existing code. Add a JSON file, register it, done.
   If adding a feature requires modifying unrelated modules, the
   architecture is wrong.

1. **The core is domain-agnostic.** The sanitization engine has no
   knowledge of any particular device or application. Domain-specific
   knowledge (safe values, detectors, HTML scanner config) lives in
   domain pattern files loaded at runtime via `--patterns`. Core
   pattern files (`pii.json`, `sensitive.json`, `allowlist.json`)
   contain only universal PII rules.

1. **Extensibility via data, not code.** Adding support for a new
   product category requires a JSON file, not code changes. Heuristic
   detectors, HTML scanners, PII patterns, and safe values are all
   configured through domain pattern files. If a domain pattern
   section requires code knowledge, the abstraction is wrong.

### Specs and Documentation

7. **Specs are the authority.** Code follows specs. No silent
   deviations. If the code needs to diverge, discuss the gap first,
   update the spec, then update the code.

1. **Design decisions land in specs, not in conversation.** Every
   architectural decision made during a session must be committed to
   the relevant spec or architecture doc before the session ends.
   Conversation history is ephemeral — specs are durable.

1. **Docs and code move together.** Every change reconciles the
   affected specs (ARCHITECTURE, CAPTURE_SPEC, SANITIZATION_SPEC,
   PATTERN_SPEC, VALIDATION_SPEC). A code change without a
   corresponding spec update is incomplete.

### Code Quality

10. **No shortcuts, no deferred structure.** If a better design is
    obvious, use it now. Don't optimise for speed of first draft.
    When a module grows past its natural boundary, restructure the
    whole module — don't bolt on the new thing and leave the rest.

01. **Quality gates are not negotiable.** If mypy, ruff, or pytest
    fails, fix the code. Don't exclude files, skip checks, or weaken
    thresholds. Never bypass pre-commit hooks — fix failures, don't
    skip them. If hooks break, fix the hook setup first.

01. **Test overrides are a code smell.** If reaching coverage requires
    heavy mocking, monkeypatching, or test overrides, the code
    structure is wrong. Restructure the code (extract dependency, make
    injectable), don't paper over it with test complexity.

### Testing

13. **Table-driven tests by default.** Identify the pattern BEFORE
    writing tests. If 3+ tests share the same setup→call→assert
    structure, start with `@pytest.mark.parametrize`.

01. **Test data lives in JSON fixtures.** No inline data blobs in
    test files. Large test data (dicts, pattern lists, test case
    tables) goes in `tests/fixtures/*.json`. Test files load fixtures
    and convert to tuples for parametrize. Schema tests use fixture
    files; behavioural tests stay inline.

01. **Coverage threshold is 75%.** Defined in `pyproject.toml`. Patch
    target 80% informational (`codecov.yml`). Don't game coverage —
    if a module is hard to test, restructure it.

### Process

16. **Only the developer merges PRs and takes irreversible actions.**
    Never merge a PR, force push, delete branches, or create releases
    without explicit approval. "Ready to merge?" is not "merge it."

01. **No external actions without discussion.** Never create GitHub
    issues, PRs, pushes, label changes, or any external-facing action
    without explicit discussion first.

01. **Conventional commits.** Commitizen pre-commit hook requires the
    format: `type(scope): message` (e.g., `feat(patterns):`,
    `fix(sanitization):`, `docs:`, `chore(release):`).

## Architecture and Specifications

| Document                          | Scope                                                     |
| --------------------------------- | --------------------------------------------------------- |
| `docs/ARCHITECTURE.md`            | Design constraints, system shape, component relationships |
| `docs/specs/CAPTURE_SPEC.md`      | Playwright session, wait-for-data, workflow phases        |
| `docs/specs/SANITIZATION_SPEC.md` | HAR/HTML/heuristic engines, two-pass model, hasher        |
| `docs/specs/PATTERN_SPEC.md`      | Pattern file schemas, domain files, merge order, loader   |
| `docs/specs/VALIDATION_SPEC.md`   | PII leak detection, check functions, pre-commit hook      |
| `docs/USE_CASES.md`               | User-facing use case catalog                              |

## Project Layout

```
src/har_capture/
├── patterns/          # Pattern loading, merging, redaction checking, hashing
│   └── domains/       # Built-in domain pattern files (network_device.json)
├── sanitization/      # HAR engine, HTML engine, heuristic engine
├── capture/           # Playwright recording, wait-for-data (optional dep)
├── validation/        # PII leak detection for pre-commit and CLI
└── cli/               # Typer commands (get, sanitize, validate, patterns)
tests/
├── fixtures/          # JSON test data (one per test module)
├── test_capture/
├── test_sanitization/
├── test_patterns/
├── test_validation/
└── test_cli/
```

## Development

```bash
# Run tests (excludes integration tests requiring Playwright)
.venv/bin/python3 -m pytest tests/ -v --tb=short -m "not integration"

# Release (after merge to main)
git checkout main && git pull && python scripts/release.py X.Y.Z
```

## Release Flow

All work ships in **one PR**: code + tests + changelog + version bump.
No separate release PR. No tagging from feature branches.

### PR Checklist (before merge)

- [ ] Version bumped in **both** `pyproject.toml` and `src/har_capture/__init__.py`
- [ ] `CHANGELOG.md` has a `## [X.Y.Z] - YYYY-MM-DD` section with changes
- [ ] `CHANGELOG.md` has a `[X.Y.Z]` comparison link at the bottom
- [ ] `CHANGELOG.md` `[unreleased]` link updated to compare from `vX.Y.Z`
- [ ] Tests pass: `.venv/bin/python3 -m pytest tests/ -v --tb=short -m "not integration"`
- [ ] Pre-commit hooks pass: `.venv/bin/python3 -m pre_commit run --all-files`
- [ ] Commit message follows conventional format: `type(scope): message`

### Pipeline: PR → PyPI

```
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

### CHANGELOG Format

Uses [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Update in
the same PR as the code change. Don't forget the comparison link at the
bottom and the `[unreleased]` link update.

### Recovery

If tag push doesn't trigger workflows within ~60s, delete and re-push:

```bash
git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z
git tag -a vX.Y.Z -m "Release X.Y.Z" && git push origin vX.Y.Z
```
