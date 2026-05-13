# Code Review

Standards applied during code review and pre-merge checks. CLAUDE.md routes here; this file is the authoritative source
for code quality and testing conventions.

## Design Principles

### No shortcuts, no deferred structure

If a better design is obvious, use it now. Don't optimise for speed of first draft. When a module grows past its natural
boundary, restructure the whole module — don't bolt on the new thing and leave the rest.

The corollary is "no `# TODO: clean up later` comments." Deferred items pile up and silently expire. Either fix it now
or open an issue with a concrete description — never leave a note in the code that future-you is supposed to find.

### Quality gates are not negotiable

If `mypy`, `ruff`, or `pytest` fails, fix the code. Don't exclude files, skip checks, or weaken thresholds.

Never bypass pre-commit hooks (`--no-verify`). If a hook is broken, fix the hook setup; don't skip it.

The exact gates are listed under [Quality Gates](#quality-gates) below.

### Test overrides are a code smell

If reaching coverage requires heavy mocking, monkeypatching, or test overrides, the code structure is wrong. Restructure
the code (extract the dependency, make it injectable, move pure logic to a module-level function) — don't paper over
with test complexity.

A closure that's hard to unit-test is a signal to extract it. The extracted pure function tests cleanly with fixtures;
the closure becomes a thin wrapper.

## Test File Standards

### Table-driven by default

Identify the test pattern *before* writing tests. If 3+ tests share the same `setup → call → assert` structure, start
with `@pytest.mark.parametrize`. Don't write three near-identical functions and "consolidate later" — consolidation
later is a refactor that won't happen.

### Test data lives in JSON fixtures

No inline data blobs in test files. Large test data (dicts, pattern lists, test-case tables) goes in
`tests/fixtures/*.json`. Test files load fixtures and convert to tuples for `parametrize`.

The exceptions:

- **Schema tests** use fixture files (they describe data shapes).
- **Behavioural tests** can stay inline when the data is one or two lines and the assertion logic is the focus.

Inline data above ~5 lines is almost always a sign that the test should be table-driven with a fixture.

### Convert ad-hoc tests to table-driven during review

Table-driven tests are a *review-step* enforcement, not just a first-draft expectation. If a PR adds 3+ similar tests
inline, the reviewer expects them refactored into a parametrize block before merge.

## Quality Gates

The gates that block a merge. Every one of these is enforced in CI and re-runnable locally.

| Gate          | Command                                                                 | Threshold                                                             |
| ------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Tests         | `.venv/bin/python3 -m pytest tests/ -v --tb=short -m "not integration"` | 0 failures                                                            |
| Coverage      | included in pytest run via `pyproject.toml`                             | `fail_under = 90`                                                     |
| Lint + format | `ruff check` and `ruff format --check`                                  | 0 violations                                                          |
| Type check    | `mypy src/`                                                             | 0 errors                                                              |
| Pre-commit    | `.venv/bin/python3 -m pre_commit run --all-files`                       | all hooks pass                                                        |
| Codecov patch | reported by `codecov.yml`                                               | 80% informational (CLI entrypoints have low patch coverage by design) |

**Don't game coverage.** If a module is hard to test, restructure it. Codecov's patch target is informational because
CLI entrypoints are thin wrappers and a 100% patch target would push contributors to write hollow tests. Coverage drops
on existing code are blocked by the codecov project target (`threshold: 5%` from base).

## Source File Standards

### Comments: default to none

Only add a comment when the *why* is non-obvious: a hidden constraint, a subtle invariant, a workaround for a specific
bug, behavior that would surprise a reader.

Don't explain *what* the code does — well-named identifiers already do that. Don't reference the current task, fix, or
callers ("used by X", "added for the Y flow", "handles the case from issue #123") — those belong in the PR description
and rot as the codebase evolves.

### Keep WHY comments on refactor

The "default to no comments" rule targets *what*-noise, not *why*-context. During a rewrite, don't strip section markers
(`# Phase 1 — auth`), rationale notes, or numbered-procedure markers. Those are durable.

### Error handling at boundaries only

Don't add error handling, fallbacks, or validation for scenarios that can't happen. Trust internal code and framework
guarantees. Only validate at system boundaries (user input via CLI args, external HTTP responses, file I/O on
user-supplied paths).

### No backwards-compatibility shims for changes you fully control

When changing internal code, change it. Don't keep the old code path behind a feature flag, leave `# removed` comments
where deletions happened, or rename unused params to `_var`. If something is unused, delete it completely.
