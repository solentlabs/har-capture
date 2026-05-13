# Claude Rules

> **This file**: how Claude behaves in this repo — diagnostic disciplines, decision sequencing, verification, process
> guardrails. Architecture, code quality, testing, and release standards live in the docs linked below; this file points
> rather than restates.
>
> **Read this before any work in this repo.** Other contributors' AI tools that skim past this file produce the failure
> modes catalogued under "AI Shortcut Audit" below — every one of them has already cost us real time.

## Where Things Live

| Topic                                                                    | Authoritative doc                                                    |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Architecture, code organization, capture pipeline, sanitization pipeline | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)                       |
| Capture spec (Playwright session, wait-for-data, workflow phases)        | [`docs/specs/CAPTURE_SPEC.md`](docs/specs/CAPTURE_SPEC.md)           |
| Sanitization spec (HAR/HTML/heuristic engines, two-pass model, hasher)   | [`docs/specs/SANITIZATION_SPEC.md`](docs/specs/SANITIZATION_SPEC.md) |
| Pattern spec (schemas, domain files, merge order, loader)                | [`docs/specs/PATTERN_SPEC.md`](docs/specs/PATTERN_SPEC.md)           |
| Validation spec (PII leak detection, pre-commit hook)                    | [`docs/specs/VALIDATION_SPEC.md`](docs/specs/VALIDATION_SPEC.md)     |
| Code quality, test standards, quality gates                              | [`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md)                         |
| Release flow, version numbering, branching/merging, CHANGELOG            | [`docs/RELEASE.md`](docs/RELEASE.md)                                 |
| User-facing use cases                                                    | [`docs/USE_CASES.md`](docs/USE_CASES.md)                             |
| Architecture decision records                                            | [`docs/ARCHITECTURE_DECISIONS.md`](docs/ARCHITECTURE_DECISIONS.md)   |

## Contents

| Section                  | Covers                                                       |
| ------------------------ | ------------------------------------------------------------ |
| Core Principles          | Specs/docs authority + process guardrails — 7 numbered rules |
| Diagnosis Discipline     | Asking for data, differential test, external failure modes   |
| Decision Discipline      | Sequencing, recommendation-not-paper, no judgment shortcuts  |
| Verification Discipline  | Ground-truth checks, in-flight PR audit, commit-before-done  |
| Pre-Push Verification    | Local quality-gate run before every push                     |
| Irreversible Operations  | STOP and VERIFY for force/delete/tag/release                 |
| PR and Issue Conventions | Conventional commits, one PR per release                     |
| AI Shortcut Audit        | Encoded session failure modes                                |

## Core Principles

These principles are hard constraints. When in doubt, the principle wins over convenience.

Principles are globally numbered 1–7. They use bullet syntax with bold-prefix numbers so per-subsection groupings stay
visually distinct while numbering stays continuous (an ordered list restarts per subsection, which would break
references like "principle 7").

### Specs and Documentation

- **1. Specs are the authority.** Code follows specs. No silent deviations. If the code needs to diverge, discuss the
  gap first, update the spec, then update the code.

- **2. Design decisions land in specs, not in conversation.** Every architectural decision made during a session must be
  committed to the relevant spec or architecture doc before the session ends. Conversation history is ephemeral — specs
  are durable.

- **3. Docs and code move together.** Every change reconciles the affected specs and docs (ARCHITECTURE, CAPTURE_SPEC,
  SANITIZATION_SPEC, PATTERN_SPEC, VALIDATION_SPEC, CODE_REVIEW, RELEASE). A code change without a corresponding doc
  update is incomplete.

### Process

- **4. Only the developer merges PRs and takes irreversible actions.** Never merge a PR, force-push, delete branches on
  a remote, or create releases without explicit approval. "Ready to merge?" is not "merge it."

- **5. No external actions without discussion.** Never create GitHub issues, PRs, pushes, label changes, comments, or
  any external-facing action without explicit discussion first.

- **6. Only the developer stages files.** Never run `git add`, `git commit`, or `git stash` without an explicit
  per-action ask. Approval of the *work* is not approval of each *commit*. Show the diff and propose a commit message;
  let the developer stage.

- **7. Conventional commits.** Commitizen pre-commit hook requires `type(scope): message`. Examples: `feat(patterns):`,
  `fix(sanitization):`, `docs:`, `chore(release):`. The conventional-commit type does **not** auto-imply a version bump
  — see [`docs/RELEASE.md`](docs/RELEASE.md#version-numbering) for the binding policy.

## Diagnosis Discipline

When a runtime error surfaces (Playwright session failure, pattern false positive, sanitization regression), ask for the
data that distinguishes candidate causes before theorizing.

- **Differential test.** Every theory must answer "why now and not before?" If it can't, it's incomplete — don't commit
  to a fix built on it.
- **External failure modes are invisible to grep.** Playwright version drift, system-dep gaps, browser-revision
  mismatches, network behavior, user actions — none of those show up in codebase searches. When stuck inside the repo,
  ask: could this be coming from outside the code?
- **Pattern issues need fixture inputs, not theories.** When a false positive or miss is reported, ask for the exact HAR
  fragment or value that triggered it. Reproduce against a fixture before proposing a fix.
- **Don't propose fixes until you can name what specifically broke and why.** "Probably X" is not a fix-ready diagnosis.

## Decision Discipline

- **One thing at a time.** Surface decisions sequentially; don't dump 6-row tables of "outstanding work." Long
  synthesized lists let shortcuts slip through under decision fatigue.
- **Research returns a recommendation, not a paper.** Default to a 2–3 sentence answer with the single tradeoff that
  matters. Tables, section headers, and option matrices are opt-in — only expand when the user asks "explain why."
- **No judgment shortcuts.** Don't dismiss alternatives as "overkill," "churn," or "no payoff" without weighing real
  costs and benefits. The shortcut costs more later — a missed improvement or a re-litigated decision.
- **Don't defer obvious cosmetic fixes.** If a review surfaces a stale name, drifted docstring, or minor nit, fix it in
  the current pass. Never write "separate pass if desired" — that's deferral dressed as a suggestion.
- **No "revisit later."** When presenting design choices, offer "ratify now" or "drop entirely." Deferred items expire
  silently.

## Verification Discipline

- **Verify against ground truth, not against doc claims.** When reviewing a planning doc, status doc, or stale README,
  summarize what's actually true (check code, git, issues), not what the doc says.

- **Before opening a new PR, list open PRs targeting the same release.** Bundle into the existing one rather than
  opening a parallel PR. See [`docs/RELEASE.md`](docs/RELEASE.md#branching-and-merging).

- **Verify the premise before creating a branch.** For any task that says "remove X" or "clean up Y," `rg` for it on the
  current branch first. Zero hits means the work is already done — stop before branching.

- **Commit before recording done.** Work must be on a durable branch before journal/memory says "done," "added," or
  "implemented." Stashed or worktree-only work can be lost.

- **Verify CI install profile matches local.** A local `.venv` with extras can hide what CI actually sees. Re-check
  against CI's actual install before pushing — passing locally is not the same as passing in CI.

- **There is no such thing as a "pre-existing" issue.** Any issue that surfaces during your work is a current issue. The
  "pre- existing" framing is a way to deflect ownership and defer fixes — it has no legitimate use. This applies to test
  failures, doc drift, broken cross-references, malformed config files, stale comments, broken CI extractions, anything.
  If you find it now, it's in scope now. `scripts/release.py` BLOCKS on this framing in commit messages for a reason:
  the v0.8.1 → v0.8.3 case study where three releases shipped for what should have been one is the canonical instance.

- **Proactive diagnosis, not reactive.** The corollary to the rule above: surface every issue you find *up front* in the
  initial audit, not piecemeal as the user pushes for verification. "I found 10 cross-reference breakages and 3 doc
  drifts and 5 lint violations" stated at audit time is a complete report. "I found 1, the user pushed, I found 4 more,
  the user pushed again, I found another 8" is reactive diagnosis dressed up as thoroughness — the cost is paid in user
  trust each time.

- **Before renumbering a numbered list anywhere in the doc tree, grep for cross-references.** Code, tests, fixtures,
  scripts, and CHANGELOG entries may cite numbered rules (`CLAUDE.md principle #7`, `rule 12`). Renumbering without a
  pre-flight grep silently breaks every cite. The check:

  ```bash
  grep -rnE "CLAUDE\.md (rule|principle|#)" src/ tests/ scripts/ docs/ CHANGELOG.md README.md
  ```

  If hits > 0, fix the live references (code/tests/scripts/fixtures) to point at the authoritative doc and section
  instead of a numbered CLAUDE.md entry. Leave historical CHANGELOG entries alone — they describe state at release time.

## Pre-Push Verification

Before pushing ANY commits, run the local quality-gate mirror:

```bash
.venv/bin/python3 -m pytest tests/ -v --tb=short -m "not integration"
.venv/bin/python3 -m pre_commit run --all-files
```

Both must be green locally. Concrete gate commands and thresholds are in
[`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md#quality-gates).

## Irreversible Operations — STOP and VERIFY

When the user gives explicit constraints (e.g., "without closing the PR," "don't delete X"):

1. **Treat as HARD BLOCKERS** — not suggestions.
1. **Verify the outcome BEFORE executing** — if unsure, ask.
1. **If something goes wrong, STOP and ask** — don't try to fix it autonomously.

Operations requiring verification before running:

- Branch renames, deletions, force pushes
- PR / issue closures
- Tag deletions, tag re-pushes
- Any `git` command with `--force` or `--hard`
- Release-script invocation (`scripts/release.py`)

## PR and Issue Conventions

- **Conventional commits format** (see Core Principle 7).
- **One PR per release.** All in-flight work for the next release lands on a single PR. Check open PRs before opening a
  new branch — bundle into the existing one. Detailed policy:
  [`docs/RELEASE.md`](docs/RELEASE.md#branching-and-merging).
- **CHANGELOG entries are user-visible.** Test-only commits, internal refactors, and dev-doc changes do not get
  CHANGELOG entries unless they change observable behavior.

## AI Shortcut Audit

Failure modes encoded from real sessions on this repo. Each one caused real cost; each one is preventable by reading the
linked doc before acting.

- **Pre-1.0 versioning reflex.** A `feat:` conventional-commit prefix does NOT auto-mean minor bump. The CHANGELOG
  section header (`Added` / `Changed` / `Fixed`) is the binding signal. →
  [`docs/RELEASE.md`](docs/RELEASE.md#version-numbering)
- **Opening a new PR for the next release.** Always list open PRs targeting the same release first and bundle into the
  existing one. → [`docs/RELEASE.md`](docs/RELEASE.md#branching-and-merging)
- **CHANGELOG entries for test-only commits.** Test additions, internal refactors, and dev-only doc changes don't get
  CHANGELOG entries. The CHANGELOG describes user-visible behavior.
- **Spec-skipping.** Don't propose architectural changes, new pattern types, capture-flow changes, or
  sanitization-engine edits without first reading the relevant spec. The specs encode invariants that aren't visible
  from the code alone. → see Where Things Live above.
- **Restating instead of pointing.** When referencing an established rule, route to its authoritative doc — don't
  restate the content. Restated content drifts; today's restatement is tomorrow's stale copy.
- **Reactive diagnosis + "pre-existing" deflection.** Finding issues only when pushed to verify, then framing them as
  "pre-existing" to imply they weren't in scope. The 0.9.1 doc audit prep session catalogued ten such cases (renumbering
  breakage, coverage drift, bare URLs, malformed YAML frontmatter, broken release.yml awk extraction, anchor typos,
  stale hook version, mis-numbered rule in release.py audit, lint violations in my own new edits, orphan remote branch).
  Every one should have been in the initial audit report, not surfaced reactively. The cost was paid in user trust —
  re-earning it requires proactive surfacing next time.
