# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.2] - 2026-07-07

### Fixed

- **Serial numbers and WPS PINs split across sibling HTML elements are now redacted.** Technicolor .jst firmware
  (XB6/XB7/XB8 family) renders the label and value in separate sibling `<span>` elements with whitespace between the
  tags (`<span class="readonlyLabel">Serial Number:</span>` followed by `<span class="value">`), which the label-based
  patterns in `sanitize_html()` did not match — the tag chain permitted consecutive tags but not whitespace between
  them. All label-based tag chains now tolerate whitespace between tags: the serial inline/table and WPS PIN passes in
  the HTML engine, the `serial_number` / `wps_pin` patterns used by `check_for_pii()`, and the serial detectors in
  `validate_har()`. Redaction now preserves the intermediate markup instead of collapsing it to `label: hash`, so
  sanitized fixtures keep their DOM structure. Reported via an unredacted serial in a contributor capture
  (cable_modem_monitor #101, Technicolor CGM4981COM `hardware.jst`).

## [0.10.1] - 2026-06-18

### Fixed

- **Base64-encoded JSON response bodies are sanitized in place, not collapsed.** Devices that return data as raw
  base64-encoded JSON (e.g. Sercomm DM1000 `setup.cgi?todo=...` endpoints, often with an empty Content-Type) decode to a
  colon-bearing string, which tripped the opaque-credential guard and replaced the entire body with a single
  `AUTH_<hash>` token — destroying field names and JSON shape. `_sanitize_response_content` now runs a decode-first
  discriminator: a body that base64-decodes to a JSON object or array is sanitized value-by-value and re-encoded,
  preserving structure; only genuinely token-shaped values fall through to whole-body redaction. `base64(user:pass)`
  values in unrecognized form/query field names (e.g. `pws`) are now also redacted, mirroring the query-param fallback.

- **Post-capture "Next steps" suggestions include the required `--patterns` flag.** The `get` command's printed
  `sanitize`/`validate` follow-up commands omitted `--patterns` (required since 0.9.0), so copy-pasting them errored.
  They now echo the patterns used for the capture.

## [0.10.0] - 2026-05-30

### Added

- **Cookie origin annotation: `_client_side_cookies` in `log._har_capture`.** After sanitization, `sanitize_har` now
  writes a `_client_side_cookies` list containing the names of any cookies found in request `Cookie` headers that never
  appeared in a `Set-Cookie` response header across the entire capture. Cookie values are never written — only names. An
  empty list means all cookies were server-set. Example output: `"_client_side_cookies": ["credential"]`. This lets
  downstream tooling (e.g. cable_modem_monitor intake pipeline) detect the client-side cookie injection pattern — where
  firmware sets a credential cookie via JavaScript rather than `Set-Cookie` — without requiring contributors to provide
  DevTools data manually.

- **URL credential location annotation: `_sanitized_credentials` in `log._har_capture`.** `sanitize_har` now pre-scans
  the original entries (before sanitization replaces credentials with `AUTH_<hash>` placeholders) and writes a
  `_sanitized_credentials` list recording the entry index and location of any bare `base64(user:pass)` credential found
  in URL query params or structured `queryString` arrays. Example:
  `"_sanitized_credentials": [{"entry_index": 1, "location": "url_query_param"}]`. This allows the intake pipeline to
  identify the auth entry without pattern-matching the placeholder — the `AUTH_<hash>` format contains an underscore
  that falls outside the base64 alphabet, breaking regex-based detection in the sanitized HAR.

### Fixed

- **Server-issued session tokens preserved in `url_token` auth response bodies.** For firmware that authenticates via
  `base64(user:pass)` in the URL query string, the server responds with an opaque session token in the response body
  (not the user's credential). The previous fix redacted any response body that looked like a base64 credential,
  stripping the token and making the HAR unreplayable without manual patching. The sanitizer now checks whether the
  response body echoes the URL credential — `btoa(user)`, `btoa(password)`, or `btoa(user:pass)` — and only redacts on a
  match; opaque server tokens that happen to decode to `x:y` format are preserved. The validator's `check_content` is
  updated symmetrically: entries listed in `_sanitized_credentials` skip the bare base64 body check, since the sanitizer
  already made the preservation decision.

- **`is_base64_credential` now applied to response body content.** The check was called in four places inside request
  URL and query-param sanitization but never in `_sanitize_response_content`. A server that echoes a bare
  `base64(user:pass)` token back in its response body (e.g. a router auth-status page returning `YWRtaW46cGFzcw==`)
  passed through unsanitized. The guard now runs before the mime-type router so the body is redacted regardless of
  `text/plain`, `text/html`, or `application/json` content type. The matching gap in `check_content`
  (`validation/secrets.py`) is also closed: the validator now flags unsanitized HARs containing a bare base64 credential
  as the entire response body, with `severity="error"`.

## [0.9.1] - 2026-05-13

### Changed

- **`Authorization` header redaction now preserves the auth scheme.** Previously the entire header value was collapsed
  to a single opaque tag (`Authorization: AUTH_xxxxxxxx`), stripping the RFC 7235 scheme token (`Basic`, `Bearer`,
  `Digest`, `NTLM`, `Negotiate`, `OAuth`). Downstream consumers had no way to classify the auth mechanism from
  request-side evidence — they had to wait for a `401 + WWW-Authenticate` exchange that often never appeared (e.g., when
  a browser sends cached credentials from request 1). The redactor now recognizes the closed set of RFC-registered
  schemes, preserves the scheme token, and tag-redacts only the credential after the first whitespace
  (`Authorization: Bearer AUTH_xxxxxxxx`). Unknown schemes (or values with no whitespace) fall through to full redaction
  so non-standard leading tokens cannot escape. Concretely this restores the ability of intake pipelines like
  `cable_modem_monitor`'s `analyze_har` to determine the auth strategy from a single authenticated request. Implemented
  as a third header-classification bucket (`headers.scheme_redact` in `sensitive.json`) alongside `full_redact` and
  `cookie_redact`; the bucket is extensible via custom patterns the same way the other two are.

- **Doc-system restructure: CLAUDE.md is now a router, not the source of truth.** Architecture, code-quality, and
  testing principles previously restated in CLAUDE.md were moved to their authoritative homes: `docs/ARCHITECTURE.md`
  gains a Code Organization section (SoC, DRY, no-CLI-dep, additive-only), `docs/CODE_REVIEW.md` is new and houses
  code-quality and test-file standards plus the concrete Quality Gates table, and `docs/RELEASE.md` gains Version
  Numbering (pre-1.0 bump policy + CHANGELOG-section tiebreaker) and Branching and Merging (one PR per release,
  consolidation rules, cherry-pick vs rebase, merge-vs-squash) sections. CLAUDE.md is restructured around
  Claude-behavior content: a Where Things Live routing table, slimmed Core Principles (specs/process only, now 7
  numbered rules), Diagnosis / Decision / Verification / Pre-Push Verification / Irreversible-Operations discipline
  sections, and a new AI Shortcut Audit section catalogueing encoded failure modes from real sessions (pre-1.0
  versioning reflex, opening parallel PRs for the same release, CHANGELOG-for-tests, spec-skipping,
  restating-instead-of-pointing). Motivation: AI-assisted contributors were following stale CLAUDE.md restatements that
  had drifted from authoritative docs (concrete example: CLAUDE.md stated 75% coverage threshold while `pyproject.toml`
  has been at `fail_under = 90` since v0.8.1). New rationale recorded in
  [ADR-11](docs/ARCHITECTURE_DECISIONS.md#adr-11-claudemd-is-a-router-not-a-source-of-truth).

- **CLAUDE.md principle renumbering.** The router restructure renumbered Core Principles from 19 entries (Architecture
  1-7, Specs/Docs 8-10, Code Quality 11-13, Testing 14-16, Process 17-19) down to 7 (Specs/Docs 1-3, Process 4-7).
  Architecture, code-quality, and testing principles moved to their authoritative docs and are no longer numbered in
  CLAUDE.md. Live code/test/script comments that referenced numbered principles were updated to point at the new
  authoritative doc and section instead. Historical CHANGELOG entries (v0.8.x, v0.9.0) retain their original
  principle/rule numbers — they describe state at release time and modifying them would be revisionist.

- **Markdownlint configuration + pre-commit hook added; full doc tree reflowed to 120-char lines.** New
  `.markdownlint.jsonc` / `.markdownlint.json` / `.markdownlint-cli2.jsonc` configs and a `markdownlint-cli2` pre-commit
  hook pinned to `v0.22.1`. The mdformat pre-commit hook now passes `--wrap 120` so prose auto-wraps to 120 chars on
  every commit, and `markdownlint` enforces `MD013` (line-length) at the same 120-char limit. Tables, code blocks, and
  headings remain enforced; tables and code blocks are exempt from MD013 because their content (commands, URLs, regex
  examples) loses meaning if line-wrapped. Every other rule customization considered during this audit was tested
  against the actual doc tree and dropped when it didn't fire — no preemptive disables, no cargo-culted disable
  justifications. The reflow touched 15 markdown files (~2700 diff lines, mechanical). The first lint run surfaced and
  fixed three bare-URL violations (`docs/TAG-PROTECTION.md` line 19, `CONTRIBUTING.md` lines 219 and 227), two
  trailing-colon headings (`docs/TAG-PROTECTION.md` lines 42 and 65), and a missing-H1 in
  `.github/PULL_REQUEST_TEMPLATE.md` — gaps no prior gate had caught. The detect-secrets pragma in
  `docs/specs/VALIDATION_SPEC.md` got separated from its target line during the reflow; the example was rewritten to use
  `"..."` placeholder syntax so it no longer triggers the keyword detector.

- **GitHub issue templates restored, mdformat frontmatter plugin added.** Both `.github/ISSUE_TEMPLATE/bug_report.md`
  and `feature_request.md` had broken YAML frontmatter: the `---` delimiters were collapsed to horizontal-rule
  underscores and the `name:`/`about:`/`labels:` metadata was mashed into `##` headings, so the files did not function
  as GitHub issue templates (no auto-populated title, labels, or assignees on issue creation). The root cause is that
  mdformat treats `---` as horizontal-rule markdown and rewrites it; without the `mdformat-frontmatter` plugin, every
  commit re-damages the templates. Both templates rewritten with correct frontmatter and the plugin added to the
  mdformat pre-commit hook's `additional_dependencies` so the templates stay intact.

- **`release.yml` CHANGELOG-extraction regex fixed.** The "Extract release notes" step used
  `awk '/^## \[VERSION\]/,/^## \[/' CHANGELOG.md` — a single-regex range where the start pattern also matches the end
  pattern, so the range was a single line (the version header itself) and the extracted release notes were empty for
  every release. GitHub Releases for v0.9.0 and prior shipped with installation-boilerplate-only bodies, missing every
  actual `### Changed` / `### Fixed` entry. Fix uses a flag-toggle awk pattern that begins after the version header.
  Verified against the 0.9.1 CHANGELOG content before commit.

- **`scripts/release.py` rule-3 reference corrected.** Print statement at line 514 said
  `CLAUDE.md rule 3: DRY non-negotiable`, but DRY was rule 2 in the old CLAUDE.md numbering — the reference was wrong
  since the audit gate was introduced. As part of the broader cross-reference migration in this release (numbered
  principles → authoritative-doc-and-section pointers), the line now points to
  `docs/ARCHITECTURE.md § Code Organization`.

## [0.9.0] - 2026-05-11

### Changed (BREAKING) in 0.9.0

- **`--patterns` is now required on `get`, `sanitize`, and `validate`.** Running any of these subcommands without
  `--patterns` prints a listing of available choices (`base`, built-in domains like `network-device`, or a custom JSON
  path) and exits with code 2. The previous behavior — silently using only universal PII rules when `--patterns` was
  omitted — was the structural cause behind issues #47 and #49 (contributors didn't know to load the network-device
  domain, so device-specific PII shipped unredacted in HARs submitted to `cable_modem_monitor`). Making the choice
  explicit turns the privacy promise from aspirational into structural. `--patterns base` is reserved as an explicit
  opt-in to core-universal-PII-only for non-device captures. `validate`'s `--patterns` shape changed from a single
  `Path` to a repeatable list to match `get` and `sanitize`. The library API (`sanitize_har_file()`, `sanitize_har()`,
  `validate_har()`) is unchanged — the core remains domain-agnostic and library callers continue to pass
  `custom_patterns=` directly.

  **Migration:**

  ```bash
  # Before
  har-capture get https://router.local
  har-capture sanitize device.har
  har-capture validate device.har

  # After
  har-capture get https://router.local --patterns network-device
  har-capture sanitize device.har --patterns network-device
  har-capture validate device.har --patterns network-device
  # Or for non-device captures:
  har-capture sanitize webapp.har --patterns base
  ```

  See `har-capture patterns` for the full list of choices.

### Fixed in 0.9.0

- **Chromium re-install prompt on every invocation (issue #50)** — `check_browser_installed` previously resolved
  Playwright's chromium binary at a hardcoded Linux-only relative path (`chrome-linux64/chrome`). On Windows and macOS
  that path never matched the actual binary layout (`chrome-win64/chrome.exe`,
  `chrome-mac/Chromium.app/Contents/MacOS/Chromium`, etc.), and the function returned False without consulting the
  dry-run fallback — re-prompting the user to "install" a browser that was already installed. The check now resolves the
  platform-agnostic `<browser>-<revision>/` install directory and confirms it exists and is non-empty. Per-platform
  binary-layout drift between Playwright versions can no longer break the detection. Helper renamed
  `_get_browser_executable` → `_get_browser_install_dir`; the per-platform `_BROWSER_EXECUTABLES` mapping is gone. Tests
  in `test_capture/test_deps.py` updated; coverage of the empty-dir-falls-through-to-dry-run branch added.

### Added in 0.9.0

- **Interactive JavaScript dialogs now surface in headed captures (closes issue #46)** — For interactive browser
  sessions (`headless=False`, `timeout=None`), native `alert` / `confirm` / `prompt` dialogs are allowed to appear in
  the Playwright window instead of being silently auto-dismissed. The resulting HAR records `_solentlabs.dialogs`
  entries with dialog type, message, default value, opened-at timestamp, the user's action (`accept` or `dismiss`), and
  `resolved_by="browser_ui"`. Closes the cable-modem capture-failure mode where Reboot / Reset / Apply buttons (which
  fire `window.confirm()`) were silently dismissed by Playwright and the resulting API call never reached the HAR.
  Implementation uses Playwright's `page.expose_function` as the JS→Python bridge (no polling, no deadlock surface).
  Headed-only by design; headless or timed captures keep Playwright's default auto-dismiss to avoid hanging unattended
  runs.
- **Heuristic detectors for default-device PII (issues #47, #49)** — `network_device.json` now ships a `serial_number`
  detector (Netgear cable-modem format `[0-9][A-Z]{2}[0-9]{4}[A-Z0-9]{6}` plus a broader uppercase-alphanumeric
  backstop) and an extended `wifi_ssid` detector that recognises common default-SSID prefixes (SPSETUP, MOTO, ATTwifi,
  XFINITY, HOMEHUB). Detector order was changed so keyword-based `device_name` runs before shape-based `wifi_ssid`,
  preventing `NETGEAR-C7000` from being miscategorized. New regression test file
  `tests/test_sanitization/test_pii_regressions.py` keys cases on issue numbers so future reports add a fixture row
  rather than a new test.
- **JSON-escape-trap warning at pattern load (issue #51)** — When a custom `--patterns` JSON file contains `\b`
  (intended as a regex word-boundary) instead of `\\b`, JSON's string-escape rules collapse it to ASCII backspace `\x08`
  before the regex compiler sees it. The pattern then compiles silently and matches nothing — a silent PII leak. The
  loader now scans regex strings for `\x08` and `\x0c` at load time and logs a warning identifying the offending key
  path and the likely intended escape. Same hazard, same warning, for `\f` (form-feed). Doesn't reject the pattern — the
  user might genuinely want a backspace match — just makes the silent case loud. Documented in `CUSTOM_PATTERNS.md` with
  a worked example. Two regression tests in `test_patterns/test_loader.py` cover the warn-on-trap and
  no-warn-on-correct-escape paths.
- **WPS-PIN labeled-regex coverage (completes issue #47)** — A new `wps_pin` pattern in `pii.json` plus a dedicated
  scanner pass in `html.py` (Pass 2d) redact 8-digit values whose label is `WPS PIN`, `PIN Code`, `Pairing PIN`, or
  `Default PIN`. The label is what makes 100%-confidence deterministic redaction achievable per CLAUDE.md principle #7:
  pure-digit values can't be flagged heuristically (the universal `^\d+$` safe pattern would have to be relaxed,
  drowning the review UI in counter noise). Format is `PIN_<hash>`. Five regex-layer regression cases added to
  `test_pii_regressions.py`.
- **`docs/RELEASE.md`** — Release flow extracted from `CLAUDE.md` so the entry-point file is dominated by principles
  rather than reference material. CLAUDE.md drops from 218 → 162 lines; principles section goes from ~52% to ~72% of the
  file.

### Changed in 0.9.0

- **`CLAUDE.md` Architecture principle #7: confidence boundary** — Surfaces the regex-vs-heuristic-layer contract at the
  entry point. The principle ("regex layer auto-redacts at 100% confidence, heuristic layer flags for review and can
  tolerate FPs, patterns that cannot guarantee zero FPs belong in `heuristics.detectors`") has existed in
  SANITIZATION_SPEC invariant #11 and ARCHITECTURE's "Confidence boundary" paragraph for weeks. CLAUDE.md now makes it
  discoverable without depth-first reading.
- **CI install profile is a single source of truth** — `scripts/install-ci-deps.sh` is now the one place that defines
  what gets installed for CI parity. Both `scripts/ci-local.sh` (the matrix-parity pre-push hook) and the two jobs in
  `.github/workflows/ci.yml` invoke it instead of hand-maintaining duplicate `pip install` lines. This closes the v0.8.1
  push-regression mode where `ci-local.sh` claimed to "mirror CI" while actually running a different install profile,
  plus the duplication-drift hazard introduced when `ci-local.sh` was first rewritten.
- **`scripts/release.py` waits for in-flight CI** — the CI verification step previously failed immediately if any check
  run was still `in_progress`, forcing a manual retry. It now polls every 20 s for up to 10 min with progress feedback
  before failing, eliminating the stale-read papercut that hit twice during v0.8.1 / v0.8.2.
- **Release-discipline audit gates added to `release.py`** — three reinforcing checks driven by the v0.8.1 → v0.8.3 case
  study, where three releases shipped for what should have been one because Claude made decisions at "should I push?"
  that violated rules just written down (the AI knowing-not-applying flaw). (A) `scan_for_anti_patterns` greps recent
  git log for known anti-pattern signatures (`pre-existing` framing, `--no-verify` / `--no-cov` bypass, deferral words
  like *papercut* / *flake* / *deferred*); BLOCKER findings abort the release unless `--acknowledged "<reason>"` is
  supplied. (B) A diff-grounded checklist prints on every invocation (including `--dry-run`) — five questions tied to
  today's failure modes, each rubber-stampable in isolation but harder to ignore when bundled with commit/file context.
  (E) The unfakeable component: a per-release sign-off phrase (`RELEASE OK X.Y.Z`) the developer must type exactly
  before tag-push proceeds; no `--yes` flag exists because the bypass defeats the purpose. The audit catches today's
  known anti-patterns and produces a stdout artifact for review; it does not pretend to catch failure modes that haven't
  been observed yet.

## [0.8.2] - 2026-05-03

### Fixed in 0.8.2

- **Test-fixture timing flake (`stays_pending` / `never_quiet`)** — `tests/fixtures/test_browser.json` had
  `timeout_s: 0.05` for the two timing-loop test cases that assert `evaluate.call_count >= 2`. The 50ms budget passed in
  CI's clean Linux container but flaked under local CPU pressure (e.g., when `release.py` runs the full 1970-test suite
  back-to-back), failing with `assert 1 >= 2` because the loop only iterated once. Surfaced — and shipped through —
  during the v0.8.1 release; framed as "pre-existing" at the time, which is exactly the deferred-fix pattern v0.8.1's
  own changelog called out for the per-module coverage rot. Bumping to `timeout_s: 0.5` gives 10× headroom; verified
  across three concurrent stress runs.

## [0.8.1] - 2026-05-03

### Fixed in 0.8.1

- **Popup / `window.open` traffic now captured** — Surfaced by CMM #146 against the Arris S33 reboot button: clicking
  reboot opens a confirmation popup whose request stream is the actual reboot command, but har-capture's recorder did
  not subscribe to `context.on("page")`, so the popup's response bodies could be evicted from Chromium's buffer before
  HAR flush, and consumers had no signal that a popup happened. Subscribing to the context-level new-page event (a)
  attaches the same eager-body-capture handler the main page has, closing the response-body eviction window for popup
  traffic, and (b) appends a record to `_solentlabs.popups` (`url`, `opened_at`) so consumers can see *that* a popup
  occurred even when its entries are interleaved with the main page's. Capture-everything: silent popups poison
  downstream analysis. Adds `BrowserSessionResult.popups: list[dict]`. Two integration-test fixtures verify the popup
  URL lands in the HAR entries and the `_solentlabs.popups` list is populated.

### Changed in 0.8.1

- **CLI testability + per-module coverage floors** — Internal restructure of the CLI layer; no user-visible behavior
  change. The project-wide 75% coverage gate had averaged high-coverage core modules against decayed CLI modules
  (`cli/patterns.py` 7%, `cli/capture.py` 38%, `cli/interactive.py` 48%) and silently hidden the rot. v0.8.1 lifts every
  `cli/*` module above 90% and adds `scripts/check_coverage_floors.py`, run from CI, to make per-module decay a build
  failure. Two production-code shape changes earned their place under CLAUDE.md rule 12 ("test overrides are a code
  smell — restructure code, don't paper over with mocks"): (1) `_stdin_is_tty()` helper extracted in `cli/sanitize.py`
  because click's `CliRunner` swaps `sys.stdin` on entry and patching the OS-level `isatty` did not stick — the helper
  gives tests a single stable patch point that all three call sites share; (2) `_resolve_custom_patterns()` extracted
  from the 230-line `capture()` orchestration so the `--patterns` resolution branches are unit-testable without driving
  the full Playwright flow. Defensive exception handlers in `cli/sanitize.py` (lines 251–264, FileNotFoundError /
  PermissionError / PatternLoadError / OSError) are unreachable from the CLI surface — typer rejects bad paths at parse
  time and the pattern loader is lenient — so they remain as a library-consumer safety net rather than chasing
  theatrical coverage. Project total: 86% → 94%. Global `--cov-fail-under` raised from 75 to 90.

## [0.8.0] - 2026-05-01

### Changed in 0.8.0

- **Bare hostnames/IPs now auto-detect HTTP vs HTTPS** — `har-capture <target>` and `check_device_connectivity(target)`
  accept a bare hostname/IP again. When no scheme is provided, a stdlib-only TCP+TLS probe of `:80` and `:443` runs
  first; HTTPS is preferred when its handshake completes. Reverses the 0.6.0 hard rejection of bare hostnames, which
  traded ambiguity for a contributor trap: guessing `http://` on an HTTPS-only device misses the auth challenge that
  lives on `:443`. Explicit schemes still bypass detection entirely — the user has chosen.

### Added in 0.8.0

- **`detect_protocol()` + `ProtocolDetectionResult`** — New stdlib-only protocol detection in
  `har_capture.capture.connectivity`. Probes TCP `:80` and `:443`; if `:443` accepts a TCP connection *and* completes a
  TLS handshake, HTTPS wins. The handshake uses a `SECLEVEL=0` cipher context so it succeeds against legacy modems (TLS
  1.0/1.1, 3DES/RC4) — without that tolerance, we'd false-fail HTTPS and silently capture an HTTP redirect stub instead
  of the auth challenge, the inverse of the CM1200 trap this whole feature exists to close. har-capture does not
  classify or surface the negotiated TLS version (Chromium runs its own TLS stack and har-capture cannot act on the
  classification); the version is logged for diagnostics only. Helpers `_strip_protocol`, `_split_host_port`,
  `_tcp_probe`, `_tls_handshake` are exposed for direct testing. Adapted from `cable_modem_monitor_core/connectivity.py`
  (both projects owned by solentlabs); duplicated rather than shared so har-capture's runtime stays stdlib-only and CMM
  Core does not pull playwright via a shared package. `getaddrinfo` defaults to IPv4 (avoids dual-stack false-fails on
  consumer LAN devices) but bracketed IPv6 literals (`[::1]:8443`) auto-select `AF_INET6` so v6-only targets are not
  silently dropped. Explicit `:port` overrides and case-insensitive scheme prefixes (`HTTPS://...`) are supported.
- **Table-driven `DETECT_PROTOCOL_CASES` test bench** — 12 rows covering HTTP-only, HTTPS-handshake-completes,
  handshake-fails-falls-back-to-HTTP, both-closed, explicit-scheme-skip-half, custom-port, and bracketed IPv6 (HTTP-only
  and HTTPS-with-port). Adding a row adds a test.

### Changed (internal cleanup) in 0.8.0

- **`_parse_target` is now a thin wrapper over `_strip_protocol`** — Eliminates the parallel-helper duplication left
  over from the v0.8.0 port. Public callers (`browser.py`, `workflow.py`) keep the `(host, scheme)` tuple shape; new
  code in `connectivity.py` uses `_strip_protocol` directly. Drops the unused `urllib.parse.urlparse` import.
  Non-http/https schemes (`ftp://`, etc.) are now returned with `scheme=None` since har-capture cannot capture them
  anyway — previously `_parse_target("ftp://x")` returned `("x", "ftp")` and the connectivity check immediately fell
  through to auto-detect, producing the same outcome via a different code path.

## [0.7.1] - 2026-04-24

### Fixed in 0.7.1

- **`custom_patterns` now propagates through `sanitize_entry` to all detection sites** — In 0.7.0 the
  `ContextVar`-scoped override was entered only by `sanitize_post_data` and `sanitize_html`, so three detection sites in
  `_sanitize_request` / `_sanitize_response` that run before either of those — header-value matching
  (`sanitize_header_value`), structured `queryString` params, and URL query params (`_sanitize_url_query_params`) —
  silently ignored `custom_patterns` when callers used the top-level entry points (`sanitize_entry`, `sanitize_har`,
  `sanitize_har_file`). **Security-adjacent**: consumers passing
  `custom_patterns={"headers": {"full_redact": ["x-modem-auth"]}}` to `sanitize_har_file` were getting unredacted auth
  headers in their "sanitized" HAR. Fixed by entering both scopes at `sanitize_entry`, so every detection site within an
  entry sees the same extension set. Adds a parallel `_HeaderSets` dataclass + `_HEADER_SETS_CTX` ContextVar +
  `_header_sets_scope` / `_resolve_header_sets` resolver + cache so `sanitize_header_value` picks up custom
  `headers.full_redact` / `headers.cookie_redact` entries the same way field detection picks up custom
  `fields.auto_redact_patterns`. Module-global state still never mutated.

## [0.7.0] - 2026-04-24

### Added in 0.7.0

- **`include_patterns` in domain pattern files** — Domain JSON files (e.g. `network_device.json`) can declare an
  `include_patterns` list to filter the merged `pii.patterns` set down to only the entries that domain needs. Supports
  exact pattern names (`"mac_address"`) and glob wildcards (`"credit_card_*"`). Prevents false positives such as the
  credit-card regex triggering on cable-modem duration floats. The built-in `network_device.json` ships with an
  `include_patterns` list. See `docs/specs/PATTERN_SPEC.md` for the schema and merge order.
- **`sanitize_post_data(..., custom_patterns=...)` now extends field detection** — The `custom_patterns` kwarg (file
  path or dict matching the `load_sensitive_patterns` schema, e.g. `{"fields": {"auto_redact_patterns": ["pws"]}}`)
  additively extends the auto-redact and flag regex sets for the call across form params,
  `application/x-www-form-urlencoded` bodies, JSON bodies, and XML bodies. Previously the kwarg was accepted but
  field-name detection always used the module-global patterns. The override is plumbed through a `ContextVar`-scoped
  resolver, so it is thread- and asyncio-safe by construction and does not mutate module state. Compiled regex pairs are
  cached per canonical key so repeated calls with the same extension skip the compile. Enables downstream consumers
  (e.g., Cable Modem Monitor) to redact device-specific credential field names without modifying the universal
  `sensitive.json`.

### Fixed in 0.7.0

- **`sanitize_html(..., custom_patterns=...)` now reaches the inline-script field matcher** — The `custom_patterns`
  kwarg previously loaded custom PII and sensitive patterns but the inline `localStorage.setItem` /
  `sessionStorage.setItem` scanner still consulted the module-global field regex, so custom field-name extensions
  silently failed. The HTML body now runs inside the same `ContextVar`-scoped override used by `sanitize_post_data`, so
  calls like `sanitize_html(html, custom_patterns={"fields": {"auto_redact_patterns": ["pws"]}})` correctly redact
  values associated with the extended field names.
- **`load_sensitive_patterns` dict merge for `auto_redact_patterns` / `flag_patterns`** — Passing a custom-patterns dict
  of the current schema (`{"fields": {"auto_redact_patterns": [...]}}`) previously had no effect: only the legacy
  `fields.patterns` key was merged, and the pattern compiler ignored that key when `auto_redact_patterns` was present.
  The merge now extends `auto_redact_patterns`, `flag_patterns`, and the legacy `patterns` list. File-path
  custom-pattern consumers that relied on the silent no-op will start seeing their extensions apply.

## [0.6.1] - 2026-04-08

### Fixed in 0.6.1

- **Missing response body on initial page load** — Playwright's HAR recorder fetches bodies lazily at `context.close()`
  via CDP `Network.getResponseBody`. If a navigation (e.g., form POST) evicts the response from Chrome's buffer before
  the flush, the body is lost — headers and sizes are correct but `content.text` is absent. Added eager body capture via
  `page.on("response")` for text content types and a post-capture `_patch_missing_bodies()` step that fills missing
  bodies from the cache before sanitization.
- **Serial number false positives** — Reduced false positive serial number detections in sanitization. Improved JS
  variable name detection and pipe-delimited pattern testability.

### Removed in 0.6.1

- **No-op route handler** — Removed `context.route("**/*", lambda route: route.continue_())` which enabled the CDP Fetch
  domain unnecessarily, potentially interfering with HAR body capture.

## [0.6.0] - 2026-04-06

### Changed in 0.6.0

- **Decomposed `capture_device_har()`** — The 460-line god function is now a ~60-line orchestrator that delegates to
  four independently testable units: `_resolve_capture_paths()` (pure filesystem), `_run_browser_session()` (Playwright
  lifecycle), `_inject_har_metadata()` (HAR enrichment), `_run_post_capture_pipeline()` (sanitize/compress/cleanup).
  Eliminates `nonlocal` data shuttling via new `BrowserSessionResult` dataclass. Public API signature unchanged.
- **Explicit scheme required** — `har-capture` now requires `http://` or `https://` in the target URL (e.g.,
  `har-capture http://192.168.1.1`). Bare hostnames/IPs are rejected with a helpful error message. This eliminates
  ambiguity and prevents duplicate connectivity probes.
- **Connectivity module hardened** — Extracted `_urlopen_with_ssl()` shared helper, eliminating 3 copies of the urllib +
  SSL context pattern across `check_device_connectivity`, `check_basic_auth`, and `check_session_contamination`.

### Added in 0.6.0

- **Session contamination check** — New `check_session_contamination()` detects live sessions before capture by
  inspecting the unauthenticated response for login-page indicators. Prevents captures that skip the auth flow because
  the device already has a session. Added as Phase 3 in the workflow.
- **Architecture Decisions document** — ADR-1 through ADR-5 covering minimal pre-flight, interactive mode, probe opt-in,
  explicit scheme, and session contamination guard.
- **`CapturePathInfo` dataclass** — Encapsulates resolved output path, sanitized path, temp file path, hostname, and
  target URL.
- **`BrowserSessionResult` dataclass** — Encapsulates all browser-captured state (cookies, localStorage, sessionStorage,
  pre-capture cookie audit).
- **20+ new unit tests** — Tests for extracted functions use zero `@patch` decorators and real temp files. browser.py
  coverage 76% → 85%.

### Fixed in 0.6.0

- **Orphaned temp file on connectivity failure** — `_resolve_capture_paths()` creates the temp file before the
  connectivity check. If connectivity fails, the temp file is now cleaned up before the early return.

## [0.5.1] - 2026-03-30

### Fixed in 0.5.1

- **POST request deduplication** — `filter_and_compress_har()` used `(method, url)` as the dedup key, silently dropping
  POST requests to the same URL with different bodies. Devices that use a single POST endpoint differentiated only by
  body parameters (e.g., `param=1` vs `param=2`) lost all but the first request. The dedup key for POST/PUT/PATCH now
  includes a SHA-256 hash of the request body, preserving distinct requests while still deduplicating identical retries.

## [0.5.0] - 2026-03-29

### Added in 0.5.0

- **Default command** — `har-capture <URL>` now works without typing `get` (e.g., `har-capture 192.168.1.1`). The `get`
  subcommand still works as an explicit alias.
- **Domain-driven pattern extensibility** — heuristic detectors (`CompiledDetector`), safe value patterns, and
  pipe-delimited variable matching are now data-driven via domain pattern files loaded with `--patterns`. See
  [Pattern Spec](docs/specs/PATTERN_SPEC.md).
- **Wait-for-data SPA capture** — JavaScript init script monkey-patches `XMLHttpRequest.send` and `window.fetch` to
  track in-flight requests. Polls for 2 seconds of network quiescence (vs Playwright's 500ms `networkidle`).
  `framenavigated` listener ensures async data completes before page transitions.
- **Test fixture extraction** — large test data moved from inline to `tests/fixtures/*.json`

### Changed in 0.5.0

- **BREAKING**: Interactive review is now always enabled and cannot be disabled. The `--no-interactive` flag has been
  removed from both `get` and `sanitize` commands. In non-TTY environments (CI/CD), flagged values are written to a
  `.review.json` report file instead.
- **BREAKING**: `capture_device_har()` and `run_capture_phase()` now default to `interactive=True` (was `False`). API
  consumers can still pass `interactive=False` explicitly.
- Documentation suite rewritten — architecture doc, 4 specs, use cases, CLI reference all verified against
  implementation (76 findings resolved)

### Fixed in 0.5.0

- 12 HIGH-severity documentation accuracy issues: wrong function signatures, wrong phase ordering, fabricated CLI flags
  (`--timeout`, `--headless`), fabricated pre-commit hook, wrong scanner pass numbering, unimplemented features
  documented as real (`_extends`, `html` domain section)

## [0.4.5] - 2026-03-09

### Fixed in 0.4.5

- **Base64 credential leak in URL query strings** — Sanitizer and validator now detect base64-encoded `user:pass` tokens
  in URL query parameters (both bare tokens like `?YWRtaW46cGFzcw==` and param values like `?token=YWRtaW46cGFzcw==`).
  Handles `parse_qsl` stripping base64 `=` padding by checking raw query segments.
- **Cookie attribute metadata in headers** — Cookie/Set-Cookie headers containing serialized attribute metadata (e.g.,
  `HttpOnly: true, Secure: true`) are now properly redacted instead of passing through unchanged. Also handles cookie
  headers with no `name=value` pairs.
- **Serial number in HTML table cells** — Serial numbers in adjacent `<td>` cells (e.g.,
  `<td>Serial Number</td><td>17V541334700308</td>`) are now detected and redacted by both the sanitizer and validator.
- **Inline `setItem()` web storage scanning** — HTML response bodies containing `localStorage.setItem()` /
  `sessionStorage.setItem()` calls now have their values scanned. Keys matching sensitive field patterns (e.g.,
  `PrivateKey`, `csrf_token`, `api_key`) trigger auto-redaction; remaining values are checked by PII patterns and
  heuristic analysis.
- **Serial numbers in pipe-delimited strings** — Serial numbers with `SN-` / `S/N-` prefixes in `tagValueList` and
  similar pipe-delimited JavaScript variables are now auto-redacted, consistent with serial detection in other contexts.

## [0.4.4] - 2026-03-05

### Changed in 0.4.4

- **CI workflow_dispatch** — Added `workflow_dispatch` trigger to CI workflow for manual recovery when push events are
  missed

### Fixed in 0.4.4

- **mypy no-any-return** — Fixed `apply_user_redactions()` returning `Any` from `json.loads()` instead of typed
  `dict[str, Any]`

### Removed in 0.4.4

- **release.py skip flags** — Removed `--skip-tests` and `--skip-quality` flags from `release.py` to prevent bypassing
  quality gates

## [0.4.3] - 2026-03-05

### Added in 0.4.3

- **Sanitization metadata in HAR** — Every sanitized HAR now embeds a `log._har_capture.sanitization` section recording
  tool version, timestamp, salt mode, heuristic mode, and redaction counts. Does not leak the salt value.
- **Web Storage Snapshot** — After page settles, captures localStorage (via `context.storage_state()`) and
  sessionStorage (via `page.evaluate()`) per origin. Stored in HAR as `log._har_capture.local_storage` and
  `log._har_capture.session_storage` with values sanitized using `STORAGE_` prefix. Catches auth-critical data that
  lives only in web storage (e.g., HNAP PrivateKey in localStorage, SJCL encryption keys in sessionStorage).

### Fixed in 0.4.3

- **`_add_capture_metadata` clobbering** — `_add_capture_metadata()` now merges with existing `_har_capture` metadata
  instead of overwriting it. Previously, `browser_cookies` injected before compression were silently lost.
- **Allowlist missing hash prefixes** — Added `STORAGE_`, `CRED_`, `SENSITIVE_` to `allowlist.json` hash prefixes,
  preventing double-redaction on re-sanitization
- **ci-local.sh bare pytest** — Integration test step now uses `"$PYTHON" -m pytest` consistently

### Changed in 0.4.3

- **Shared SSL context** — Extracted duplicate SSL context creation from `connectivity.py` to use shared
  `make_ssl_context()` from `probes.py`
- **CLI code deduplication** — Extracted `apply_reviewed_redactions()` into `cli/interactive.py`, eliminating ~55 lines
  of identical logic between `capture.py` and `sanitize.py`
- **Debug logging on JSON parse failure** — `_sanitize_json_text()` now logs a debug message when encountering non-JSON
  text instead of silently returning
- **Pre-compiled regex in secrets validation** — `check_post_data()` and `check_json_fields()` now use pre-compiled
  patterns via `_compile_sensitive_fields()` for better performance
- **Removed unused constant** — Deleted `_SSID_NAME_MAX_LENGTH` from `heuristics.py` (never referenced)
- **Module-level import** — Moved `RedactionCollector` from per-call lazy import in `sanitize_html()` to module-level
  `else` branch of `TYPE_CHECKING` block
- **Thread-safety docstring** — `RedactionCollector` now documents that it is not thread-safe
- **IPv6 docstring** — `_parse_target()` now documents IPv6 address support

## [0.4.2] - 2026-03-05

### Fixed in 0.4.2

- **Probe 200-Path Cookies** - `probe_auth_challenge()` now captures `Set-Cookie` and `WWW-Authenticate` headers on 200
  responses (previously only extracted on 401/error paths)

### Added in 0.4.2

- **Browser Cookie Snapshot** - After Playwright navigates and page settles, `context.cookies()` captures all browser
  cookies (including JS-set ones like XSRF_TOKEN) with full properties (domain, path, expires, httpOnly, secure,
  sameSite). Stored in HAR as `log._har_capture.browser_cookies` with values sanitized.

## [0.4.1] - 2026-03-04

### Fixed in 0.4.1

- **HTTPS Auth Probe** - `probe_auth_challenge()` passed `context=` kwarg to `OpenerDirector.open()`, which only
  `urlopen()` accepts. Every HTTPS target silently failed. Fixed by installing the SSL context via `HTTPSHandler` in
  `build_opener()`.
- **PII Test Server Password** - Changed default password from `12345` to `pw` to match documented usage.

### Added in 0.4.1

- **HTTPS Probe Integration Tests** - Real local TLS server tests using `trustme` library, covering auth challenge,
  cookie capture, body preview, redirect suppression, and HEAD support over HTTPS.
- **README Screenshots** - Added "See It In Action" section with sanitization report, flagged values table, and
  interactive redact picker screenshots.

## [0.4.0] - 2026-02-28

### Added in 0.4.0

- **Pre-Capture Diagnostic Probes** - Unauthenticated HTTP and ICMP probes run before the Playwright session
  - Auth challenge probe: captures `WWW-Authenticate` headers and Set-Cookie values
  - HEAD support probe: checks if the target server supports HEAD requests
  - ICMP probe: pings the host and reports latency
  - Results stored as `log._probes` metadata in HAR output
- **Public IP Sanitization** - Detects and redacts public IPv4 addresses (preserves private/loopback/link-local)
- **Serial Number Field Detection** - JSON fields named `serial`, `serial_number`, `serialnumber`, `serialnum`, `sn` are
  now redacted
- **Cookie Object Sanitization** - Structured cookie objects in request/response entries are now sanitized
- **Credential-Like Value Detection** - New heuristic for short passwords (`pass123`, `token42`, `key!2024`)
- **Router/Modem Brand Detection** - Heuristics now flag values containing device brand names (NETGEAR, Linksys, ASUS,
  etc.)
- **PII Test Server** - `scripts/pii_test_server.py` replaces `mock_modem.py` as a standalone PII-laden web server for
  dogfooding sanitization, with mixed sci-fi references from the '70s through '90s (Blade Runner, TRON, Alien, WarGames,
  The Matrix, and more)
- **Browser Auto-Reinstall** - Detects missing browser executable and auto-reinstalls before retry

### Changed in 0.4.0

- **BREAKING**: `--interactive` flag replaced with `--no-interactive` (interactive mode is now the default for both
  `capture` and `sanitize` commands)
- SSID heuristic tightened: broad alphanumeric matching replaced with CamelCase-only pattern to reduce false positives
- Safe value patterns expanded: common words (`premium`, `admin`, `guest`, etc.) and already-redacted values are no
  longer flagged
- Phone number pattern boundary changed from `(?<!\d)` to `(?<!\w)` to prevent matching inside tokens
- `systemInfo`, `wifiInfo`, `networkInfo` now matched by pipe-delimited variable sanitization
- Codecov patch coverage check set to informational (reports but doesn't block)

### Fixed in 0.4.0

- **Security Hardening** - Sanitization coverage improvements across HAR, HTML, and heuristic analysis
- Pre-commit hooks fixed for relocated repository (stale venv paths)
- `ci-local.sh` now uses venv Python directly instead of bare `ruff`/`pytest` commands
- Various ruff and mypy errors resolved (type annotations, import sorting, unused suppressions)

### Migration Guide in 0.4.0

**CLI flag change:**

```bash
# Before (v0.3.x)
har-capture get http://device --interactive

# After (v0.4.0) — interactive is now the default
har-capture get http://device
har-capture get http://device --no-interactive  # to disable
```

## [0.3.3] - 2026-02-06

### Fixed in 0.3.3

- **5-Octet IPv4 Corruption** - Private IP addresses now produce valid 4-octet format instead of invalid 5-octet format
  (e.g., `10.123.45.67` is correctly sanitized to `10.255.x.x` instead of `10.255.x.x.67`)
- **Version String Preservation** - Firmware version strings like `5.7.1.5` are now correctly preserved instead of being
  sanitized as IP addresses. Version strings are not PII and must remain for diagnostics.

## [0.3.2] - 2026-02-06

### Added in 0.3.2

- **HeuristicMode Enum** - Fine-grained control over heuristic behavior with three modes:
  - `DISABLED` (default) - Skip heuristics, only redact known patterns (safe, backward compatible)
  - `FLAG` - Flag suspicious values for manual review (interactive mode)
  - `REDACT` - Auto-redact suspicious values (automated workflows)
- **Custom Patterns from Dict** - `custom_patterns` now accepts dict or file path
  - Enables passing patterns directly from modem.yaml or other configs
  - No need to write temporary files for API integration
- **Category-Aware Hashing** - New `hash_sensitive_value()` method for heuristically-detected values
  - Generates prefixed hashes: `WIFI_xxxxx`, `CRED_xxxxx`, `DEVICE_xxxxx`
  - Preserves correlation while indicating detection category

### Changed in 0.3.2

- **BREAKING**: Replaced `flag_suspicious` boolean with `heuristics: HeuristicMode` parameter
  - Old: `sanitize_har(data, flag_suspicious=True)`
  - New: `sanitize_har(data, heuristics=HeuristicMode.FLAG)`
  - Affects: `sanitize_html()`, `sanitize_har()`, `sanitize_har_file()`, CLI, browser capture
- **Custom Pattern Precedence** - Custom patterns now applied first, preventing generic patterns from overriding them
- **Already-Redacted Protection** - Account ID and heuristic patterns skip already-redacted values (e.g.,
  `MODEM_SN_xxxxx`)

### Fixed in 0.3.2

- **Custom Patterns Not Applied** - Custom patterns were loaded but never applied during sanitization
- **Pattern Re-Redaction** - Account ID pattern no longer re-hashes custom-redacted values
- **Multi-Underscore Prefixes** - Heuristics now correctly skip prefixes with underscores (e.g., `MODEM_SN_`)

### Migration Guide in 0.3.2

**For API Users:**

```python
# Before (v0.3.1)
from har_capture.sanitization.har import sanitize_har_file
sanitize_har_file(path, flag_suspicious=True)

# After (v0.3.2)
from har_capture.sanitization.har import sanitize_har_file
from har_capture.sanitization.report import HeuristicMode

# Interactive mode (manual review)
sanitize_har_file(path, heuristics=HeuristicMode.FLAG)

# Automated mode (auto-redact, may over-redact)
sanitize_har_file(path, heuristics=HeuristicMode.REDACT)

# Safe mode (default, only known patterns)
sanitize_har_file(path, heuristics=HeuristicMode.DISABLED)
# or simply: sanitize_har_file(path)
```

**For cable_modem_monitor Integration:**

```python
# Pass custom patterns as dict
modem_patterns = {
    "patterns": {
        "modem_serial": {
            "regex": r"SN[0-9]{10}",
            "replacement_prefix": "MODEM_SN"
        }
    }
}
sanitize_har_file(
    path,
    heuristics=HeuristicMode.REDACT,
    custom_patterns=modem_patterns  # Dict instead of file path
)
```

## [0.3.1] - 2026-02-04

### Fixed in 0.3.1

- **Interactive Mode Display** - Fixed summary panel not displaying when `keep_raw=False` (default)
  - Now shows version, auto-redacted counts, and file paths at start of review
  - Fixed double screen clearing that was hiding the summary
- **Interactive Mode File Handling** - Keep sanitized HAR file when interactive mode is enabled
  - Previously deleted uncompressed file, causing "Missing sanitization data" error
  - Now preserves file for user review and redaction application
- **Test Linting** - Fixed RUF059 warnings for unused unpacked variables in tests
- **Type Checking** - Re-added necessary type ignore for json.loads return type

### Added in 0.3.1

- **Solent Labs™ Branding** - Added watermark to interactive mode panels
- **Improved Instructions** - Clearer checkbox prompts ("Enter when done", pre-selected items noted)
- **Better UX** - Simplified keybindings (A/N for all/none work now), removed redundant Ctrl+C mention

## [0.3.0] - 2026-02-04

### Added in 0.3.0

- **Interactive Sanitization Mode** - Review and approve edge cases (WiFi SSIDs, device names, credentials) with
  beautiful CLI interface
  - Checkbox selection for flagged values with confidence indicators
  - Context display (surrounding HTML/values) for informed decisions
  - Quick actions (redact all, redact high confidence, skip review)
  - Two-pass workflow: auto-redaction + user review
- **Heuristic Detection** - ML-free detection of suspicious values:
  - SSID-like patterns (WiFi network names)
  - Device name patterns (router hostnames)
  - High-entropy values (potential passwords)
  - Values adjacent to redacted content
- **Sanitization Reports** - Structured reports with:
  - Auto-redaction statistics
  - Flagged values with confidence levels (high/medium/low)
  - User decisions (redacted/skipped)
  - Salt preservation for Pass 2
- **Consolidated Redaction Checking** - Single source of truth in `patterns/redaction.py`
  - Moved hard-coded patterns to `allowlist.json` configuration
  - Custom pattern support with merge logic
  - 99% test coverage with 71 parameterized tests

### Changed in 0.3.0

- **BREAKING**: Removed deprecated `patterns.loader.is_allowlisted()` - Use `patterns.is_allowlisted` instead
- **BREAKING**: Removed deprecated `validation.secrets.REDACTED_PATTERNS` - Now in `allowlist.json`
- Version bump to 0.3.0 (major release with breaking changes)
- Simplified README comparison table for better readability
- All test files now have comprehensive docstrings
- Tests refactored to table-driven style with `@pytest.mark.parametrize`

### Removed in 0.3.0

- Deprecated backward compatibility shims (clean v0.3.0 API)
- `docs/TECH_DEBT.md` (observations now tracked via TODO comments or issues)

### Fixed in 0.3.0

- ReDoS prevention with length checks before regex matching
- Input validation in `apply_user_redactions` with clear error messages
- Exception handling in interactive mode (graceful terminal error recovery)

### Migration Guide in 0.3.0

**Breaking Changes:**

```python
# ❌ No longer works:
from har_capture.patterns.loader import is_allowlisted
from har_capture.validation.secrets import REDACTED_PATTERNS

# ✅ Use instead:
from har_capture.patterns import is_allowlisted
from har_capture.patterns import is_redacted  # Recommended
```

**New Features:**

```bash
# Interactive mode - review edge cases
har-capture sanitize input.har --interactive

# Customize patterns
har-capture sanitize input.har --patterns custom-allowlist.json
```

## [0.2.5] - 2026-02-01

### Changed in 0.2.5

- Browser auto-installs on first `har-capture get` (no prompt, no manual step)

## [0.2.4] - 2026-02-01

### Added in 0.2.4

- Release automation script (`scripts/release.py`) for consistent version bumps

### Security in 0.2.4

- Raw HAR capture now uses temp files; PII is never written to user's directory
- Only sanitized content is saved to user-specified output path

### Changed in 0.2.4

- Extracted `REDACTED` constant and `_redact_value()` helper to reduce code duplication

## [0.2.3] - 2026-01-31

### Changed in 0.2.3

- HAR files are now pretty-printed by default (indent=2) for better readability
- Compressed output size unchanged (whitespace compresses well)

## [0.2.2] - 2026-01-31

### Fixed in 0.2.2

- **Security**: Compressed files now contain sanitized content (was compressing raw file)
- Workflow order: sanitize first, then compress the sanitized file

### Added in 0.2.2

- Version consistency test to prevent `__init__.py` / `pyproject.toml` mismatch
- Documentation clarifying that `get` command sanitizes by default

## [0.2.1] - 2026-01-30

### Fixed in 0.2.1

- Python 3.10 compatibility for version test (use regex instead of tomllib)

## [0.2.0] - 2026-01-30

### Added in 0.2.0

- Correlation-preserving redaction with salted hashes
- Format-preserving replacements (MAC, IP, email stay valid formats)
- Custom pattern support via external JSON files
- `--salt` and `--no-salt` CLI options
- Comprehensive test coverage (84%+)

### Changed in 0.2.0

- Default sanitization now uses random salt per session
- Refactored `CaptureResult` with composition pattern

## [0.1.2] - 2026-01-29

### Added in 0.1.2

- Auto-prompt to install browser on first capture (Y/n with default Yes)
- "Next steps" guidance after capture completes
- New functions: `check_browser_installed()`, `install_browser()`

### Fixed in 0.1.2

- README Quick Start: `--ip` flag → positional argument

## [0.1.1] - 2026-01-29

### Fixed in 0.1.1

- Downloads badge now renders correctly on PyPI (switched to shields.io)

### Added in 0.1.1

- Quick Start section in README for copy-paste installation

## [0.1.0] - 2026-01-29

### Added in 0.1.0

- Initial release extracted from cable_modem_monitor
- `sanitization.html`: HTML sanitization with PII detection
  - MAC address redaction
  - IP address redaction (preserves common gateway IPs)
  - IPv6 address redaction
  - Serial number redaction
  - Password/credential redaction
  - Email address redaction
  - WiFi credential detection in JavaScript variables
- `sanitization.har`: HAR file sanitization
  - Header sanitization (Authorization, Cookie, etc.)
  - POST data sanitization
  - Response content sanitization
  - JSON field sanitization
- `validation.secrets`: PII leak detection for pre-commit validation
- `capture.browser`: Playwright-based browser capture
- CLI commands: `capture`, `sanitize`, `validate`
- Zero dependencies for core sanitization (stdlib only)
- Optional dependencies for capture (playwright), CLI (typer)

[0.1.0]: https://github.com/solentlabs/har-capture/releases/tag/v0.1.0
[0.1.1]: https://github.com/solentlabs/har-capture/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/solentlabs/har-capture/compare/v0.1.1...v0.1.2
[0.10.0]: https://github.com/solentlabs/har-capture/compare/v0.9.1...v0.10.0
[0.10.1]: https://github.com/solentlabs/har-capture/compare/v0.10.0...v0.10.1
[0.10.2]: https://github.com/solentlabs/har-capture/compare/v0.10.1...v0.10.2
[0.2.0]: https://github.com/solentlabs/har-capture/compare/v0.1.2...v0.2.0
[0.2.1]: https://github.com/solentlabs/har-capture/compare/v0.2.0...v0.2.1
[0.2.2]: https://github.com/solentlabs/har-capture/compare/v0.2.1...v0.2.2
[0.2.3]: https://github.com/solentlabs/har-capture/compare/v0.2.2...v0.2.3
[0.2.4]: https://github.com/solentlabs/har-capture/compare/v0.2.3...v0.2.4
[0.2.5]: https://github.com/solentlabs/har-capture/compare/v0.2.4...v0.2.5
[0.3.0]: https://github.com/solentlabs/har-capture/compare/v0.2.5...v0.3.0
[0.3.1]: https://github.com/solentlabs/har-capture/compare/v0.3.0...v0.3.1
[0.3.2]: https://github.com/solentlabs/har-capture/compare/v0.3.1...v0.3.2
[0.3.3]: https://github.com/solentlabs/har-capture/compare/v0.3.2...v0.3.3
[0.4.0]: https://github.com/solentlabs/har-capture/compare/v0.3.3...v0.4.0
[0.4.1]: https://github.com/solentlabs/har-capture/compare/v0.4.0...v0.4.1
[0.4.2]: https://github.com/solentlabs/har-capture/compare/v0.4.1...v0.4.2
[0.4.3]: https://github.com/solentlabs/har-capture/compare/v0.4.2...v0.4.3
[0.4.4]: https://github.com/solentlabs/har-capture/compare/v0.4.3...v0.4.4
[0.4.5]: https://github.com/solentlabs/har-capture/compare/v0.4.4...v0.4.5
[0.5.0]: https://github.com/solentlabs/har-capture/compare/v0.4.5...v0.5.0
[0.5.1]: https://github.com/solentlabs/har-capture/compare/v0.5.0...v0.5.1
[0.6.0]: https://github.com/solentlabs/har-capture/compare/v0.5.1...v0.6.0
[0.6.1]: https://github.com/solentlabs/har-capture/compare/v0.6.0...v0.6.1
[0.7.0]: https://github.com/solentlabs/har-capture/compare/v0.6.1...v0.7.0
[0.7.1]: https://github.com/solentlabs/har-capture/compare/v0.7.0...v0.7.1
[0.8.0]: https://github.com/solentlabs/har-capture/compare/v0.7.1...v0.8.0
[0.8.1]: https://github.com/solentlabs/har-capture/compare/v0.8.0...v0.8.1
[0.8.2]: https://github.com/solentlabs/har-capture/compare/v0.8.1...v0.8.2
[0.9.0]: https://github.com/solentlabs/har-capture/compare/v0.8.2...v0.9.0
[0.9.1]: https://github.com/solentlabs/har-capture/compare/v0.9.0...v0.9.1
[unreleased]: https://github.com/solentlabs/har-capture/compare/v0.10.2...HEAD
