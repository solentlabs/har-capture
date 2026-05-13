# Architecture Decisions

Design rationale and "why" behind architectural choices. Each decision records the context, the choice made, and the
reasoning — so future contributors understand the tradeoffs rather than just the outcome.

## ADR-1: Capture is User-Driven, Not Automated

**Context:** har-capture's primary purpose is to help a user sanitize and package observed browser traffic so a
downstream system (like cable_modem_monitor) can reverse-engineer device APIs. The user navigates the device's web
interface, logs in, visits pages — the tool records everything.

**Decision:** The default capture mode is interactive. The user drives the browser. har-capture records, sanitizes, and
packages.

**Consequence:** The tool should not attempt to automate device interaction (login, navigation) in the default path.
Automated/headless mode exists for CI and advanced users but is not the primary use case.

## ADR-2: Minimal Pre-Flight in Interactive Mode

**Context:** The capture workflow originally ran 5 HTTP requests before opening Playwright: connectivity check, auth
challenge probe, HEAD probe, ICMP ping, and auth detection. For devices that allow only one concurrent session (e.g.,
Compal CH7465MT), these requests exhaust the session slot before the browser opens.

**Decision:** Interactive mode should make the fewest possible pre-flight HTTP requests. The browser handles auth
dialogs, redirects, and errors naturally — the user is present to respond.

- **Connectivity check (1 GET):** Retained. Validates the device is reachable before launching Playwright; without the
  check, Playwright would hang silently on unreachable devices. The original 0.6.0 form required an explicit `http://`
  or `https://` scheme — this was reversed in 0.8.0 after the CM1200 trap (contributor guesses HTTP, misses HTTPS-only
  auth challenge). Bare hostnames now auto-detect via TCP+TLS probes; explicit schemes still bypass detection. See
  ADR-10.
- **Auth detection:** Not needed in interactive mode. When a device responds with 401, Playwright shows a native Basic
  Auth dialog. The user enters credentials. Both the 401 and the authenticated retry are captured in the HAR — the full
  auth exchange is recorded.
- **Probes (auth challenge, HEAD, ICMP):** Not needed in interactive mode. Probe data (401 headers, Set-Cookie) is
  captured naturally in the HAR when the browser navigates. Probes were added because Playwright's `http_credentials`
  suppresses the 401 — but interactive mode does not use `http_credentials`.

**`--minimal` flag:** For the edge case where even the single connectivity check is problematic, `--minimal` reduces
pre-flight further: skips probes, skips auth detection, uses `domcontentloaded` page load strategy, disables
wait-for-data.

**Headless/automated mode** (`--headless --timeout N`) is the exception: no human is present, so auth detection and
probes are necessary. The user requesting headless mode implicitly accepts the connection overhead.

**Consequence:** The default interactive capture goes from 5 pre-flight HTTP requests to 1. Most devices work without
any flags.

## ADR-3: Probes Are Opt-In Diagnostics

**Context:** Pre-capture probes capture the device's 401 response, `WWW-Authenticate` headers, and `Set-Cookie` data.
cable_modem_monitor's intake pipeline uses this to reverse-engineer auth patterns. But the probe data is also present in
the HAR itself (the browser's first request to a 401 endpoint is recorded).

**Decision:** Probes are opt-in via `--diagnostics`. The HAR already contains the auth exchange from the browser's
natural interaction. Probes add a pre-Playwright snapshot that's useful when `http_credentials` suppresses the 401,
which only happens in automated mode.

**Consequence:** har-capture stays domain-agnostic. Downstream consumers (CMM intake) request `--diagnostics` when they
need probe metadata. Default users don't pay the connection cost.

## ADR-4: Auto-Fallback for Persistent-Connection Devices

**Context:** `page.goto(url, wait_until="networkidle")` requires 500ms of zero network activity. Some devices (Compal
CH7465MT) keep persistent polling/heartbeat connections, so `networkidle` never resolves. The `wait-for-data` mechanism
(2s of zero pending XHR/fetch) has the same problem.

**Decision:** Auto-detect and fall back. The initial `page.goto` uses `networkidle` with a 15-second timeout. If it
times out (the definitive signal that the device has persistent connections), the system:

1. Falls back to `domcontentloaded` (the page is already loaded — the wait condition failed, not the navigation)
1. Disables quiescence checks for the rest of the session
1. Logs the fallback so the user knows what happened

This is the same pattern as protocol negotiation — try the better option, catch the definitive failure, fall back. No
heuristics, no guessing.

Normal devices resolve `networkidle` in under 5 seconds. The 15-second timeout gives headroom for slow devices while
catching persistent-connection devices without excessive wait.

**Consequence:** The user never needs to know about page load strategies. The tool auto-adapts. `--minimal` remains as
an escape hatch for the rare case where even the auto-fallback's 15-second wait is unacceptable, or where the
connectivity check's single GET exhausts the device's session.

## ADR-5: Domain-Agnostic Core, Domain Knowledge via Data

**Context:** har-capture serves multiple consumers (cable modem monitor, printer admin panels, IoT hubs, SaaS
dashboards). Device-specific knowledge (safe values, heuristic detectors, HTML scanner config) varies across domains.

**Decision:** The sanitization engine has no knowledge of any particular device. Domain knowledge is loaded from JSON
pattern files at runtime via `--patterns`. Core pattern files (`pii.json`, `sensitive.json`, `allowlist.json`) contain
only universal PII rules.

**Consequence:** Adding support for a new product category requires a JSON file, not code changes. Consumers ship their
own pattern files.

## ADR-6: Two-Pass Sanitization Model

**Context:** Automated PII detection has false positives. Aggressive auto-redaction can destroy debugging utility.
Conservative detection misses real PII.

**Decision:** Pass 1 auto-redacts high-confidence PII (MACs, IPs, emails, passwords, tokens). Pass 2 presents ambiguous
values for interactive review — the user sees the value, its context, why it was flagged, and decides whether to redact.

**Consequence:** The tool is safe by default (Pass 1 catches universal PII) while giving the user control over edge
cases. Non-interactive mode (CI/headless) writes flagged values to a JSON report instead.

## ADR-7: XML POST Bodies Are Sanitized via Two Layers

**Context:** Devices with XML APIs (e.g., Compal CH7465MT) send POST bodies with `text/xml` or `application/xml` MIME
types containing session tokens, encrypted credentials, and device data.

**Decision:** XML POST body sanitization uses two layers:

1. `_sanitize_xml_fields()` — Parses XML, checks element tag names and attribute names against sensitive field patterns,
   redacts matching values. This mirrors how the JSON and form-urlencoded handlers check field names.
1. `sanitize_html()` — The existing 17-pass scanner runs on the XML text to catch pattern-based PII (MACs, IPs, emails)
   that field-name checking misses.

**Consequence:** Both field-name-based and pattern-based PII are caught. The HTML scanner already handles XML content
(used for `text/xml` responses), so no new engine is needed. Malformed XML falls through gracefully.

## ADR-8: Duplicate Connectivity Check Eliminated

**Context:** `capture_device_har()` internally called `check_device_connectivity()` to determine the URL scheme. But the
CLI workflow already called this in Phase 2. The result was two identical GET requests before the browser opened.

**Decision:** The CLI now passes the pre-computed `target_url` to `capture_device_har()`. When provided, the internal
connectivity check is skipped. When called directly (library API without CLI), the check still runs.

**Consequence:** One fewer pre-flight HTTP request for all capture modes. Library API backward-compatible (new parameter
has a `None` default).

## ADR-9: Session Contamination Guard

**Context:** 6 of 36 catalog HARs in the MCP intake pipeline failed validation because the browser had an existing
session when capture started. Failure signatures: first request carries `Secure`, `XSRF_TOKEN`, `PHPSESSID` session
cookies, or `Authorization` headers. The login flow is missing, making the HAR useless for auth analysis.

**Decision:** Three layered defenses, in priority order:

1. **Force clean browser context.** `storage_state={"cookies": [], "origins": []}` is set on every Playwright context.
   This prevents all cookie/credential inheritance regardless of how the browser was launched. This single change
   prevents all 6 failure signatures.

1. **Pre-flight session check.** Before launching Playwright, an unauthenticated GET checks whether the device serves
   data content (no login page). If so, the device has a live session from another source (another tab, previous
   connection from the same IP), and the workflow aborts with a clear message. Skipped in `--minimal` mode.

1. **Pre-capture cookie audit.** `context.cookies()` is called immediately after context creation and before any
   navigation. The result is emitted as `_solentlabs.pre_capture_cookies` in the HAR. With the clean storage state, this
   should always be empty — a non-empty list is a diagnostic signal for downstream tools.

**Consequence:** The default workflow adds one pre-flight GET (session check). `--minimal` skips it for
session-constrained devices. The pre-capture cookie audit has zero network cost — it reads local context state. All
three defenses are additive and composable.

## ADR-10: Auto-Detect Protocol for Bare Hostnames (supersedes 0.6.0 explicit-scheme rule)

**Context:** v0.6.0 hardened the connectivity phase to require an explicit `http://` or `https://` scheme, rejecting
bare hostnames with a "Missing scheme" error. The intent was to eliminate ambiguity and avoid duplicate connectivity
probes. In practice this restored a contributor trap that v0.4.4's raw-probe feature had originally been built to
diagnose: cable_modem_monitor #121 (CM1200) closed only after weeks of debugging because the device serves its auth
challenge on `:443` and silently 200s on `:80`. A contributor guessing `http://` captures a useless redirect stub; a
contributor guessing `https://` captures the real auth flow. The "helpful error" the v0.6.0 rejection produces does not
help — both choices look equally plausible at the CLI.

**Decision:** When the target lacks an explicit scheme, auto-detect via stdlib TCP+TLS probes. Probe `:80` and `:443`;
prefer HTTPS when its TCP connection accepts *and* the TLS handshake completes. Explicit schemes still bypass detection
— the user has chosen and we do not second-guess.

The probe code is adapted from `cable_modem_monitor_core/connectivity.py` (both projects owned by solentlabs). It is
duplicated, not shared, so har-capture's runtime stays stdlib-only — CMM Core's `requests`/`urllib3` deps would land in
every har-capture install, and a shared package would also drag playwright into CMM Core's tree.

The implementation defaults `getaddrinfo` to IPv4: most consumer devices are IPv4-only on the LAN side, and a dual-stack
resolver may otherwise return IPv6 first and false-fail before falling back. Bracketed IPv6 input (`[::1]:8443`) is
treated as the user's explicit v6 signal and auto-selects `AF_INET6` for the probe — capture-everything beats default-
to-fail when the user is asking us to look at v6. Unbracketed inputs that happen to contain colons stay on AF_INET
(heuristic IPv6 detection on bare strings is too risky to do silently). The TLS handshake uses a `SECLEVEL=0` cipher
context so it completes against legacy devices (TLS 1.0/1.1, 3DES/RC4) — this tolerance is the entire point. Without it,
we would false-fail HTTPS on old modems and incorrectly fall back to HTTP, inverting the trap this feature exists to
close.

har-capture deliberately does **not** classify or surface the negotiated TLS version. Unlike CMM Core (whose
`requests`-based runtime can mount a `LegacySSLAdapter` to keep polling working), har-capture's runtime is Chromium
driven by Playwright — we don't control its TLS stack and cannot act on a "legacy" classification. Carrying that flag
would be ceremony without consequence. The version is logged for diagnostics so operators tailing logs can see what got
negotiated, but the `ProtocolDetectionResult` returns only `success`/`protocol`/`working_url`/ `error`. This is a
deliberate divergence from CMM Core, recorded here so future re-syncs do not reintroduce the flag.

**Consequence:** Bare hostnames work again (`har-capture 192.168.100.1`). The CM1200 trap is closed by default, and the
inverse trap (false-failing HTTPS on legacy devices) is closed by the cipher tolerance. One additional pre-flight TCP
probe in the bare-hostname path (the TCP connect on the unused port — closed ports return immediately, so latency is
bounded by `timeout`). When an explicit scheme is given, behavior is byte-identical to v0.7.x.

## ADR-11: CLAUDE.md is a Router, Not a Source of Truth

**Context:** Through v0.9.0, `CLAUDE.md` had grown to 19 numbered principles across five subsections (Architecture 1-7,
Specs/Docs 8-10, Code Quality 11-13, Testing 14-16, Process 17-19). Most of the content restated material that had
authoritative homes elsewhere: architecture principles were already in `ARCHITECTURE.md`, the confidence boundary was
already in `SANITIZATION_SPEC` invariant #11, code-quality and testing rules had no dedicated doc and so accumulated
here by default.

Two failure modes resulted:

1. **Drift.** Restated content diverged from authority. CLAUDE.md stated the coverage threshold as 75% well after
   `pyproject.toml` moved to `fail_under = 90` (raised in v0.8.1 per the v0.8.1 CHANGELOG entry). A reader trusting
   CLAUDE.md got a stale answer; nothing forced reconciliation.

1. **AI-assisted contributors followed the restatements, not the authoritative docs.** Other contributors using AI tools
   were reaching the restated rule in CLAUDE.md and acting on it without consulting the spec the rule originally came
   from. The restatement became the de facto source of truth simply because it was the first hit. When the restatement
   was stale, the AI happily produced stale-aligned code.

A third failure mode surfaced during the v0.9.1 prep session itself: **the absence of versioning, branching, and
PR-consolidation policy in any authoritative doc.** Those rules lived only in personal memory and project tradition
(`git log`). An AI tool reaching for the post-1.0 conventional-commits → semver mapping (`feat:` → minor) mis-bumped the
version because the actual pre-1.0 policy was nowhere to be read. Similarly, the "one PR per release" rule was not
encoded anywhere a fresh reader (human or AI) could find it.

Cable Modem Monitor went through the same exercise (commit `6c4271e7`, "docs: slim CLAUDE.md by offloading
architecture/quality/testing principles") and landed on a router pattern: CLAUDE.md becomes a thin entry point
describing how Claude behaves in the repo, with a routing table to authoritative docs and discipline sections that have
no other home. Architecture, code-quality, testing, and release-policy rules each have a single authoritative location
and CLAUDE.md points at them rather than restating them.

**Decision:** Restructure har-capture's doc set around the same router pattern.

- `CLAUDE.md` is reduced to: opening tagline + routing table ("Where Things Live") + slimmed Core Principles
  (specs-authority + process guardrails only, 7 numbered rules with continuous numbering preserved via
  bullet-with-bold-prefix syntax) + discipline sections (Diagnosis, Decision, Verification, Pre-Push Verification,
  Irreversible Operations, PR/Issue Conventions) + an AI Shortcut Audit cataloguing encoded failure modes from real
  sessions.
- `docs/ARCHITECTURE.md` gains a Code Organization section housing the four code-structure principles (SoC, DRY,
  no-CLI-dep in core, additive features) and the package layout that enforces them. The existing Design Constraints,
  domain-extension model, and Confidence Boundary sections are unchanged.
- `docs/CODE_REVIEW.md` is new and houses code-quality principles (no shortcuts, quality gates non-negotiable, test
  overrides as code smell), test-file standards (table-driven by default, JSON fixtures, conversion as review-step), the
  concrete Quality Gates table (command + threshold), and source-file standards (comments, error handling at boundaries,
  no backwards-compat shims).
- `docs/RELEASE.md` gains a Version Numbering section (pre-1.0 bump policy, conventional-commit type does not auto-imply
  bump, CHANGELOG-section-header as the tiebreaker, examples from project history) and a Branching and Merging section
  (one PR per release, consolidate before pushing, cherry-pick vs rebase, merge-vs-squash).

**Consequence:**

- Any future principle or convention goes to its authoritative doc first. If it does not have an authoritative doc, the
  priority is to create or extend one — not to add it to CLAUDE.md. CLAUDE.md picks up a routing entry pointing at the
  authoritative location and, if it affects Claude's runtime behavior specifically, a brief reference in the relevant
  discipline section.
- Renumbering Core Principles in CLAUDE.md is a cross-cutting change. Live code/test/script references to numbered
  principles in this PR were updated to point at the new authoritative doc and section rather than at numbered CLAUDE.md
  entries (which can be renumbered again). Historical CHANGELOG entries retain their original numbers — they describe
  state at release time and modifying them would be revisionist. Future numbered-list renumbering requires the
  pre-flight grep added to CLAUDE.md's Verification Discipline.
- The doc set is bigger overall (CLAUDE.md 168 → 215 lines, ARCHITECTURE +24, RELEASE +78, new CODE_REVIEW 126 lines)
  but each section now has a single authoritative location. Drift is detectable by direct comparison; restating a rule
  in CLAUDE.md is now an anti-pattern flagged explicitly in the AI Shortcut Audit ("Restating instead of pointing").
- The AI Shortcut Audit section is intended to grow. When a real session surfaces a new shortcut that produced cost, add
  the entry with a route to the doc that would have prevented it. Speculative entries are not added.
