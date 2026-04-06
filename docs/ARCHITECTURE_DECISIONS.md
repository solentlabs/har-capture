# Architecture Decisions

Design rationale and "why" behind architectural choices. Each decision
records the context, the choice made, and the reasoning — so future
contributors understand the tradeoffs rather than just the outcome.

## ADR-1: Capture is User-Driven, Not Automated

**Context:** har-capture's primary purpose is to help a user sanitize and
package observed browser traffic so a downstream system (like
cable_modem_monitor) can reverse-engineer device APIs. The user navigates
the device's web interface, logs in, visits pages — the tool records
everything.

**Decision:** The default capture mode is interactive. The user drives the
browser. har-capture records, sanitizes, and packages.

**Consequence:** The tool should not attempt to automate device interaction
(login, navigation) in the default path. Automated/headless mode exists for
CI and advanced users but is not the primary use case.

## ADR-2: Minimal Pre-Flight in Interactive Mode

**Context:** The capture workflow originally ran 5 HTTP requests before
opening Playwright: connectivity check, auth challenge probe, HEAD probe,
ICMP ping, and auth detection. For devices that allow only one concurrent
session (e.g., Compal CH7465MT), these requests exhaust the session slot
before the browser opens.

**Decision:** Interactive mode should make the fewest possible pre-flight
HTTP requests. The browser handles auth dialogs, redirects, and errors
naturally — the user is present to respond.

- **Connectivity check (1 GET):** Retained. Validates the device is reachable
  on the user-provided scheme before launching Playwright. The URL must
  include an explicit `http://` or `https://` scheme. Without the check,
  Playwright would hang silently on unreachable devices.
- **Auth detection:** Not needed in interactive mode. When a device responds
  with 401, Playwright shows a native Basic Auth dialog. The user enters
  credentials. Both the 401 and the authenticated retry are captured in the
  HAR — the full auth exchange is recorded.
- **Probes (auth challenge, HEAD, ICMP):** Not needed in interactive mode.
  Probe data (401 headers, Set-Cookie) is captured naturally in the HAR when
  the browser navigates. Probes were added because Playwright's
  `http_credentials` suppresses the 401 — but interactive mode does not use
  `http_credentials`.

**`--minimal` flag:** For the edge case where even the single connectivity
check is problematic, `--minimal` reduces pre-flight further:
skips probes, skips auth detection, uses `domcontentloaded` page load
strategy, disables wait-for-data.

**Headless/automated mode** (`--headless --timeout N`) is the exception: no
human is present, so auth detection and probes are necessary. The user
requesting headless mode implicitly accepts the connection overhead.

**Consequence:** The default interactive capture goes from 5 pre-flight
HTTP requests to 1. Most devices work without any flags.

## ADR-3: Probes Are Opt-In Diagnostics

**Context:** Pre-capture probes capture the device's 401 response,
`WWW-Authenticate` headers, and `Set-Cookie` data. cable_modem_monitor's
intake pipeline uses this to reverse-engineer auth patterns. But the probe
data is also present in the HAR itself (the browser's first request to a
401 endpoint is recorded).

**Decision:** Probes are opt-in via `--diagnostics`. The HAR already
contains the auth exchange from the browser's natural interaction. Probes
add a pre-Playwright snapshot that's useful when `http_credentials`
suppresses the 401, which only happens in automated mode.

**Consequence:** har-capture stays domain-agnostic. Downstream consumers
(CMM intake) request `--diagnostics` when they need probe metadata. Default
users don't pay the connection cost.

## ADR-4: Auto-Fallback for Persistent-Connection Devices

**Context:** `page.goto(url, wait_until="networkidle")` requires 500ms of
zero network activity. Some devices (Compal CH7465MT) keep persistent
polling/heartbeat connections, so `networkidle` never resolves. The
`wait-for-data` mechanism (2s of zero pending XHR/fetch) has the same
problem.

**Decision:** Auto-detect and fall back. The initial `page.goto` uses
`networkidle` with a 15-second timeout. If it times out (the definitive
signal that the device has persistent connections), the system:

1. Falls back to `domcontentloaded` (the page is already loaded — the wait
   condition failed, not the navigation)
1. Disables quiescence checks for the rest of the session
1. Logs the fallback so the user knows what happened

This is the same pattern as protocol negotiation — try the better option,
catch the definitive failure, fall back. No heuristics, no guessing.

Normal devices resolve `networkidle` in under 5 seconds. The 15-second
timeout gives headroom for slow devices while catching persistent-connection
devices without excessive wait.

**Consequence:** The user never needs to know about page load strategies.
The tool auto-adapts. `--minimal` remains as an escape hatch for the rare
case where even the auto-fallback's 15-second wait is unacceptable, or
where the connectivity check's single GET exhausts the device's session.

## ADR-5: Domain-Agnostic Core, Domain Knowledge via Data

**Context:** har-capture serves multiple consumers (cable modem monitor,
printer admin panels, IoT hubs, SaaS dashboards). Device-specific knowledge
(safe values, heuristic detectors, HTML scanner config) varies across
domains.

**Decision:** The sanitization engine has no knowledge of any particular
device. Domain knowledge is loaded from JSON pattern files at runtime via
`--patterns`. Core pattern files (`pii.json`, `sensitive.json`,
`allowlist.json`) contain only universal PII rules.

**Consequence:** Adding support for a new product category requires a JSON
file, not code changes. Consumers ship their own pattern files.

## ADR-6: Two-Pass Sanitization Model

**Context:** Automated PII detection has false positives. Aggressive
auto-redaction can destroy debugging utility. Conservative detection misses
real PII.

**Decision:** Pass 1 auto-redacts high-confidence PII (MACs, IPs, emails,
passwords, tokens). Pass 2 presents ambiguous values for interactive review
— the user sees the value, its context, why it was flagged, and decides
whether to redact.

**Consequence:** The tool is safe by default (Pass 1 catches universal PII)
while giving the user control over edge cases. Non-interactive mode
(CI/headless) writes flagged values to a JSON report instead.

## ADR-7: XML POST Bodies Are Sanitized via Two Layers

**Context:** Devices with XML APIs (e.g., Compal CH7465MT) send POST
bodies with `text/xml` or `application/xml` MIME types containing session
tokens, encrypted credentials, and device data.

**Decision:** XML POST body sanitization uses two layers:

1. `_sanitize_xml_fields()` — Parses XML, checks element tag names and
   attribute names against sensitive field patterns, redacts matching values.
   This mirrors how the JSON and form-urlencoded handlers check field names.
1. `sanitize_html()` — The existing 17-pass scanner runs on the XML text
   to catch pattern-based PII (MACs, IPs, emails) that field-name checking
   misses.

**Consequence:** Both field-name-based and pattern-based PII are caught.
The HTML scanner already handles XML content (used for `text/xml`
responses), so no new engine is needed. Malformed XML falls through
gracefully.

## ADR-8: Duplicate Connectivity Check Eliminated

**Context:** `capture_device_har()` internally called
`check_device_connectivity()` to determine the URL scheme. But the CLI
workflow already called this in Phase 2. The result was two identical GET
requests before the browser opened.

**Decision:** The CLI now passes the pre-computed `target_url` to
`capture_device_har()`. When provided, the internal connectivity check is
skipped. When called directly (library API without CLI), the check still
runs.

**Consequence:** One fewer pre-flight HTTP request for all capture modes.
Library API backward-compatible (new parameter has a `None` default).

## ADR-9: Session Contamination Guard

**Context:** 6 of 36 catalog HARs in the MCP intake pipeline failed
validation because the browser had an existing session when capture
started. Failure signatures: first request carries `Secure`,
`XSRF_TOKEN`, `PHPSESSID` session cookies, or `Authorization` headers.
The login flow is missing, making the HAR useless for auth analysis.

**Decision:** Three layered defenses, in priority order:

1. **Force clean browser context.** `storage_state={"cookies": [], "origins": []}` is set on every Playwright context. This prevents
   all cookie/credential inheritance regardless of how the browser was
   launched. This single change prevents all 6 failure signatures.

1. **Pre-flight session check.** Before launching Playwright, an
   unauthenticated GET checks whether the device serves data content
   (no login page). If so, the device has a live session from another
   source (another tab, previous connection from the same IP), and the
   workflow aborts with a clear message. Skipped in `--minimal` mode.

1. **Pre-capture cookie audit.** `context.cookies()` is called
   immediately after context creation and before any navigation. The
   result is emitted as `_solentlabs.pre_capture_cookies` in the HAR.
   With the clean storage state, this should always be empty — a
   non-empty list is a diagnostic signal for downstream tools.

**Consequence:** The default workflow adds one pre-flight GET (session
check). `--minimal` skips it for session-constrained devices. The
pre-capture cookie audit has zero network cost — it reads local context
state. All three defenses are additive and composable.
