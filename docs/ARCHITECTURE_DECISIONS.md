# Architecture Decisions

The architectural choices that shape har-capture as it is today, and why each holds: the problem it answers, the rule,
and what follows from it.

## ADR-1: Capture is User-Driven, Not Automated

**Context:** har-capture helps a user sanitize and package observed browser traffic so a downstream system (like
cable_modem_monitor) can reverse-engineer device APIs. The user navigates the device's web interface, logs in, visits
pages — the tool records everything.

**Decision:** The default capture mode is interactive. The user drives the browser. har-capture records, sanitizes, and
packages.

**Consequence:** The tool does not automate device interaction (login, navigation) in the default path.
Automated/headless capture exists in the Python API for CI and advanced users (see ADR-2); it is not the primary use
case, and the CLI does not offer it.

## ADR-2: Minimal Pre-Flight in Interactive Mode

**Context:** Every HTTP request sent before the browser opens can cost a session. Devices that allow only one concurrent
session (e.g., Compal CH7465MT) lose the slot to pre-flight requests, and the capture then records a locked-out device.

**Decision:** Interactive mode makes the fewest possible pre-flight HTTP requests. The browser handles auth dialogs,
redirects, and errors naturally — the user is present to respond.

- **Connectivity check (1 GET):** Validates the device is reachable before launching Playwright, which otherwise hangs
  silently on an unreachable device, and settles `http` vs `https`. Bare hostnames auto-detect the scheme via TCP+TLS
  probes; an explicit scheme bypasses detection (ADR-10).
- **Session check (1 GET):** Detects a live session before capture starts (ADR-9).
- **No auth detection.** When a device responds with 401, Playwright shows a native Basic Auth dialog and the user
  enters credentials. Both the 401 and the authenticated retry are captured in the HAR.
- **No probes without credentials.** The 401 headers and `Set-Cookie` a probe would record are captured in the HAR when
  the browser navigates. A probe is needed only when Playwright's `http_credentials` suppresses the 401 (ADR-3).

**`--minimal`:** For session-constrained devices, `--minimal` skips the session check and the auth probe, loads pages
with `domcontentloaded`, and disables wait-for-data. The connectivity check still runs once, inside
`capture_device_har()`. CAPTURE_SPEC § Minimal Mode tabulates the requests per mode.

**Headless/automated capture** is a Python API mode (`capture_device_har(headless=True, timeout=N)`,
`run_capture_workflow(...)`), and the exception to minimal pre-flight: no human is present, so the library's workflow
runs session, probe and auth checks by default. A headless capture requires a `timeout` — without one it would wait for
a user to close a window that does not exist — and both entry points raise `ValueError` before sending anything.

**No headless CLI flag.** A form-login device cannot be captured headless (nobody is there to fill the form), and ADR-1
makes capture user-driven, so the CLI has no `--headless`, `--timeout` or `--diagnostics` flag. Unattended capture of a
Basic-Auth device is available through the Python API.

**With credentials** (`--username/--password`), the CLI sends one more pre-flight request, the auth challenge probe:
Playwright's `http_credentials` suppresses the device's 401 in the HAR, and the probe records it first (ADR-3).

**Consequence:** A default interactive capture sends two pre-flight GETs, three with credentials, one with `--minimal`.
Most devices work without any flags.

## ADR-3: Probes Are Opt-In Diagnostics

**Context:** Pre-capture probes record the device's 401 response, `WWW-Authenticate` headers, and `Set-Cookie` data.
cable_modem_monitor's intake pipeline uses this to reverse-engineer auth patterns. The same data is also in the HAR
itself whenever the browser's first request to a 401 endpoint is recorded.

**Decision:** The CLI runs one probe, the auth challenge (`run_auth_probe_phase`), and only when `--username/--password`
is given: Playwright's `http_credentials` then suppresses the 401 in the HAR, and the probe is the only record of it.
Without credentials the browser shows the native auth dialog and the HAR holds the full 401 exchange, so no probe runs.
`--minimal` skips it. The HEAD and ICMP probes run only in the Python API (`run_capture_workflow()` runs all three by
default; `skip_probes=True` skips them).

**Consequence:** har-capture stays domain-agnostic, and the CLI sends at most one request beyond the connectivity and
session checks. A consumer that needs the HEAD or ICMP results uses the Python API.

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

**Consequence:** The user never needs to know about page load strategies. The tool auto-adapts. `--minimal` is the
escape hatch where even the auto-fallback's 15-second wait, or the session check, is unacceptable.

## ADR-5: Domain-Agnostic Core, Domain Knowledge via Data

**Context:** har-capture serves multiple consumers (cable modem monitor, printer admin panels, IoT hubs, SaaS
dashboards). Device-specific knowledge (safe values, heuristic detectors, HTML scanner config) varies across domains.

**Decision:** The sanitization engine has no knowledge of any particular device. Domain knowledge is loaded from JSON
pattern files at runtime via `--patterns`. Core pattern files (`pii.json`, `sensitive.json`, `allowlist.json`) contain
only universal PII rules.

Script variable names are vendor knowledge. The HTML engine reads a `var NAME = '…'` value only for names a pattern file
lists in `script_variables` (PATTERN_SPEC): `network-device` lists Motorola's `CurrentPw…` password variables and
Netgear's `tagValueList` and similar pipe-delimited names.

Wi-Fi network names are not device knowledge: an SSID is personal data wherever it appears, so the SSID rules (text
labels, sibling labels, SSID-named attributes, inputs and selects, JS keys naming `ssid`, the JSON SSID-key rule, and
validate's SSID warnings) are core.

**Consequence:** Adding support for a new product category requires a JSON file, not code changes. Consumers ship their
own pattern files. `--patterns base` applies universal rules only, so a device capture takes its domain file.

## ADR-6: Two-Pass Sanitization Model

**Context:** Automated PII detection has false positives. Aggressive auto-redaction can destroy debugging utility.
Conservative detection misses real PII.

**Decision:** Pass 1 auto-redacts high-confidence PII (MACs, IPs, emails, passwords, tokens). Pass 2 presents ambiguous
values for interactive review — the user sees the value, its context, why it was flagged, and decides whether to redact.

**Consequence:** The tool is safe by default (Pass 1 catches universal PII) while giving the user control over edge
cases. The review needs a terminal, and a flagged value nobody reviews ships as captured — so the sanitized file records
how its review ended (`log._har_capture.sanitization.review`: `completed`, `skipped`, `cancelled`, `no_tty`,
`none_flagged`; absent when no review was recorded). A file with flagged values and `user_redacted: 0` is otherwise
indistinguishable from one nobody looked at; the recorded outcome lets a recipient tell a reviewed capture from an
ignored one.

Without a terminal, neither command prompts; each records `no_tty` and warns loudly with the flagged count. `sanitize`
also writes the flagged values to a JSON report beside its input (`<input>.review.json`, or `--report`): the raw input
is already on disk, so the report adds no new copy of it. `get` writes no report: the raw capture never persists on disk
(design constraint 5), and a report would hold its flagged values. Recording is a library function (`record_review`), so
the CLI stays a thin wrapper (Code Organization rule 3).

## ADR-7: XML POST Bodies Are Sanitized via Two Layers

**Context:** Devices with XML APIs (e.g., Compal CH7465MT) send POST bodies with `text/xml` or `application/xml` MIME
types containing session tokens, encrypted credentials, and device data.

**Decision:** XML POST body sanitization uses two layers:

1. `_sanitize_xml_fields()` — Parses XML, checks element tag names and attribute names against sensitive field patterns,
   redacts matching values. This mirrors how the JSON and form-urlencoded handlers check field names.
1. `sanitize_html()` — The HTML engine's scanner runs on the XML text to catch pattern-based PII (MACs, IPs, emails)
   that field-name checking misses.

**Consequence:** Both field-name-based and pattern-based PII are caught. The HTML scanner already handles XML content
(used for `text/xml` responses), so no separate engine exists. Malformed XML falls through gracefully.

## ADR-8: One Connectivity Check per Capture

**Context:** Both the CLI workflow and `capture_device_har()` need the device's URL scheme, and each check is a GET the
device answers before the browser opens.

**Decision:** The CLI passes the `target_url` its connectivity phase computed to `capture_device_har()`, which then
skips its own check. Called without `target_url` (the library API, or the CLI in `--minimal` mode),
`capture_device_har()` runs the check itself.

**Consequence:** Every capture mode sends exactly one connectivity GET. `target_url` defaults to `None`, so library
callers need no change.

## ADR-9: Session Contamination Guard

**Context:** A capture that starts with a live session has no login flow, which makes the HAR useless for auth analysis.
Its signature: the first request already carries `Secure`, `XSRF_TOKEN` or `PHPSESSID` session cookies, or an
`Authorization` header. In cable_modem_monitor's catalog intake this was the failure behind 6 of 36 rejected HARs.

**Decision:** Three layered defenses, in priority order:

1. **Force clean browser context.** `storage_state={"cookies": [], "origins": []}` is set on every Playwright context.
   This prevents all cookie/credential inheritance regardless of how the browser was launched, and on its own prevents
   every signature above.

1. **Pre-flight session check.** Before launching Playwright, an unauthenticated GET checks whether the device serves
   data content (no login page). If so, the device has a live session from another source (another tab, a connection
   from the same IP), and the workflow aborts with a clear message. Skipped in `--minimal` mode.

1. **Pre-capture cookie audit.** `context.cookies()` is called immediately after context creation and before any
   navigation. The result is emitted as `_solentlabs.pre_capture_cookies` in the HAR. With the clean storage state, this
   is always empty — a non-empty list is a diagnostic signal for downstream tools.

**Consequence:** The default workflow sends one pre-flight GET for the session check. `--minimal` skips it for
session-constrained devices. The pre-capture cookie audit has zero network cost — it reads local context state. All
three defenses are additive and composable.

## ADR-10: Auto-Detect Protocol for Bare Hostnames

**Context:** A contributor typing a bare hostname cannot tell which scheme the device needs, and guessing wrong is
silent. A Netgear CM1200 serves its auth challenge on `:443` and answers `200` on `:80`: a contributor guessing
`http://` captures a useless redirect stub, one guessing `https://` captures the real auth flow. An error asking for an
explicit scheme does not help — both choices look equally plausible at the CLI.

**Decision:** When the target lacks an explicit scheme, auto-detect via stdlib TCP+TLS probes. Probe `:80` and `:443`;
prefer HTTPS when its TCP connection accepts *and* the TLS handshake completes. Explicit schemes bypass detection — the
user has chosen and the tool does not second-guess.

The probe code is adapted from `cable_modem_monitor_core/connectivity.py` (both projects owned by solentlabs). It is
duplicated, not shared, so har-capture's runtime stays stdlib-only — CMM Core's `requests`/`urllib3` deps would land in
every har-capture install, and a shared package would also drag playwright into CMM Core's tree.

`getaddrinfo` defaults to IPv4: most consumer devices are IPv4-only on the LAN side, and a dual-stack resolver may
otherwise return IPv6 first and false-fail before falling back. Bracketed IPv6 input (`[::1]:8443`) is the user's
explicit v6 signal and selects `AF_INET6` for the probe. Unbracketed inputs that happen to contain colons stay on
AF_INET (heuristic IPv6 detection on bare strings is too risky to do silently). The TLS handshake uses a `SECLEVEL=0`
cipher context so it completes against legacy devices (TLS 1.0/1.1, 3DES/RC4); without that tolerance HTTPS would
false-fail on old modems and fall back to HTTP, inverting the trap this feature closes.

har-capture does **not** classify or surface the negotiated TLS version. Unlike CMM Core (whose `requests`-based runtime
can mount a `LegacySSLAdapter` to keep polling working), har-capture's runtime is Chromium driven by Playwright — it
does not control that TLS stack and cannot act on a "legacy" classification. The version is logged for diagnostics, and
`ProtocolDetectionResult` returns only `success`/`protocol`/`working_url`/`error`. This is a deliberate divergence from
CMM Core, so a re-sync must not bring the flag across.

**Consequence:** Bare hostnames work (`har-capture 192.168.100.1`), with HTTPS preferred where the device offers it and
legacy TLS tolerated. The bare-hostname path adds one TCP probe on the unused port (a closed port returns immediately,
so latency is bounded by `timeout`). An explicit scheme skips detection entirely.

## ADR-11: CLAUDE.md is a Router, Not a Source of Truth

**Context:** Rules restated outside their authoritative doc drift from it, and readers — human or AI — act on whichever
copy they reach first. A restated coverage threshold in CLAUDE.md read 75% while `pyproject.toml` enforced 90; AI tools
reaching CLAUDE.md first followed the stale copy. Rules with no authoritative home at all (pre-1.0 version bumps, one PR
per release) were invisible to a fresh reader, and a conventional-commit reflex mis-bumped a version for lack of them.

**Decision:** Every rule has one authoritative doc, and `CLAUDE.md` routes to it.

- `CLAUDE.md` holds a routing table ("Where Things Live"), Core Principles limited to specs-authority and process
  guardrails (numbered continuously via bullet-with-bold-prefix syntax), discipline sections (Diagnosis, Decision,
  Verification, Pre-Push Verification, Irreversible Operations, PR/Issue Conventions), and an AI Shortcut Audit
  cataloguing failure modes from real sessions.
- `docs/ARCHITECTURE.md` holds the Code Organization principles (SoC, DRY, no CLI dependency in core, additive features)
  and the package layout that enforces them, alongside the Design Constraints, domain-extension model, and Confidence
  Boundary.
- `docs/CODE_REVIEW.md` holds code-quality principles, test-file standards (table-driven, JSON fixtures), the Quality
  Gates table, and source-file standards.
- `docs/RELEASE.md` holds Version Numbering (pre-1.0 bump policy; the CHANGELOG section header, not the commit type,
  decides the bump) and Branching and Merging (one PR per release).

cable_modem_monitor uses the same router pattern.

**Consequence:**

- A new principle or convention goes to its authoritative doc first; if none exists, one is created or extended.
  CLAUDE.md gains a routing entry and, when it changes Claude's runtime behavior, a brief reference in the relevant
  discipline section.
- Code, tests and scripts cite an authoritative doc and section, never a numbered CLAUDE.md entry. CHANGELOG entries
  keep the numbers they were written with. Renumbering a list requires the pre-flight grep in CLAUDE.md's Verification
  Discipline.
- Restating a rule in CLAUDE.md is an anti-pattern listed in the AI Shortcut Audit ("Restating instead of pointing").
  The audit grows only from real sessions that surfaced a costly shortcut, each entry routing to the doc that would have
  prevented it.

## ADR-12: Redaction Scope Is Anti-Drift — "Redact More" Is a Change Against the Founding Contract

**Context:** har-capture's founding contract is to observe and capture everything, scrub PII, and compress so the user
can submit. Sanitization serves that contract, not overrides it — a HAR that survived sanitization must still be
faithful enough to reconstruct the device's behavior.

A redactor drifts from that contract one locally-defensible change at a time, and the cost is visible only in aggregate,
from outside the tool. Two canonical cases:

1. **Stripping authorization scheme tokens.** `Basic` / `Bearer` / `Digest` is protocol structure from a closed set of
   RFC 7235 identifiers, not a secret. Removing it scrubs no PII and destroys the only signal that lets a consumer
   classify the auth mechanism without a `401 + WWW-Authenticate` exchange — a Netgear C7000v2 capture carrying 32×
   `Authorization: AUTH_<hash>` cannot be classified.
1. **Hashing cookie attribute values.** A cookie regex like `([^=;\s]+)=([^;]*)` matches `Path=/` and `Max-Age=3600`
   exactly as it matches `session=<secret>`, hashing protocol metadata alongside credentials.

**Decision:** Widening redaction scope is a change **against** the founding contract and carries the burden of proof. It
is not a safety improvement by default.

Three rules follow:

1. **Protocol structure is never PII.** Scheme tokens, cookie attributes, URL path shape and segment count, field names,
   JSON keys, MIME types, status codes, header names. Redaction replaces *values*; it must not alter the shape a
   consumer parses. When a value must be redacted in a structural position, the placeholder occupies that position — the
   structure survives.
1. **A "redact more" proposal names the concrete leak it closes and the fidelity it costs.** "Safer" is not a rationale.
   If the fidelity cost cannot be stated, the analysis is incomplete.
1. **Redaction driven by value shape rather than by label must prove the value cannot be legitimate data.** The bar is
   *cannot be structure*, not *scores high on entropy*. `GetDeviceInformation` and `configurationSettings` are the
   canonical counterexamples — both are long, both are opaque to a naive detector, both are URL path segments. They are
   why `_LONG_TOKEN_PATTERN` requires mixed letters *and* digits at 32+ characters.

**Relationship to invariant 11:** [`SANITIZATION_SPEC.md`](specs/SANITIZATION_SPEC.md#constraints--invariants) invariant
11 governs *confidence* — what may auto-redact without user review. This ADR governs *scope* — what is eligible to be
considered PII at all. A change can clear invariant 11 (100% confident the value is what we think it is) and still fail
this ADR (the thing we are certain about is protocol structure). Both gates apply.

**Consequence:** Some real secrets remain in captures until the user redacts them at review. That is the accepted trade:
the two-pass model (ADR-6) exists to route exactly these cases to a human, and an over-redacted HAR fails silently in a
way an under-redacted one does not — the user sees flagged values and decides, but nobody sees fidelity that was
destroyed before the file left their machine.

This ADR does **not** constrain changes that widen *detection and flagging*. Surfacing more candidates for review costs
no fidelity; `safe_value_patterns` is the release valve when a shape proves benign.

## ADR-13: High-Confidence Vendor Serial Formats Are Deterministic — Auto-Redact and Validate-Error, Delimiter-Aware

**Context:** A vendor serial can sit where no label names it: Netgear's `RouterStatus.htm` serves it inside a
pipe-delimited blob (`var tagValueList = '1.01|V6.01.03|<serial>|…'`), where the labeled serial passes have nothing to
anchor on. The heuristic engine flags it for review, but FLAG mode keeps the raw value in the on-disk artifact until the
review completes, so a skipped or unfinished review ships the serial — and a validator whose serial checks all need a
label reports the file clean. A CM2500 capture made by following the contributor instructions exactly shipped its serial
that way.

**Decision:** A `serial_number` detector declared at **high** confidence in a domain pattern file asserts a known vendor
serial layout and is treated as deterministic by both tools:

- **Sanitize** auto-redacts a fullmatch on a delimiter-bounded candidate token (`redact_vendor_serials`, HTML engine
  pass 2e plus the non-HTML text-content path), in every heuristic mode — Pass 1, before any artifact reaches disk.
- **Validate** reports an unredacted fullmatch on the same token extraction as an **error** (exit 1), from the same
  detector entries — the two tools cannot disagree because they share one pattern source
  (`patterns/domains/network_device.json`).

**ADR-12 accounting** (a "redact more" change carries the burden of proof):

- *Concrete leak closed:* unlabeled vendor serials in delimited firmware blobs, which the two-pass model otherwise
  routes to a human exactly when the human is told no action is needed.
- *Fidelity cost:* one token replaced by a correlation-preserving `SERIAL_<hash>` placeholder. Segment count, delimiter
  structure, and cross-entry correlation survive. Serial numbers are squarely the PII the tool exists to scrub — no
  consumer parses the serial's *value* as structure.
- *Cannot-be-structure proof:* the Netgear layout (13 uppercase alphanumerics: digit, 1–2 letters, 2–4 digits,
  alphanumeric tail) is digit-led — identifiers, method names, and protocol keywords are letter-led; pure counters carry
  no letters; the fullmatch-on-token rule rejects serial-shaped substrings of longer runs (hex, base64, compound
  identifiers).

**Confidence bar:** declaring `"confidence": "high"` on a `serial_number` detector *means* deterministic — it is
invariant 11's 100% bar expressed as data. A layout that cannot meet the bar stays at `medium` (flag for review). The
generic uppercase-alphanumeric backstop is `medium` for exactly this reason.

**Consequence:** the review never sees vendor-format serials (they are redacted before flagging), and a contributor who
skips the review still ships a serial-clean artifact for every layout the domain file knows. Unknown layouts stay where
ADR-12 puts them: flagged for the human.

## ADR-14: Structural Position, Not Value Shape, Identifies a Labeled Credential

**Context.** Technicolor gateways (XB6/XB7/XB8/XB10) render a "Device Label Information" block on `network_setup.jst`
carrying four sticker values in plain text: serial, WPS PIN, default Wi-Fi password and default SSID. The label and
value sit in sibling elements (`<span>Password:</span><span class="value">…</span>`), so a rule whose value class stops
at `<` never reaches the value, and a real default Wi-Fi password in such a capture has reached a public GitHub issue.

Neither label vocabulary nor value shape identifies these values: a bare tag chain `(?:<[^>]*>\s*)*` hops into prose,
and the values look like any other token.

**Decision.** Credential and network-name labels are matched by **structural position**, not by value shape and not by a
bare tag chain.

1. **The value must occupy its own element, as a single whitespace-free token.** Label element closes, value element
   opens, the value is that element's entire text content and contains no whitespace. The element rule distinguishes a
   sticker value from help-text prose: `$.i18n("<strong>Password:</strong> Enter the Password you registered")` shares a
   text node with its label, while `<span class="value">` does not. The single-token rule keeps ordinary gateway markup
   — `<dt>Password:</dt><dd>Not set</dd>`, `<div class="hint">Must be at least 8 characters</div>` — which the element
   rule alone would redact. Every real sticker value across the fleet is one token; every prose and status false
   positive is not.

   This carries a deliberate cost: **an SSID containing a space is not matched by these rules.** A space-bearing element
   text cannot be told apart from prose structurally, and under ADR-12 the burden of proof falls on redacting rather
   than on preserving — destroying gateway UI copy is the worse failure.

1. **Where no label exists, the naming element is the anchor.** An SSID rendered in `<font class="wifi_ntwrk">` or as
   the options of `<select id="mac_ssid">` has no adjacent label at all. The element that names itself an SSID holder
   supplies the anchor instead.

1. **One pattern source, three consumers.** The patterns are defined once in `sanitization/html.py` and imported by
   `validation/secrets.py` and `check_for_pii`. Importing rather than restating keeps the label/value layer from
   diverging between the tools.

1. **A labeled password is an error; a network name is a warning.** The label states outright that the value is a
   credential, so an unredacted match is deterministic in ADR-13's sense. An SSID identifies a network rather than
   authenticating to it.

The label/value text does not go through the heuristic engine: on the Technicolor captures it flags about a quarter of
all label/value pairs — `System Uptime`, `DHCP Lease Time`, `BOOT Version`, `Model` — which `REDACT` would destroy and
`FLAG` would flood the review with.

**ADR-12 accounting** (a "redact more" change carries the burden of proof):

- *Concrete leak closed:* a plaintext default Wi-Fi password, plus the default and live SSIDs that make it usable.
- *Fidelity cost:* four values per affected page, replaced by correlation-preserving `PASS_<hash>` / `WIFI_<hash>`
  placeholders. Markup and whitespace are re-emitted verbatim, so sanitized fixtures keep their DOM structure and parser
  tests still exercise the same selectors.
- *Cannot-be-structure proof:* the rule fires only where a credential label or an SSID-naming attribute already declares
  the value's meaning, and only on a single-token value that is not a known-safe status word. Across the committed fleet
  the rules touch only the credentials and network names, and nothing else.

**Symmetry requirement.** Every check `validate` makes must be one a sanitize run can clear. `validate` checks every
response body, while `sanitize_html` runs only for HTML/XML mime types, so the structural pass is exposed as
`redact_structural_credentials()` and applied to non-HTML text bodies too — a device-label block embedded in a `.js`
body is redacted, not reported as an error nothing can remove. A check that can fail with no remediation path is worse
than no check.

**Consequence.** A capture of any Technicolor gateway in the family is sticker-clean without review, and `validate`
fails (exit 1) rather than blessing a plaintext credential. Every guard exists against a reproduced false positive and
is load-bearing: no bare `key` (`metaKey` in minified jQuery); no `<th>` ("Source SSID Index"); no trailing-separator
text (`<span id="priwifinet">Private Wi-Fi Network- </span>`); no whitespace in the value (hint and status text); no
known-safe status word (`Enabled`, `Disabled`, `N/A`); no bare integers (row indices); no `<option value="">` (chooser
placeholders like `-- Select --`); no attribute whose SSID token carries a helper suffix (`ssid_help`, `ssid-label`,
`ssidTitle`); and no already-redacted value (re-sanitizing must not churn placeholders).

## ADR-15: Repeated Requests Are Never Collapsed

**Context.** A capture routinely holds the same request more than once, and the repeats are not redundant: they differ
in outcome or content, and the difference is often the evidence.

1. A POST to the same endpoint with a different body carries different data (an Arris S33 `GetMultipleHNAPs` call
   carrying the channel data).
1. A failed fetch can precede a successful one: an Arris SB8200 capture holds `GET cmswinfo.php` as `status: -1`,
   `net::ERR_ABORTED`, while the page rendered in the browser and is served `no-store`.
1. cable_modem_monitor's `MODEM_REQUEST.md` asks contributors to open a status page *before* logging in and to visit
   every status page after; on a device whose data URLs carry no token, both visits share `(GET, url)`, and on a CM2500
   both answer `200`.
1. The Basic Auth 401 and its authenticated retry are a `GET` to the same URL (ADR-2).

**Decision.** Repeated requests are never collapsed. `filter_and_compress_har()` filters by file type (the
`CaptureOptions` bloat extensions) and nothing else; every other entry survives in recorder order.

No key identifies a redundant repeat. Keying on the request misses a differing outcome; keying on the full outcome —
status, `_failureText`, a body hash — still discards headers that carry evidence (a fresh `Set-Cookie` on each visit is
the session behavior a downstream integration has to model), and it cannot include headers without including `Date`,
which differs on every response. A capture is evidence; nothing in it is ours to discard on a guess.

**Consequence.** A page fetched repeatedly — polled by its own JavaScript, or revisited during the session — appears
once per fetch, so captures of busy pages are larger. The `removed_entries` stat, and the CLI's "Removed N bloat
entries" line, count file-type filtering alone.

## ADR-16: Transport Encoding Is Not Content

**Context.** A HAR body carries `encoding: base64` when the recorder could not store it as a string — the bytes were not
UTF-8, or the type was not one the recorder treats as text. That base64 is the recorder's, not the server's. Read as if
the server had sent it, an Arris SB8200 HTML fragment served as `application/octet-stream` looks like
`base64(user:pass)` whenever the fragment holds a colon, and a fragment without one passes every pass unscanned — while
a validator that decodes the body reports PII no sanitize run removes, the failure ADR-14 forbids.

**Decision.**

1. **Both tools decode through one function** (`decode_transport_body`): the mime type's charset, else strict UTF-8.
   When that fails under a text type, the bytes are read as latin-1 — capture stores a page base64 exactly when its
   bytes are not UTF-8, whatever charset it declares, and latin-1 maps every byte, so none is lost.
1. **A decoded body is written back as plain text, `encoding` dropped.** Re-encoding would keep the body out of reach of
   the passes that replace text where it sits — Pass 1b propagation and Pass 2's review replacement — and a consumer
   that reads HAR reads both forms. The server sent the bytes, not the base64, so the representation is not evidence. An
   `AUTH_<hash>` placeholder under `encoding: base64`, which no decoder accepts, loses the marker.
1. **Binary stays as recorded, and neither tool scans it.** Bytes that are not text under any of the rules above are not
   a body either tool can reason about; a check on replacement characters would report what no sanitize run clears.

**ADR-12 accounting.** See
[Sanitization Spec — Response Content Dispatch](specs/SANITIZATION_SPEC.md#response-content-dispatch): the leak closed
is PII in transport-encoded and untyped bodies that `validate` reports; the fidelity cost is the recorder's base64
representation (for a latin-1 read, text that stands in for non-UTF-8 bytes, recoverable by encoding it as latin-1); the
engines' rules are the same for every body.

**Consequence.** A sanitized HAR carries `encoding` only on binary bodies. A transport-encoded body whose text is
literally `user:pass` is not replaced: the base64 that would match is the recorder's, and the same text served as plain
text is not replaced either.

## ADR-17: A Device CA's Certificate Name Is a Device Identity

**Context.** A HAR recorded by Chromium or Playwright carries `_securityDetails` on each TLS entry: `protocol`,
`subjectName`, `issuer`, `validFrom`, `validTo`. Across the CMM fleet, 8,391 entries name the device in `subjectName`:
5,913 by a colon MAC under a CableLabs device or cable-modem CA (four distinct MACs, all with vendor-assigned prefixes),
and 2,478 by a bare 12-hex ID under an HWROB or SWROB device sub-CA (six distinct values, all prefixed `0000`, none
appearing as a MAC anywhere in its capture, so possibly an ID rather than a MAC). A further 13,444 entries are
self-signed: 7,568 with an empty name, the rest under nine distinct names — model names, vendor hostnames,
`localhost.localdomain`, one already a placeholder — each seen in two to six model directories.

**Decision.**

1. **`subjectName` and `issuer` are a device identity field.** A name that is wholly a MAC in any layout — separated,
   bare or dotted, as under a MAC-named JSON key — and a colon or hyphen MAC inside a name, is hashed in place with
   `hash_mac`, in its own layout, so it correlates with the same MAC elsewhere in the capture. The bare-hex IDs are
   hashed whatever they turn out to be: a device CA issues a certificate to one device, and its name identifies that
   device either way. One predicate, `certificate_name_macs()`, decides for both tools; `validate` reports an unredacted
   one as an error and recognizes a MAC placeholder in these fields only.
1. **A self-signed name without a MAC is offered for review** (`device_name`, LOW, once per distinct value), not
   redacted. Every such name in the fleet is firmware text, but nothing distinguishes it from a name a device's owner
   set, so ADR-12 sends it to review. `localhost` and `localhost.localdomain` are kept unoffered. `validate` does not
   report these names: sanitize does not clear them.
1. **`protocol`, `validFrom`, `validTo` and the entry's `serverIPAddress` are kept.** Across the fleet `serverIPAddress`
   holds the device's LAN address (25,592 of 25,610 private addresses equal the URL's host) or a public server reached
   by hostname (19); none is the owner's own public address, so redacting it would cost fidelity and close no leak.

**ADR-12 accounting.** The leak closed is the device MAC or device-CA ID in 8,391 certificate names. The fidelity cost
is the certificate's subject text; the certificate's issuer, protocol and validity survive, and a hashed MAC keeps its
layout.

**Consequence.** Only `_securityDetails` on the entry is read; the fleet holds it nowhere else. A certificate name the
user chooses to redact in the review is replaced by Pass 2 everywhere it occurs, a model name in page text included.

## ADR-18: Sanitize and Validate Are Two Walkers; the Symmetry Harness Enforces Agreement

**Context.** `sanitize` (`sanitization/har.py`, `html.py`) and `validate` (`validation/secrets.py`) each walk the HAR
and apply their own rules. A new vocabulary word is a pattern-file edit; a new leak shape touches both walkers and
usually a shared predicate in `patterns/redaction.py`. The two can disagree — `validate` reporting a value no sanitize
run clears, or sanitize removing a value `validate` never checks — which ADR-14 forbids.

**Decision.** Agreement is enforced by the ADR-14 symmetry harness (`tests/test_symmetry.py`), not by construction:
every leak either tool knows has a row (a raw HAR with one leak), and the harness requires `validate` to report it and
every heuristic mode of `sanitize` to clear it. Where a decision can be one function, both tools call it
(`classify_identity_field`, `cookie_segment_actions`, `certificate_name_macs`, `check_har_types`, the compiled
HTML-engine regexes `check_for_pii` shares).

Two ways of reaching the same answer are a strength, not duplication: `validate` independently re-derives what sanitize
should have removed, so a sanitizer bug shows up as a finding instead of passing silently, and the harness turns any
disagreement between them into a failing row. A single rule registry run in redact and check modes would make
disagreement impossible by construction, and would give up that independent check.

**Consequence.** A change that widens either tool adds harness rows in the same commit. A rule a shared predicate can
express lives in `patterns/redaction.py` and is called by both tools; one that cannot is written twice and pinned by
harness rows.

## ADR-19: In Script Code, Only a Literal Follows a Credential Label

**Context.** The labeled passes (`password_field`, `session_token`, the bare-`key` offer) read the text after a label as
the secret. In JavaScript that text is usually code: `sjclEncryptObj.password = password;`,
`{username: username.value, password: password.value}`, `password: {` in a validate rules block,
`if (currentpassword == 0)`. Replacing it destroys the code a reader needs — on an Arris TG3442S login page the value
after `key` is the key-derivation call (`sjclEncryptObj.key = sjcl.misc.pbkdf2(password, …)`), the fact the capture
exists to show. A regex cannot tell `password = pw;` in code from `"a=b; password=hunter2;"` in a string: the difference
is where the text sits, not what it looks like.

**Decision.** A labeled value's position decides whether it is a literal (`labeled_literal`, on `script_code_spans`):

1. **In script code an unquoted value is kept unless it is a number.** Script code is a JavaScript `<script>` body, or a
   whole body that opens as JavaScript, less its strings, comments and regex literals. A number there is replaced up to
   its end, so the punctuation after it stays.
1. **A quoted value is always a literal.** It sits inside the string its quote opens, which is data.
1. **Outside script code a bare token is a literal**: markup text, attributes, URLs, a JS string's contents.
1. **What the scanner cannot place is data.** An unclosed `<script>`, a non-JavaScript `type`, a `<script>` inside an
   HTML comment, a broken tag, and a string unterminated at its line end are data, so a misread redacts rather than
   keeps.
1. **Both tools apply it.** The sanitizer's passes and `check_for_pii` call the same function, so a kept code value is
   neither replaced nor reported.

**ADR-12 accounting.** This narrows redaction. *Leak opened:* none observed — across the fleet's 848 parseable script
bodies the scanner reads no string, comment or regex character as code (checked against the acorn tokenizer), and a
JavaScript identifier is by definition not a string literal. *Accepted limit:* a regex literal directly after `)` or `]`
that holds a quote is read as division, which can expose one line's string contents as code; the fleet has none.
*Fidelity restored:* identifiers, members, objects and comparisons after a credential label survive, as does the
punctuation after a replaced number.

**Consequence.** Code after `password`, `key` and `token` labels in inline and served-as-HTML scripts survives
sanitization; quoted secrets, secrets in strings and secrets in markup are replaced as before. Captures already
sanitized keep their damage — the original text is not recoverable.
