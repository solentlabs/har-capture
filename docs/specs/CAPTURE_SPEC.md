# Capture Spec

## Purpose

This spec describes the full Playwright-based capture lifecycle — from browser launch through HAR recording to post-capture filtering and compression. An engineer modifying the capture subsystem should read this document to understand how the wait-for-data mechanism works, how browser state is captured and injected, and how the phased workflow gates each step.

## Key Files

| File                                      | Role                                                                                                               |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `src/har_capture/capture/browser.py`      | Core capture orchestration: Playwright session, wait-for-data, HAR recording, state capture, filtering/compression |
| `src/har_capture/capture/workflow.py`     | Multi-phase workflow: browser check → connectivity → probes → auth → capture                                       |
| `src/har_capture/capture/probes.py`       | Pre-capture diagnostics: auth challenge, HEAD support, ICMP ping                                                   |
| `src/har_capture/capture/connectivity.py` | Reachability check, protocol auto-detection (TCP+TLS probe), Basic Auth detection                                  |
| `src/har_capture/capture/deps.py`         | Browser installation and system dependency checking                                                                |
| `src/har_capture/cli/capture.py`          | CLI `har-capture get` command, interactive prompts                                                                 |

## Workflow Phases

The capture workflow (`workflow.py`) orchestrates six sequential phases. Each phase returns a result object; the workflow stops at the first failure.

### Phase 1: Browser Check (`check_browser_phase`)

```python
result = check_browser_phase(browser="chromium")
# result.browser.needs_install: bool
```

Calls `check_browser_installed()` from `deps.py`. If the browser is missing, the CLI prompts the user to download it (~150 MB). If system libraries are missing (libasound, libnss3, libnspr4), error messages are pattern-matched against `_MISSING_DEPS_PATTERNS` and the user is told which packages to install.

### Phase 2: Connectivity Check (`check_connectivity_phase`)

```python
result = check_connectivity_phase(target, result)
# result.connectivity.ok: bool
# result.connectivity.scheme: str ("http" or "https")
# result.connectivity.target_url: str
```

`check_device_connectivity()` in `connectivity.py` sends an unauthenticated GET request via stdlib urllib:

1. Parse target via `_parse_target()` — handles URLs with schemes (including IPv6 with brackets, ports)
1. If no scheme is provided, run `detect_protocol()` (see below) to choose between HTTP and HTTPS via TCP+TLS probes; if both transports fail, return the detection error
1. Send a single GET to `{scheme}://{host}/` (using either the provided or detected scheme)
1. Any response (including 401/403) = reachable
1. Self-signed certificates accepted via `make_ssl_context()` (`check_hostname=False, verify_mode=CERT_NONE`)

Returns `(reachable, scheme, error)`. Explicit schemes bypass auto-detection — the user has chosen.

#### Protocol auto-detection (`detect_protocol`)

Stdlib-only protocol probe used when the target lacks an explicit scheme. Probes TCP `:80` and `:443`; if `:443` accepts a TCP connection *and* completes a TLS handshake, HTTPS wins — devices that expose both ports almost always intend HTTPS for authenticated traffic, and `:80` is typically a redirect or legacy stub. The handshake uses a `SECLEVEL=0` cipher context so it completes against legacy devices (TLS 1.0/1.1, 3DES/RC4) — this tolerance is load-bearing: without it, the probe would false-fail HTTPS on old modems and capture HTTP instead. `getaddrinfo` defaults to `AF_INET` (protects against dual-stack false-fail on IPv4-only LAN devices); bracketed IPv6 input (`[::1]:8443`) auto-selects `AF_INET6` so v6-only targets are not silently dropped. Scheme matching is case-insensitive. If the user supplies an explicit `:port` (e.g. `127.0.0.1:8443`), only that port is probed. Returns a `ProtocolDetectionResult` with `success`, `protocol`, `working_url`, and `error`. The negotiated TLS version is logged for diagnostics but not classified or surfaced — har-capture cannot act on it (Chromium runs its own TLS stack); see ADR-10 for the rationale. Adapted from `cable_modem_monitor_core/connectivity.py` and intentionally duplicated rather than shared so har-capture's runtime stays stdlib-only.

### Phase 3: Session Contamination Check (`check_session_phase`)

```python
result = check_session_phase(target_url, result)
# result.session.contaminated: bool
# result.session.message: str | None
```

`check_session_contamination()` in `connectivity.py` makes an unauthenticated GET to the target URL and inspects the response to detect whether the device has a live session that would cause the capture to miss the login flow.

1. If the response is non-200 (401, 403, redirect) → clean state, auth is required
1. If the response is 200 with a body under 100 bytes → clean (redirect stub)
1. If the response body contains login-page indicators (`password`, `login`, `sign in`, `signin`, `log in`, `authenticate`) → clean, login page is being served
1. If the response is 200 with substantial content and no login indicators → **contaminated** — the device is serving authenticated content without requiring login

When contamination is detected, the workflow aborts with: *"Browser has a live session — clear cookies or use a clean profile."*

Skipped in `--minimal` mode and when `skip_session_check=True`.

### Phase 4: Probes (`run_probes_phase`)

```python
result = run_probes_phase(target_url, timeout=10, result=result)
# result.probes.data: dict with auth_challenge, head_support, icmp keys
```

> **CLI behavior:** The CLI only runs the auth probe, and only when `--username`/`--password` is provided (see [ADR-3](../ARCHITECTURE_DECISIONS.md#adr-3-probes-are-opt-in-diagnostics)). When Playwright's `http_credentials` is set, it suppresses the 401 response in the HAR — the auth probe captures that data before suppression. Without credentials, the browser shows the native auth dialog and the full 401 exchange is recorded in the HAR naturally.
>
> **Library API:** `run_capture_workflow()` runs all three probes by default. Pass `skip_probes=True` to skip.

`run_probes()` in `probes.py` runs three independent probes:

**Auth Challenge Probe** (`probe_auth_challenge`):

- Unauthenticated GET (no redirect following via `_NoRedirectHandler`)
- Captures: status code, `WWW-Authenticate` header, `Set-Cookie` headers (list), all response headers, first 1024 chars of body
- Handles `HTTPError` (401, 403) and `URLError` (connection refused)

**HEAD Support Probe** (`probe_head_support`):

- HEAD request to target
- Any HTTP response (2xx–5xx) = supported
- Connection error = not supported

**ICMP Probe** (`probe_icmp`):

- Platform-specific ping command:
  - Linux: `ping -c 1 -W <seconds> <host>`
  - macOS: `ping -c 1 -t <seconds> <host>`
  - Windows: `ping -n 1 -w <milliseconds> <host>`
- Parses latency from stdout regex: `time[=<](\d+\.?\d*)\s*ms`
- Timeout: half the overall probe timeout

Probe results are embedded in the HAR output as `_probes` for downstream consumption.

### Phase 5: Auth Detection (`check_auth_phase`)

```python
result = check_auth_phase(target_url, result)
# result.auth.requires_basic_auth: bool
# result.auth.realm: str | None
```

> **CLI behavior:** The CLI no longer calls `check_auth_phase`. In interactive mode, Playwright shows a native Basic Auth dialog when the device responds with 401 — the user enters credentials in the browser and the full auth exchange is captured in the HAR (see [ADR-2](../ARCHITECTURE_DECISIONS.md#adr-2-minimal-pre-flight-in-interactive-mode)). When `--username`/`--password` is provided, credentials are passed directly to Playwright's `http_credentials` without auth detection.
>
> **Library API:** `run_capture_workflow()` runs auth detection by default and returns early if Basic Auth is detected without credentials (so the caller can prompt). Pass `skip_auth_check=True` to skip.

`check_basic_auth()` in `connectivity.py`:

1. Send unauthenticated GET to target URL
1. On 401 status: check `WWW-Authenticate` header
1. If header starts with "basic" (case-insensitive): extract realm, return `(True, realm)`
1. Non-Basic auth (Bearer, Digest): return `(False, None)`
1. Non-401 response or error: return `(False, None)`

### Phase 6: Capture (`run_capture_phase`)

Calls `capture_device_har()` from `browser.py` with all accumulated state (credentials, probe data, patterns).

## Minimal Mode (`--minimal`)

Some devices allow only one concurrent HTTP connection (e.g., Compal CH7465MT). The original capture workflow made 5 pre-Playwright HTTP requests (connectivity, auth challenge probe, HEAD probe, auth detection, plus a duplicate connectivity check inside `capture_device_har()`), which exhausted the session slot before the browser opened. The refactored default makes 1–2 requests. The `--minimal` flag goes further by deferring the connectivity check into `capture_device_har()` and skipping everything else.

### What `--minimal` Does

| Behavior                           | Default                       | Default + `--username/--password` | `--minimal`        |
| ---------------------------------- | ----------------------------- | --------------------------------- | ------------------ |
| Connectivity check                 | Yes (1 GET)                   | Yes (1 GET)                       | Yes (1 GET)\*      |
| Session contamination check        | Yes (1 GET)                   | Yes (1 GET)                       | **Skipped**        |
| Auth probe                         | Skipped                       | Yes (1 GET)                       | **Skipped**        |
| `page.goto` wait strategy          | `networkidle` (auto-fallback) | `networkidle` (auto-fallback)     | `domcontentloaded` |
| Wait-for-data (XHR/fetch tracking) | Enabled                       | Enabled                           | **Disabled**       |
| Pre-Playwright HTTP requests       | 2                             | 3                                 | 1\*                |

\* In `--minimal` mode, the CLI skips the connectivity check. `capture_device_har()` runs it internally when no `target_url` is provided — still 1 GET, but inside the capture function rather than as a separate CLI phase.

The connectivity check is preserved in all modes because it determines `http` vs `https` and validates the device is reachable before launching Playwright.

> **Library API note:** `run_capture_workflow()` still runs session check (Phase 3), probes (Phase 4), and auth detection (Phase 5) by default for backward compatibility. Use `skip_session_check=True`, `skip_probes=True`, and `skip_auth_check=True` to match the CLI's minimal-pre-flight behavior.

### `target_url` Parameter

When the CLI workflow completes Phase 2, `target_url` (e.g., `http://192.168.100.1/`) is already known. Passing it to `capture_device_har()` eliminates the duplicate internal connectivity check that previously ran at the start of the function. This optimization applies to **all** capture modes, not just `--minimal`.

### `page_load_strategy` Parameter

Controls the `wait_until` argument to Playwright's `page.goto()`. Accepts any Playwright-supported value: `"networkidle"` (default), `"domcontentloaded"`, `"load"`, `"commit"`. In `--minimal` mode, `"domcontentloaded"` is used because devices with persistent polling/heartbeat connections prevent `networkidle` from ever being satisfied.

## Browser Capture Detail

### Internal Decomposition

`capture_device_har()` is the public API — its signature is unchanged. Internally, it delegates to five extracted functions that can each be tested independently:

```
capture_device_har()
├── Pre-flight checks (check_playwright, check_browser_installed)
├── _resolve_capture_paths()   → CapturePathInfo
├── _run_browser_session()     → BrowserSessionResult
├── _patch_missing_bodies()    → patches temp HAR in-place
├── _inject_har_metadata()     → modifies temp HAR in-place
└── _run_post_capture_pipeline() → CaptureResult
```

Error recovery (missing browser/deps detection and retry) stays inline in `capture_device_har()` as local helpers.

#### `_resolve_capture_paths(ip, output, target_url) -> CapturePathInfo`

Pure filesystem + parsing logic. Resolves the output path (auto-generates if None), ensures `.har` suffix, creates parent directories, parses the target hostname, determines the sanitized output path, and creates the temp file via `mkstemp()`. Returns a `CapturePathInfo` dataclass.

Testable with: zero mocks.

#### `_run_browser_session(...) -> BrowserSessionResult`

Everything that touches Playwright: launch browser, configure context (storage state, credentials, HAR recording), navigate with networkidle/domcontentloaded fallback, wait-for-data, capture cookies/storage, handle timeout vs interactive mode, close browser. Returns `BrowserSessionResult` with all captured browser state — eliminates the `nonlocal` pattern used previously to shuttle data out of a nested closure.

Testable with: one mock (`sync_playwright`).

#### `_inject_har_metadata(temp_path, target_url, probes, session)`

Reads the raw HAR from the temp file, injects `_probes`, `_har_capture` (cookies, storage), and `_solentlabs` (pre-capture cookies), writes back. Handles corrupt/unreadable HAR gracefully.

Testable with: zero mocks (real temp file).

#### `_run_post_capture_pipeline(...) -> CaptureResult`

Runs sanitization, copies raw HAR if needed, cleans up temp file, compresses. The temp file is always deleted.

Testable with: zero Playwright mocks (one mock for `sanitize_har_file` if isolating, or zero mocks with a real fixture).

### `capture_device_har()` Signature

```python
def capture_device_har(
    ip: str,                                          # Target URL/IP/hostname
    output: str | Path | None = None,                 # Output path (auto-generated if None)
    browser: str = "chromium",                        # Browser engine
    http_credentials: dict[str, str] | None = None,   # {"username": ..., "password": ...}
    sanitize: bool = True,                            # Run sanitization
    compress: bool = True,                            # Create .har.gz
    keep_raw: bool = False,                           # Preserve unsanitized HAR
    include_fonts: bool = False,                      # Include font entries
    include_images: bool = False,                     # Include image entries
    include_media: bool = False,                      # Include media entries
    headless: bool = False,                           # Run without visible browser
    timeout: int | None = None,                       # Seconds to wait (None = interactive)
    interactive: bool = True,                         # Flag suspicious values for review
    probes: dict[str, Any] | None = None,             # Probe results to inject
    custom_patterns: str | dict[str, Any] | None = None,  # Sanitization patterns
    wait_for_data: bool = True,                       # Enable async data tracking
    target_url: str | None = None,                    # Pre-computed URL (skips internal connectivity check)
    page_load_strategy: str = "networkidle",          # Playwright wait_until for page.goto
) -> CaptureResult
```

### `CaptureResult` Dataclass

```python
@dataclass
class CaptureResult:
    har_path: Path | None         # Raw HAR path (None if deleted after sanitization)
    compressed_path: Path | None  # .har.gz path
    sanitized_path: Path | None   # Sanitized HAR path
    stats: dict[str, Any]         # Entry/size metrics
    success: bool
    error: str | None
    sanitization_report: SanitizationReport | None
```

### `CapturePathInfo` Dataclass

```python
@dataclass
class CapturePathInfo:
    output_path: Path       # User-facing HAR output path
    sanitized_output: Path  # Path for sanitized HAR (stem + .sanitized.har)
    temp_path: Path         # Temp file path for raw HAR (PII, always deleted)
    host: str               # Extracted hostname from target
    target_url: str         # Full URL for navigation
```

### `BrowserSessionResult` Dataclass

```python
@dataclass
class BrowserSessionResult:
    pre_capture_cookies: list[Any]           # Cookie jar state before navigation
    browser_cookies: list[Any]               # Cookies after page load
    web_storage_local: list[dict[str, Any]]  # localStorage entries per origin
    web_storage_session: dict[str, str]      # sessionStorage key/value pairs
    captured_bodies: dict[str, bytes]        # Eagerly captured response bodies
    success: bool
    error: str | None
```

### Context Configuration

```python
context = browser_type.new_context(
    record_har_path=temp_file,        # Secure temp file via mkstemp()
    record_har_content="embed",       # Base64-encode response bodies in HAR
    ignore_https_errors=True,         # Accept self-signed device certs
    service_workers="block",          # Prevent caching interference
    storage_state={                   # Force clean context — no inherited state
        "cookies": [],
        "origins": [],
    },
    http_credentials=http_credentials # Basic Auth credentials (if any)
)
```

Design decisions:

- **Clean storage state**: `storage_state={"cookies": [], "origins": []}` forces an empty cookie jar and localStorage. Without this, some Playwright configurations inherit cookies or `httpCredentials` from launch options, causing the first request to carry session artifacts (e.g., `Secure`, `XSRF_TOKEN`, `PHPSESSID`, `Authorization`). This prevents all 6 failure signatures identified in the MCP intake pipeline.
- **Temp file for raw HAR**: Created via `tempfile.mkstemp()` — raw PII is never written to the user's directory. The FD is closed but the path is kept for Playwright.
- **Embedded content**: `record_har_content="embed"` base64-encodes response bodies within the HAR JSON, avoiding external file management.
- **Service worker blocking**: `service_workers="block"` prevents cached responses from interfering with fresh device captures.
- **HTTPS tolerance**: Device hardware commonly uses self-signed or expired certificates.

### Pre-Capture Cookie Audit

Immediately after context creation and before any navigation, `context.cookies()` is called and the result is stored as `pre_capture_cookies`. After the browser closes, this list is injected into the HAR at `log._solentlabs.pre_capture_cookies`.

With the clean `storage_state`, this list should always be empty. A non-empty list indicates the context inherited cookies despite the explicit clean state — a signal for downstream tools that the capture may be contaminated.

```json
{
  "log": {
    "_solentlabs": {
      "pre_capture_cookies": []
    }
  }
}
```

### Wait-for-Data Mechanism

#### Problem

Playwright's `wait_until="networkidle"` waits for 500ms of network silence after page load. For SPA-style device interfaces that fire XHR/fetch calls 1-2 seconds after the initial page renders, this is too short — the HAR misses async data loads.

#### Solution: JS Init Script Injection

When `wait_for_data=True`, an init script is injected via `page.add_init_script()`:

```javascript
(function() {
    let p = 0;
    // Monkey-patch XMLHttpRequest.prototype.send
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        p++;
        this.addEventListener('loadend', () => { p = Math.max(0, p - 1); });
        return origSend.apply(this, arguments);
    };
    // Monkey-patch window.fetch
    const origFetch = window.fetch;
    window.fetch = function() {
        p++;
        return origFetch.apply(this, arguments).finally(() => { p = Math.max(0, p - 1); });
    };
    // Expose counter as a property
    Object.defineProperty(window, '__harCapturePendingRequests', { get: () => p });
})();
```

Key details:

- Counter `p` tracks in-flight XHR/fetch requests
- `Math.max(0, p - 1)` prevents negative counts from race conditions
- `Object.defineProperty` with getter allows Playwright to read the counter via `page.evaluate()`
- Injected before any page JS runs (init script)

#### Navigation Event Listener

A `framenavigated` event listener ensures async data completes before page transitions:

```python
def _on_frame_navigated(frame):
    if frame != page.main_frame:
        return
    if _is_first_nav[0]:
        _is_first_nav[0] = False
        return  # Initial goto — handled by explicit quiescence wait below
    page.wait_for_load_state("domcontentloaded")
    _wait_for_network_quiescence(page)
```

This creates a waterfall effect:

1. Page A loads and fires async XHR/fetch
1. User clicks a link to Page B
1. Navigation triggers `framenavigated` event
1. Listener waits for DOM content loaded, then polls for network quiescence
1. Page B's init script starts tracking its own pending requests

The `_is_first_nav` flag skips waiting on the initial `page.goto()` (handled by the explicit quiescence wait after `goto`).

Note: this uses a page event (not a route handler) because calling `page.evaluate()` from a sync route handler deadlocks Playwright's dispatch loop.

#### Network Quiescence Polling

After `page.goto()`, the system calls `_wait_for_network_quiescence()`:

```python
def _wait_for_network_quiescence(page, quiescence_s=2.0, timeout_s=30.0):
    last_active = time.time()
    while True:
        pending = page.evaluate("window.__harCapturePendingRequests")
        now = time.time()
        if pending > 0:
            last_active = now
        elif now - last_active >= quiescence_s:
            break  # Quiet for long enough
        if now - start > timeout_s:
            break  # Overall timeout
        page.wait_for_timeout(_DATA_WAIT_POLL_MS)
```

This is more robust than Playwright's `networkidle` (500ms) — it waits for `_DATA_WAIT_QUIESCENCE_S` (2.0 seconds) of zero pending requests.

#### Timing Constants

| Constant                   | Value | Purpose                            |
| -------------------------- | ----- | ---------------------------------- |
| `_DATA_WAIT_QUIESCENCE_S`  | 2.0s  | How long pending must stay at zero |
| `_DATA_WAIT_TIMEOUT_S`     | 30.0s | Max total wait per page            |
| `_DATA_WAIT_NAV_TIMEOUT_S` | 15.0s | Max wait in navigation listener    |
| `_DATA_WAIT_POLL_MS`       | 200ms | Poll interval for checking counter |

#### `--no-wait-for-data` Behavior

When disabled, no JS injection, no quiescence polling, and no `framenavigated` listener. `page.goto()` with `wait_until="networkidle"` is the only wait mechanism. The eager response body capture listener (`page.on("response")`) is always active regardless of this flag.

### Eager Response Body Capture

#### Problem

Playwright's `record_har_content="embed"` captures response bodies lazily — it calls CDP `Network.getResponseBody` when `context.close()` flushes the HAR to disk. If a navigation event causes Chrome to evict the response data from its network buffer before the flush, the body is lost. Headers, sizes, and timing are correct (captured synchronously from Network domain events), but `content.text` is absent and `content.size` is `-1`.

This typically affects the initial page load (e.g., a login form) when the user or JavaScript submits a form quickly, triggering a navigation that supersedes the first response.

#### Solution: Eager Body Capture via Response Listener

Before navigation, a `page.on("response")` listener is registered that eagerly calls `response.body()` for text-based content types (`text/*`, `application/json`, `application/xml`). Bodies are stored in `BrowserSessionResult.captured_bodies` keyed by `"<method>|<url>|<status>"`.

After Playwright writes the HAR and before metadata injection, `_patch_missing_bodies()` scans HAR entries for responses that have `bodySize > 0` or `_transferSize > 0` but no `content.text`. For each missing body, it looks up the key in the captured bodies cache and patches the body into the HAR entry.

Text bodies are stored as plain UTF-8 strings. Non-UTF-8 bodies fall back to base64 encoding with `content.encoding = "base64"`.

#### `_patch_missing_bodies(temp_path, captured_bodies) -> int`

- Reads the raw HAR from `temp_path`
- For each entry missing `content.text` with `bodySize > 0` or `_transferSize > 0`: looks up `"<method>|<url>|<status>"` in `captured_bodies` and patches the body
- Writes the patched HAR back to `temp_path`
- Returns the number of entries patched
- Handles corrupt HAR files gracefully (returns 0)

Testable with: zero mocks (real temp file).

### Timeout vs Interactive Mode

**Timeout mode** (`timeout=N` in the Python API — not exposed as a CLI flag):

- If `wait_for_data=True`: Uses `page.wait_for_timeout(N * 1000)` (keeps Playwright event loop active so the JS counter continues tracking) followed by a final quiescence wait
- If `wait_for_data=False`: Uses `time.sleep(N)` (simpler, no event loop needed)
- Browser closes automatically after the timeout

**Interactive mode** (no timeout, default):

- Browser stays open until the user manually closes the window
- Uses `page.wait_for_event("close")` to block until closure
- Required for devices with in-browser auth (HNAP, form-based login) where the user needs to interact

### Browser State Capture

After navigation and before closing the context, three types of browser state are captured:

```python
# Cookies
cookies = context.cookies()
# → list of dicts with name, value, domain, path, expires, httpOnly, secure, sameSite

# localStorage
storage = context.storage_state()
# → dict with "origins": [{"origin": "...", "localStorage": [{"name": ..., "value": ...}]}]

# sessionStorage (via JS evaluation)
session_storage = page.evaluate("() => Object.entries(sessionStorage)")
# → list of [key, value] pairs
```

These are injected into the HAR as synthetic entries under `_har_capture` metadata keys:

- `_har_capture.browser_cookies`
- `_har_capture.local_storage`
- `_har_capture.session_storage`

This preserves state that wouldn't appear in the HTTP-level HAR recording.

### Error Recovery

The capture phase detects and handles two classes of recoverable errors:

**Missing browser executable** (`_MISSING_BROWSER_PATTERNS`):

- Patterns like "Executable doesn't exist" or "Failed to launch"
- Fix: Reinstall the browser via `playwright install <browser>`
- Retry once after fix

**Missing system dependencies** (`_MISSING_DEPS_PATTERNS`):

- Patterns like "libasound.so", "libnss3.so", "libnspr4.so"
- Fix: Install system deps via `playwright install-deps`
- Retry once after fix

Error messages are sanitized via `_sanitize_error_message()` to remove any embedded credentials before being returned to the caller.

## Post-Capture Processing

### Body Patching

Immediately after the browser closes and writes the raw HAR, `_patch_missing_bodies()` scans for entries with missing response bodies and patches them from the eagerly captured body cache. This runs before metadata injection and sanitization so that downstream processing sees complete responses.

### Metadata Injection

After body patching:

```python
har_data["log"]["_probes"] = probes_data
har_data["log"]["_har_capture"] = {
    "browser_cookies": cookies,
    "local_storage": local_storage,
    "session_storage": session_storage,
    "tool": "har-capture",
    "version": __version__,
    "captured_at": datetime.now(tz=timezone.utc).isoformat(),
    "cache_disabled": True,
    "service_workers_blocked": True,
}
har_data["log"]["_solentlabs"] = {
    "pre_capture_cookies": pre_capture_cookies,  # Cookie jar state before navigation
}
```

### Sanitization

The temp file is sanitized via `sanitize_har_file()`:

- `heuristics=HeuristicMode.FLAG` if `interactive=True`, else `DISABLED`
- Custom patterns applied if `--patterns` was specified
- Output written to `{output_path_stem}.sanitized.har`

### Filter and Compress (`filter_and_compress_har`)

```python
def filter_and_compress_har(har_path, options=None) -> (Path, dict):
```

1. **Add metadata**: `_add_capture_metadata()` writes tool info, timestamps
1. **Filter entries by extension**: Based on `CaptureOptions` flags:
   - `include_fonts=False` → filter .woff, .woff2, .ttf, .otf, .eot
   - `include_images=False` → filter .png, .jpg, .jpeg, .gif, .ico, .svg, .webp, .bmp
   - `include_media=False` → filter .mp3, .mp4, .wav, .webm, .ogg, .avi, .mov
   - Always filter: .map (sourcemaps)
1. **Deduplicate**: Remove entries with same method + URL
1. **Write filtered HAR**: Pretty-printed JSON
1. **Gzip compress**: Compression level 9, output to `.har.gz`
1. **Return stats**: Entry counts, sizes before/after

### File Cleanup

| Condition                     | Temp file | Raw HAR          | Sanitized HAR | Compressed  |
| ----------------------------- | --------- | ---------------- | ------------- | ----------- |
| Default (sanitize + compress) | Deleted   | Not created      | Deleted       | Kept        |
| `--keep-raw`                  | Deleted   | Copied from temp | Kept          | Kept        |
| `--no-sanitize`               | Deleted   | Copied from temp | Not created   | Kept        |
| `--no-compress`               | Deleted   | Not created      | Kept          | Not created |
| Interactive mode              | Deleted   | Not created      | Kept          | Kept        |

The raw temp file is **always** deleted regardless of flags, ensuring PII doesn't persist.

## `CaptureOptions` Dataclass

```python
@dataclass
class CaptureOptions:
    include_fonts: bool = False
    include_images: bool = False
    include_media: bool = False

    def get_bloat_extensions(self) -> set[str]:
        """Returns set of extensions to filter based on include flags."""
        # Always includes sourcemaps (.map)
        # Conditionally adds font/image/media extensions based on flags
```

## Constraints / Invariants

1. **Raw HAR never persists** — The temp file is deleted after sanitization, even if the process crashes (it's in `/tmp`).
1. **Sanitization runs before compression** — The compressed `.har.gz` always contains sanitized content.
1. **Browser state capture happens after navigation** — Cookies and storage are captured after `page.goto()` completes and any wait-for-data polling finishes.
1. **Phase ordering is strict** — Connectivity must be checked before auth, browser must be checked before capture. Reordering phases would break the workflow.
1. **Wait-for-data is opt-out** — `wait_for_data=True` is the default. Disabling it reverts to Playwright's basic `networkidle` wait.
1. **Init script runs before page JS** — The XHR/fetch monkey-patches are in place before any application JavaScript executes.
1. **Probes are optional metadata** — Probe failures do not stop the capture workflow. Probes always succeed (they catch all exceptions internally). Probes can be skipped entirely via `--minimal` for session-constrained devices.
1. **Error messages are credential-free** — Any username/password strings are replaced before errors are returned.
1. **Service workers are always blocked** — This is hardcoded in context config, not configurable, to ensure fresh captures.
1. **Self-signed certs are always accepted** — Both probes and Playwright context ignore certificate errors.
1. **Browser context is always clean** — `storage_state={"cookies": [], "origins": []}` is hardcoded. No cookies, localStorage, or credentials leak from previous sessions.
1. **Pre-capture cookie state is always recorded** — `_solentlabs.pre_capture_cookies` is emitted in every capture, even when empty. Downstream tools can verify context cleanliness without assumptions.
