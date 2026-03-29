# Capture Spec

## Purpose

This spec describes the full Playwright-based capture lifecycle — from browser launch through HAR recording to post-capture filtering and compression. An engineer modifying the capture subsystem should read this document to understand how the wait-for-data mechanism works, how browser state is captured and injected, and how the phased workflow gates each step.

## Key Files

| File                                      | Role                                                                                                               |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `src/har_capture/capture/browser.py`      | Core capture orchestration: Playwright session, wait-for-data, HAR recording, state capture, filtering/compression |
| `src/har_capture/capture/workflow.py`     | Multi-phase workflow: browser check → connectivity → probes → auth → capture                                       |
| `src/har_capture/capture/probes.py`       | Pre-capture diagnostics: auth challenge, HEAD support, ICMP ping                                                   |
| `src/har_capture/capture/connectivity.py` | Scheme detection, reachability, Basic Auth detection                                                               |
| `src/har_capture/capture/deps.py`         | Browser installation and system dependency checking                                                                |
| `src/har_capture/cli/capture.py`          | CLI `har-capture get` command, interactive prompts                                                                 |

## Workflow Phases

The capture workflow (`workflow.py`) orchestrates five sequential phases. Each phase returns a result object; the workflow stops at the first failure.

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

`check_device_connectivity()` in `connectivity.py` sends unauthenticated GET requests via stdlib urllib:

1. Parse target via `_parse_target()` — handles URLs, hostnames, IPs (including IPv6 with brackets, ports)
1. If user specified a scheme, try only that scheme
1. Otherwise try `["http", "https"]` in order
1. Any response (including 401/403) = reachable
1. Self-signed certificates accepted via `make_ssl_context()` (`check_hostname=False, verify_mode=CERT_NONE`)

Returns `(reachable, scheme, error)`.

### Phase 3: Probes (`run_probes_phase`)

```python
result = run_probes_phase(target_url, timeout=10, result=result)
# result.probes.data: dict with auth_challenge, head_support, icmp keys
```

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

### Phase 4: Auth Detection (`check_auth_phase`)

```python
result = check_auth_phase(target_url, result)
# result.auth.requires_basic_auth: bool
# result.auth.realm: str | None
```

`check_basic_auth()` in `connectivity.py`:

1. Send unauthenticated GET to target URL
1. On 401 status: check `WWW-Authenticate` header
1. If header starts with "basic" (case-insensitive): extract realm, return `(True, realm)`
1. Non-Basic auth (Bearer, Digest): return `(False, None)`
1. Non-401 response or error: return `(False, None)`

If Basic Auth is required and no `--username`/`--password` were provided, the workflow stops and the CLI prompts interactively.

### Phase 5: Capture (`run_capture_phase`)

Calls `capture_device_har()` from `browser.py` with all accumulated state (credentials, probe data, patterns).

## Browser Capture Detail

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

### Context Configuration

```python
context = browser_type.new_context(
    record_har_path=temp_file,        # Secure temp file via mkstemp()
    record_har_content="embed",       # Base64-encode response bodies in HAR
    ignore_https_errors=True,         # Accept self-signed device certs
    service_workers="block",          # Prevent caching interference
    http_credentials=http_credentials # Basic Auth credentials (if any)
)
```

Design decisions:

- **Temp file for raw HAR**: Created via `tempfile.mkstemp()` — raw PII is never written to the user's directory. The FD is closed but the path is kept for Playwright.
- **Embedded content**: `record_har_content="embed"` base64-encodes response bodies within the HAR JSON, avoiding external file management.
- **Service worker blocking**: `service_workers="block"` prevents cached responses from interfering with fresh device captures.
- **HTTPS tolerance**: Device hardware commonly uses self-signed or expired certificates.

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

When disabled, no JS injection, no quiescence polling, and no `framenavigated` listener. A context-level route (`context.route("**/*", ...)`) still handles cache control. `page.goto()` with `wait_until="networkidle"` is the only wait mechanism.

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

### Metadata Injection

After the browser closes and writes the raw HAR:

```python
har_data["log"]["_probes"] = probes_data
har_data["log"]["_har_capture"] = {
    "browser_cookies": cookies,
    "local_storage": local_storage,
    "session_storage": session_storage,
    "tool": "har-capture",
    "version": __version__,
    "captured_at": datetime.utcnow().isoformat() + "Z",
    "cache_disabled": True,
    "service_workers_blocked": True,
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
1. **Probe data is informational** — Probe failures do not stop the capture workflow. Probes always succeed (they catch all exceptions internally).
1. **Error messages are credential-free** — Any username/password strings are replaced before errors are returned.
1. **Service workers are always blocked** — This is hardcoded in context config, not configurable, to ensure fresh captures.
1. **Self-signed certs are always accepted** — Both probes and Playwright context ignore certificate errors.
