# Use Cases

A complete catalog of what har-capture does, organized by actor and goal.

## Contents

### Capture

- [UC-1: Capture HAR from a Device with No Auth](#uc-1-capture-har-from-a-device-with-no-auth)
- [UC-2: Capture HAR from a Device with HTTP Basic Auth](#uc-2-capture-har-from-a-device-with-http-basic-auth)
- [UC-3: Capture HAR from a Device with In-Browser Auth](#uc-3-capture-har-from-a-device-with-in-browser-auth)
- [UC-4: Capture with Wait-for-Data (SPA Async Data)](#uc-4-capture-with-wait-for-data-spa-async-data)
- [UC-5: Capture with Custom Domain Patterns](#uc-5-capture-with-custom-domain-patterns)
- [UC-6: Automated Capture (Non-Interactive)](#uc-6-automated-capture-non-interactive)
- [UC-7: Interactive Capture (User Navigates, Closes Browser)](#uc-7-interactive-capture-user-navigates-closes-browser)
- [UC-8: Capture from a Single-Session Device](#uc-8-capture-from-a-single-session-device)

### Sanitization

- [UC-10: Sanitize an Existing HAR File](#uc-10-sanitize-an-existing-har-file)
- [UC-11: Sanitize with Domain Patterns for Enhanced Accuracy](#uc-11-sanitize-with-domain-patterns-for-enhanced-accuracy)
- [UC-12: Interactive Review of Flagged Values](#uc-12-interactive-review-of-flagged-values)
- [UC-13: Automated Sanitization (CI/CD)](#uc-13-automated-sanitization-cicd)
- [UC-14: Sanitize HAR with Pipe-Delimited Modem Data](#uc-14-sanitize-har-with-pipe-delimited-modem-data)
- [UC-15: Preserve Correlation Across Redacted Values](#uc-15-preserve-correlation-across-redacted-values)
- [UC-16: Sanitize HAR with XML API Device](#uc-16-sanitize-har-with-xml-api-device)

### Validation

- [UC-20: Validate a Sanitized HAR for PII Leaks](#uc-20-validate-a-sanitized-har-for-pii-leaks)
- [UC-21: Pre-Commit Hook Validation](#uc-21-pre-commit-hook-validation)

### Patterns

- [UC-30: List Available Domain Patterns](#uc-30-list-available-domain-patterns)
- [UC-31: Create a Custom Domain Pattern File](#uc-31-create-a-custom-domain-pattern-file)
- [UC-32: Layer Multiple Domain Patterns](#uc-32-layer-multiple-domain-patterns)
- [UC-33: Inspect Domain Pattern Details](#uc-33-inspect-domain-pattern-details)

### Integration

- [UC-40: Python API Usage](#uc-40-python-api-usage)
- [UC-41: Downstream Consumer (Modem Intake)](#uc-41-downstream-consumer-modem-intake)

______________________________________________________________________

## Capture Use Cases

### UC-1: Capture HAR from a Device with No Auth

**Actor**: Engineer or support agent capturing traffic from an open device web interface.

**Goal**: Record all HTTP traffic from a device's web interface into a sanitized HAR file.

**Preconditions**:

- Device is reachable on the network
- Playwright is installed (`pip install har-capture[capture]`)
- Browser engine is installed (auto-prompted on first run)

**Flow**:

1. User runs capture command targeting the device (full URL with `http://`/`https://`, or a bare hostname/IP)
1. System checks browser availability
1. System checks device connectivity. If the user did not supply a scheme, system probes TCP `:80` and `:443` and prefers HTTPS when its TLS handshake completes (see ADR-10); explicit schemes are used as given
1. System checks for session contamination — aborts if the device has a live session (serves data without login)
1. System launches Playwright browser with a clean context (empty cookie jar), navigates to device URL
1. Browser records all HTTP traffic to a temp HAR file with embedded response bodies
1. Wait-for-data mechanism captures async XHR/fetch requests
1. User closes browser (interactive) or timeout expires
1. System captures cookies, localStorage, sessionStorage
1. System sanitizes the HAR (removes PII, hashes sensitive values)
1. System filters bloat (fonts, images, media) and compresses to .har.gz
1. System deletes temp file containing raw PII

**Variations**:

- Device uses self-signed cert → accepted automatically
- Device has a live session from another browser tab → session check aborts with "clear cookies or use a clean profile"
- Device serves SPA that loads data async → wait-for-data captures it
- Browser not installed → user prompted to download (~150 MB)

**CLI Example**:

```bash
# Scheme auto-detected (HTTPS preferred when reachable)
har-capture 192.168.1.1 --patterns network-device

# Explicit scheme bypasses auto-detection
har-capture http://192.168.1.1 --patterns network-device
har-capture http://192.168.100.1 --output modem_capture.har --patterns network-device
```

______________________________________________________________________

### UC-2: Capture HAR from a Device with HTTP Basic Auth

**Actor**: Engineer capturing from a device that requires username/password via HTTP Basic Auth.

**Goal**: Capture traffic including authenticated pages without exposing credentials.

**Preconditions**:

- Device responds with 401 + `WWW-Authenticate: Basic` header
- User knows the credentials

**Flow**:

1. User runs capture command
1. System detects Basic Auth requirement via auth check phase
1. If credentials not provided on command line, CLI prompts for username/password
1. System passes credentials to Playwright context as `http_credentials`
1. Browser automatically handles Basic Auth challenge-response on every request
1. Capture proceeds as in UC-1
1. Credentials are sanitized from error messages if any error occurs

**Variations**:

- Credentials provided on command line → no interactive prompt
- Wrong credentials → device returns 401 repeatedly, captured in HAR
- Credentials in error messages → sanitized before display

**CLI Example**:

```bash
har-capture get http://192.168.1.1 --username admin --password password123 --patterns network-device
har-capture get http://192.168.1.1 -u admin -p password123 --patterns network-device
```

______________________________________________________________________

### UC-3: Capture HAR from a Device with In-Browser Auth

**Actor**: Engineer capturing from a device that uses form-based login, HNAP, or other browser-rendered auth.

**Goal**: Capture the full login flow and subsequent authenticated pages.

**Preconditions**:

- Device serves a login page (not HTTP Basic Auth)
- User knows the login credentials

**Flow**:

1. User runs capture in interactive mode (no timeout)
1. System detects no Basic Auth (200 response with login page)
1. Browser opens to the login page
1. User enters credentials in the browser's login form
1. Device authenticates (form POST, HNAP SOAP, etc.) — all captured in HAR
1. User navigates authenticated pages
1. Wait-for-data captures async data loads on each page
1. User closes browser when done
1. Capture, sanitization, and compression proceed as in UC-1
1. Login credentials in POST data are auto-redacted during sanitization

**Variations**:

- HNAP challenge-response → JavaScript executes naturally in browser, SOAP calls captured
- Multi-step login → all requests captured
- Session cookies → captured and included in HAR metadata

**CLI Example**:

```bash
har-capture get http://192.168.1.1 --patterns network-device
# Browser opens, user logs in manually, navigates, then closes browser
```

______________________________________________________________________

### UC-4: Capture with Wait-for-Data (SPA Async Data)

**Actor**: Engineer capturing from a device whose web interface loads data asynchronously after page render.

**Goal**: Ensure all XHR/fetch-loaded data appears in the HAR file.

**Preconditions**:

- Device web interface uses JavaScript to load data after page load
- Default behavior (wait-for-data is enabled by default)

**Flow**:

1. User runs capture command (wait-for-data is on by default)
1. System injects JavaScript init script that monkey-patches `XMLHttpRequest.send` and `window.fetch`
1. Init script tracks in-flight requests via `__harCapturePendingRequests` counter
1. Browser navigates to device URL
1. Page renders; JavaScript fires async data requests
1. System polls the counter, waiting for it to reach zero
1. System waits for 2.0 seconds of network quiescence (no new requests)
1. If user navigates to another page, `framenavigated` listener waits for current page's data to load
1. Capture completes with all async data included

**Variations**:

- Disable wait-for-data → falls back to Playwright's basic 500ms `networkidle`
- Very slow data loads → 30-second overall timeout per page prevents hanging
- Page navigation during data load → `framenavigated` listener waits for data to complete

**CLI Example**:

```bash
# Default: wait-for-data enabled
har-capture get http://192.168.1.1 --patterns network-device

# Explicitly disable (for faster capture of simple sites)
har-capture get http://192.168.1.1 --no-wait-for-data --patterns network-device
```

______________________________________________________________________

### UC-5: Capture with Custom Domain Patterns

**Actor**: Engineer capturing from a known device type who wants domain-tuned sanitization.

**Goal**: Use device-specific patterns for better sanitization accuracy (fewer false positives).

**Preconditions**:

- A domain pattern file exists (built-in or custom JSON)

**Flow**:

1. User specifies `--patterns` with a domain name or file path
1. System resolves the pattern name to a JSON file (e.g., `network-device` → `domains/network_device.json`)
1. Domain patterns are merged with core patterns (lists extend, dicts update)
1. Capture proceeds normally
1. During sanitization, domain heuristic detectors identify domain-specific PII (WiFi SSIDs, device names)
1. Domain safe-value patterns prevent false positives on technical vocabulary
1. Domain HTML scanners process vendor-specific structures (pipe-delimited data, etc.)

**Variations**:

- Multiple patterns → merged left to right: `--patterns network-device --patterns ./custom.json`
- Custom patterns as file path → loaded and merged with built-in
- Unknown pattern name → error with available domain list

**CLI Example**:

```bash
har-capture get http://192.168.1.1 --patterns network-device
har-capture get http://192.168.1.1 --patterns network-device --patterns ./my_extras.json
```

______________________________________________________________________

### UC-6: Automated Capture (Non-Interactive)

**Actor**: CI/CD pipeline or automated script capturing without user interaction.

**Goal**: Capture a HAR file non-interactively.

**Preconditions**:

- Target device is accessible from the CI environment
- Credentials provided via command line or environment
- No TTY available

**Flow**:

1. Script runs capture command
1. System runs all pre-flight checks (browser, connectivity, session contamination, probes, auth)
1. Browser launches, navigates to device
1. Wait-for-data captures async requests
1. Browser closes when page activity completes
1. Sanitization runs with heuristic flagging; flagged values written to report (no TTY)
1. Compressed HAR file is produced
1. Script receives exit code 0 (success) or 1 (failure)

**Variations**:

- Basic Auth device → `--username` and `--password` required
- `timeout` and `headless` parameters are available via the Python API (`capture_device_har()`) but not exposed as CLI flags

**CLI Example**:

```bash
har-capture http://192.168.1.1 \ --patterns network-device
    --username admin --password pass123 \
    --patterns network-device --output captures/modem.har
```

______________________________________________________________________

### UC-7: Interactive Capture (User Navigates, Closes Browser)

**Actor**: Engineer who needs to navigate specific pages, trigger specific actions, then capture.

**Goal**: Manually explore a device web interface and capture everything visited.

**Preconditions**:

- TTY available for interactive mode
- Device accessible in browser

**Flow**:

1. User runs capture with no timeout (default)
1. Browser opens to device URL
1. User navigates pages, clicks buttons, submits forms
1. All HTTP traffic is recorded (including redirects, AJAX, form submissions)
1. Wait-for-data captures async data on each page visited
1. User closes the browser window when done
1. System detects browser close event
1. Sanitization runs with interactive review (flagged values presented)
1. User selects which flagged values to redact
1. Final sanitized + compressed HAR is produced

**Variations**:

- User clicks through many pages → all captured and deduplicated during compression
- Large capture (images, fonts) → bloat filtering removes non-essential content
- Flagged values review → user can skip review with Ctrl+C (values preserved as-is)

**CLI Example**:

```bash
har-capture get http://192.168.1.1 --keep-raw --patterns network-device
# Browser opens. User navigates. User closes browser.
# Interactive review of flagged values follows.
```

______________________________________________________________________

## Sanitization Use Cases

### UC-10: Sanitize an Existing HAR File

**Actor**: Engineer with a pre-existing HAR file (from DevTools, another tool, or a prior capture).

**Goal**: Remove PII from the HAR file for safe sharing.

**Preconditions**:

- Valid HAR file exists on disk
- File is not already sanitized (system warns if it appears sanitized)

**Flow**:

1. User runs sanitize command on the HAR file
1. System validates HAR structure (JSON schema)
1. System checks file size against max limit (default 100 MB)
1. System loads patterns (core + any custom)
1. Pass 1: Auto-sanitize headers, cookies, POST data, URLs, response content
1. System writes sanitized output to `{input}.sanitized.har`
1. System embeds sanitization metadata (salt mode, heuristic mode, redaction counts)

**Variations**:

- File too large → error with suggestion to use `--max-size 0`
- Invalid HAR structure → `HarValidationError`
- Already sanitized → warning prompt, user can proceed or cancel

**CLI Example**:

```bash
har-capture sanitize capture.har --patterns network-device
har-capture sanitize capture.har --output clean.har --patterns network-device
```

______________________________________________________________________

### UC-11: Sanitize with Domain Patterns for Enhanced Accuracy

**Actor**: Engineer sanitizing a HAR from a known device type.

**Goal**: Get better sanitization accuracy using device-specific patterns.

**Preconditions**:

- HAR file from a known device type
- Domain pattern file available

**Flow**:

1. User runs sanitize with `--patterns`
1. Domain patterns merged with core patterns
1. Domain heuristic detectors identify category-specific PII (WiFi SSIDs, device names)
1. Domain safe values prevent false positives on technical vocabulary
1. Domain HTML scanners process vendor-specific data structures
1. Sanitized output has fewer false positives and catches domain-specific PII

**CLI Example**:

```bash
har-capture sanitize modem_capture.har --patterns network-device
```

______________________________________________________________________

### UC-12: Interactive Review of Flagged Values

**Actor**: Engineer who wants to review borderline values before redacting.

**Goal**: Make informed decisions about which flagged values are actually sensitive.

**Preconditions**:

- TTY available
- Heuristic engine enabled (default when interactive)

**Flow**:

1. User runs sanitize (interactive is default when TTY available)
1. Pass 1 auto-sanitizes known PII and flags suspicious values
1. CLI presents a table of flagged values with:
   - Original value
   - Category (wifi_ssid, credential, device_name, suspicious)
   - Confidence level (LOW, MEDIUM, HIGH)
   - Reason (why it was flagged)
   - Context (surrounding values)
   - Occurrence count
1. User selects values to redact (by number, range, or "all")
1. Pass 2 applies user-selected redactions using the same salt
1. Final sanitized file written

**Variations**:

- No flagged values → skip review, proceed directly
- User skips all → original values preserved
- Non-TTY → flagged values written to JSON report file

**CLI Example**:

```bash
har-capture sanitize capture.har --patterns network-device
# Interactive table shown, user selects values
har-capture sanitize capture.har --report flagged.json  # Save report to file --patterns network-device
```

______________________________________________________________________

### UC-13: Automated Sanitization (CI/CD)

**Actor**: CI/CD pipeline processing HAR files automatically.

**Goal**: Sanitize with consistent results in a non-TTY environment.

**Preconditions**:

- HAR file accessible to pipeline
- No TTY available

**Flow**:

1. Pipeline runs sanitize command
1. Heuristic analysis runs, flagging suspicious values
1. No TTY detected — flagged values written to `.review.json` report instead of interactive prompt
1. Sanitized output written
1. Exit code 0 on success

**Variations**:

- Use `--salt` for reproducible hashing across runs
- Use `--no-salt` for static placeholders (simpler, no correlation)
- Pipe to validation: `har-capture sanitize f.har --patterns network-device && har-capture validate f.sanitized.har --patterns network-device`

**CLI Example**:

```bash
har-capture sanitize capture.har --compress --salt mysalt123 --patterns network-device
```

______________________________________________________________________

### UC-14: Sanitize HAR with Pipe-Delimited Modem Data

**Actor**: Engineer sanitizing a capture from a Netgear or similar device that uses pipe-delimited JavaScript variables.

**Goal**: Sanitize vendor-specific data structures (tagValueList, deviceList, etc.).

**Preconditions**:

- HAR contains responses with pipe-delimited JavaScript variables
- Domain patterns specified for pipe-delimited variable names

**Flow**:

1. User runs sanitize with `--patterns network-device`
1. HTML content engine's pipe-delimited scanner matches variable names from domain pattern
1. Each pipe-separated value is analyzed individually:
   - Known PII (MACs, IPs) → auto-redacted
   - Serial number patterns (SN-, S/N-) → auto-redacted
   - Safe values from domain list → preserved
   - Already-redacted values → preserved
   - Suspicious values → flagged (if heuristics enabled) or preserved (if disabled)
1. Reassembled pipe-delimited string replaces original in HTML

**CLI Example**:

```bash
har-capture sanitize netgear_capture.har --patterns network-device
```

______________________________________________________________________

### UC-15: Preserve Correlation Across Redacted Values

**Actor**: Engineer who needs to trace device behavior across redacted entries.

**Goal**: Same MAC/IP/value always maps to same placeholder, enabling cross-entry analysis.

**Preconditions**:

- Default salted hashing mode (auto salt)

**Flow**:

1. Sanitization generates a random salt (32 hex chars)
1. Every occurrence of MAC `AA:BB:CC:DD:EE:FF` maps to `02:a1:b2:c3:d4:e5`
1. Every occurrence of IP `192.168.1.100` maps to `10.255.42.17`
1. Downstream analysis can still determine: "device `02:a1:b2:c3:d4:e5` made requests on entries 1, 5, 12"
1. Salt is stored in sanitization metadata for Pass 2 consistency

**Variations**:

- `--no-salt` → static placeholders, no correlation (all MACs → `XX:XX:XX:XX:XX:XX`)
- `--salt custom123` → deterministic, reproducible across runs
- Different sessions with `auto` → different hashes (salt changes per session)

**CLI Example**:

```bash
# Correlation-preserving (default)
har-capture sanitize capture.har --patterns network-device

# No correlation (static placeholders)
har-capture sanitize capture.har --no-salt --patterns network-device

# Reproducible across runs
har-capture sanitize capture.har --salt my-stable-salt --patterns network-device
```

______________________________________________________________________

### UC-8: Capture from a Single-Session Device

**Actor**: Engineer capturing from a device that allows only one concurrent HTTP connection (e.g., Compal CH7465MT cable modem with `max_concurrent: 1`).

**Goal**: Capture HAR without exhausting the device's session limit or timing out on persistent connections.

**Preconditions**:

- Device is reachable on the network
- Device allows only one concurrent HTTP session
- Device may keep JS polling/heartbeat connections open indefinitely

**Flow**:

1. User runs capture with `--minimal` flag
1. System checks browser availability (Phase 1)
1. System checks connectivity with a single GET — auto-detects http/https when no scheme is provided (TCP+TLS probe; HTTPS preferred), or uses the explicit scheme as given
1. Session check, probes, and auth check are **skipped** — no additional HTTP requests
1. Browser opens with a clean context and `domcontentloaded` page load strategy (no `networkidle` wait)
1. Wait-for-data XHR/fetch tracking is disabled
1. User logs in manually, navigates pages, closes browser
1. Capture, sanitization, and compression proceed normally

**Variations**:

- Device needs Basic Auth → provide `--username`/`--password` on command line (auth check phase is skipped, credentials passed directly to Playwright)
- Device uses form-based auth → user logs in through the browser UI (captured in HAR)
- Even `--minimal` connectivity check triggers lockout → user can provide an explicit scheme (`http://192.168.100.1`) to skip the auto-detect TCP+TLS probes

**CLI Example**:

```bash
har-capture http://192.168.100.1 --minimal --patterns network-device
har-capture http://192.168.100.1 --minimal --patterns network-device
har-capture http://192.168.100.1 --minimal --username admin --password pass123 --patterns network-device
```

______________________________________________________________________

### UC-16: Sanitize HAR with XML API Device

**Actor**: Engineer sanitizing a HAR capture from a device that uses an XML POST API (e.g., a cable modem with `getter.xml`/`setter.xml` endpoints).

**Goal**: Sanitize PII within XML POST request bodies and XML response bodies.

**Preconditions**:

- HAR file contains entries with `text/xml` or `application/xml` POST bodies
- HAR file contains entries with `application/xml` response content

**Flow**:

1. User runs sanitize command on the HAR file
1. System detects XML MIME type on POST body entries
1. XML POST bodies are routed through the HTML/XML content engine (same 17-pass scanner used for response content)
1. Sensitive values within XML elements (passwords, tokens, MACs, IPs) are auto-redacted
1. XML response bodies with `application/xml` MIME type are routed through the same engine
1. Non-sensitive XML content (element names, action parameters, status values) is preserved
1. Validation confirms no PII remains in the sanitized XML

**Variations**:

- Malformed XML → gracefully skipped (logged, sanitization continues)
- Form-encoded POST to XML endpoint (e.g., `fun=10&token=abc`) → handled by existing form-urlencoded handler, not the XML handler
- Mixed HAR with both XML and HTML responses → each entry routed by MIME type

**CLI Example**:

```bash
har-capture sanitize modem_capture.har --patterns network-device
```

______________________________________________________________________

## Validation Use Cases

### UC-20: Validate a Sanitized HAR for PII Leaks

**Actor**: Engineer or QA checking that sanitization was thorough.

**Goal**: Verify no PII remains in the sanitized HAR file.

**Preconditions**:

- Sanitized HAR file exists
- File has been through the sanitization pipeline

**Flow**:

1. User runs validate command
1. System loads HAR (supports both .har and .har.gz)
1. For each entry, system checks:
   - URL query parameters for base64-encoded credentials
   - Request/response headers for sensitive header names
   - POST data for sensitive field names
   - Response content for MAC addresses, serial numbers, public IPs
1. For each potential finding, system checks if value is already redacted
1. Redacted values are suppressed (no finding generated)
1. Non-redacted sensitive values are reported as findings
1. Exit code 0 if clean, 1 if findings detected

**Variations**:

- Gzipped HAR → decompressed transparently
- All values properly redacted → empty findings list, exit 0
- Mixed results → some values may be warnings (content) vs errors (headers)

**CLI Example**:

```bash
har-capture validate capture.sanitized.har --patterns network-device
har-capture validate capture.sanitized.har.gz --patterns network-device
```

______________________________________________________________________

### UC-21: Pre-Commit Hook Validation

**Actor**: Developer committing HAR files to a repository.

**Goal**: Prevent accidental commit of HAR files containing unsanitized PII.

**Preconditions**:

- Pre-commit hook configured in repository
- HAR files staged for commit

**Flow**:

1. Developer runs `git commit`
1. Pre-commit hook triggers `har-capture validate` on staged `.har` and `.har.gz` files
1. Validation runs on each staged HAR file
1. If any findings with "error" severity → commit is blocked
1. Developer reviews findings, re-sanitizes, and re-commits
1. If no findings → commit proceeds

**Variations**:

- Warning-only findings → commit may proceed (depends on hook configuration)
- Large HAR files → validation may be slow but does not skip entries
- No HAR files staged → hook passes immediately

**Example pre-commit config** (for consumer repos that store HAR files):

```yaml
- repo: local
  hooks:
    - id: check-har-secrets
      name: Check HAR files for secrets
      entry: har-capture validate --patterns network-device
      files: '\.har(\.gz)?$'
      types: [file]
```

______________________________________________________________________

## Pattern Use Cases

### UC-30: List Available Domain Patterns

**Actor**: Engineer exploring what domain patterns are available.

**Goal**: See all built-in domain pattern files and their descriptions.

**Preconditions**:

- har-capture installed

**Flow**:

1. User runs patterns command
1. System scans `patterns/domains/` directory
1. System lists each domain with name and description
1. User selects a domain to inspect further

**CLI Example**:

```bash
har-capture patterns
# Output:
# Available patterns:
#   network-device    Network device (router, modem, access point) patterns
```

______________________________________________________________________

### UC-31: Create a Custom Domain Pattern File

**Actor**: Engineer adding support for a new device category.

**Goal**: Create a JSON file that teaches har-capture about domain-specific PII and safe values.

**Preconditions**:

- Understanding of the device's web interface structure
- Examples of the device's HTML/JavaScript output

**Flow**:

1. Engineer creates a JSON file with relevant sections:
   - `heuristics.safe_value_patterns` — regex for domain-specific safe values
   - `heuristics.detectors` — detectors for domain-specific suspicious values
   - `tagValueList.safe_values` — exact-match safe values for pipe-delimited data
   - `pii.patterns` — additional PII patterns unique to this device
1. Engineer tests with `--patterns ./custom.json`
1. Reviews sanitization results, adjusts patterns
1. Pattern file is distributed alongside the consumer application

**CLI Example**:

```bash
# Create custom pattern file
cat > printer_patterns.json << 'EOF'
{
  "_description": "Enterprise printer patterns",
  "heuristics": {
    "safe_value_patterns": [
      {"regex": "^\\d+\\s*(?:ppm|dpi|pages)$", "_comment": "Print speed/resolution"}
    ],
    "detectors": [
      {
        "category": "print_queue",
        "confidence": "medium",
        "min_length": 3,
        "max_length": 64,
        "requires_letter": true,
        "patterns": [
          {"regex": "(?i)print.*queue|queue.*\\d+", "reason": "Print queue name"}
        ]
      }
    ]
  },
  "tagValueList": {
    "safe_values": ["ready", "idle", "printing", "toner low", "paper jam"]
  }
}
EOF

# Use it
har-capture sanitize printer_capture.har --patterns ./printer_patterns.json
```

______________________________________________________________________

### UC-32: Layer Multiple Domain Patterns

**Actor**: Engineer who needs the built-in network-device patterns plus additional vendor-specific patterns.

**Goal**: Build on existing patterns without duplicating them.

**Preconditions**:

- Built-in domain pattern exists (e.g., `network-device`)
- Engineer has additional patterns to add

**Flow**:

1. Engineer creates a JSON file with vendor-specific additions
1. User specifies multiple `--patterns` arguments — merged left to right (see [Pattern Spec — Merge Order](docs/specs/PATTERN_SPEC.md#merge-order))
1. Combined patterns are used for sanitization

**CLI Example**:

```bash
# Create additional pattern file
cat > docsis_extras.json << 'EOF'
{
  "_description": "DOCSIS cable modem extras",
  "pii": {
    "patterns": {
      "arris_auth_token": {
        "regex": "(ArrisXB\\w+Token\\s*=\\s*['\"])([^'\"]+)(['\"])",
        "replacement_prefix": "AUTH",
        "description": "Arris XB-series auth tokens"
      }
    }
  },
  "tagValueList": {
    "safe_values": ["s-cdma", "ofdm", "ofdma", "16qam"]
  }
}
EOF

# Layer on top of network-device
har-capture sanitize capture.har --patterns network-device --patterns ./docsis_extras.json
```

______________________________________________________________________

### UC-33: Inspect Domain Pattern Details

**Actor**: Engineer exploring what a domain pattern file contains.

**Goal**: View the safe values, detectors, and patterns in a domain file.

**Preconditions**:

- Domain pattern exists (built-in or file path)

**Flow**:

1. User runs patterns command with `--show`
1. System resolves the domain name to a file
1. System displays: file path, description, safe value patterns, detectors, safe values

**CLI Example**:

```bash
har-capture patterns --show network-device
# Output:
# Domain: network-device
# Path: .../patterns/domains/network_device.json
# Description: Network device (router, modem, access point) patterns
# Safe value patterns: 15
# Detectors: 2 (wifi_ssid, device_name)
# Tag-value safe values: 28
```

______________________________________________________________________

## Integration Use Cases

### UC-40: Python API Usage

**Actor**: Developer building a tool that processes HAR files programmatically.

**Goal**: Sanitize HAR files from Python code without using the CLI.

**Preconditions**:

- har-capture installed as a dependency

**Flow**:

1. Developer imports sanitization functions
1. Calls `sanitize_har_file()` or `sanitize_html()` with options
1. Receives sanitized output and sanitization report
1. Processes report for flagged values or statistics

**Code Example**:

```python
from har_capture.sanitization.har import sanitize_har_file, HeuristicMode

# Basic sanitization
output_path, report = sanitize_har_file(
    "capture.har",
    output_path="clean.har",
    salt="auto",
    heuristics=HeuristicMode.DISABLED,
)

# With domain patterns
output_path, report = sanitize_har_file(
    "capture.har",
    custom_patterns="network-device-patterns.json",
    heuristics=HeuristicMode.FLAG,
)

# Check report
print(f"Auto-redacted: {report.auto_redacted_counts}")
print(f"Flagged values: {len(report.flagged)}")

# Sanitize HTML content directly
from har_capture.sanitization.html import sanitize_html

clean_html = sanitize_html(
    raw_html,
    salt="auto",
    custom_patterns={"pii": {"patterns": {...}}},
)

# Validate a sanitized file
from har_capture.validation.secrets import validate_har

findings = validate_har("clean.har")
if findings:
    for f in findings:
        print(f"{f.severity}: {f.field} = {f.value} ({f.reason})")
```

______________________________________________________________________

### UC-41: Downstream Consumer (Modem Intake)

**Actor**: The cable_modem_monitor (CMM) system's modem-intake pipeline.

**Goal**: Process HAR captures submitted by field engineers, extracting device data while ensuring PII is removed.

**Preconditions**:

- HAR file captured via `har-capture get` with `--patterns network-device`
- CMM's modem-intake pipeline has har-capture as a dependency

**Flow**:

1. Field engineer captures HAR from a cable modem using har-capture
1. Engineer submits the `.har.gz` file to CMM
1. CMM's modem-intake pipeline:
   - Validates the HAR via `validate_har()` to ensure PII is removed
   - If validation fails, rejects the submission
   - Extracts device data from sanitized HAR entries
   - Reads probe data from `_probes` key (auth challenge, ICMP latency)
   - Reads capture metadata from `_har_capture` key (tool version, timestamp)
   - Reads browser cookies and storage from `_har_capture` metadata
   - Reads pre-capture cookie audit from `_solentlabs.pre_capture_cookies` — verifies the browser context was clean when capture started
1. Extracted data is stored in CMM's database

**Variations**:

- Validation finds PII → submission rejected, engineer re-sanitizes
- Probe data missing → pipeline handles gracefully (probes are optional)
- Custom domain patterns → CMM ships its own pattern file extending `network-device`

**Data Flow**:

```text
Field Engineer                     CMM Pipeline
     │                                  │
     │  har-capture get http://192.168.1.1     │
     │  --patterns network-device       │
     │                                  │
     │  ─── capture.har.gz ──────────►  │
     │                                  │  validate_har()
     │                                  │  extract entries
     │                                  │  read _probes
     │                                  │  read _har_capture metadata
     │                                  │  read _solentlabs (pre_capture_cookies)
     │                                  │  store in database
```

______________________________________________________________________

### UC-42: Redact Device-Specific Credential Fields at Runtime

**Actor**: A downstream library (e.g. CMM) that captures auth traffic at runtime and knows, from its device catalog, which field names carry credentials for a particular model.

**Goal**: Feed runtime-known credential field names (from a product catalog, YAML config, or database lookup) into sanitization without modifying the universal `sensitive.json` or maintaining a consumer-side pre-redaction helper.

**Preconditions**:

- Consumer has a `postData`-shaped dict from a live HTTP capture (e.g. via a Playwright session adapter).
- Consumer has the field-name list for the current device (e.g. a `credential_fields` entry of `["pws"]` loaded from `modem.yaml`).
- Consumer wants one canonical sanitization policy (har-capture's) rather than its own pre-pass.

**Flow**:

1. Consumer resolves the device's credential field names from its catalog at runtime.
1. Consumer builds a `custom_patterns` dict of shape `{"fields": {"auto_redact_patterns": [...]}}`.
1. Consumer passes that dict to `sanitize_post_data(..., custom_patterns=...)`.
1. har-capture merges the extensions with built-ins for this call only (via a `ContextVar` scope) and returns sanitized `postData`.
1. Subsequent calls for a different device with a different field list use their own dict; no state bleeds between calls.

**Code Example**:

```python
from har_capture.sanitization import sanitize_post_data

def redact_capture_for_device(post_data: dict, device_spec: dict) -> dict:
    """Sanitize a captured postData using per-device credential field names."""
    custom = {
        "fields": {
            "auto_redact_patterns": device_spec.get("credential_field_names", []),
        },
    }
    return sanitize_post_data(post_data, custom_patterns=custom)

# Example: a Hitron CODA56 catalog entry lists "pws" as its credential field
hitron_spec = {"credential_field_names": ["pws"]}
captured = {
    "mimeType": "application/x-www-form-urlencoded",
    "text": "user=admin&pws=hunter2",
}
redact_capture_for_device(captured, hitron_spec)
# → {"mimeType": "...", "text": "user=admin&pws=[REDACTED]"}

# Same process with a Motorola MB7621 (different field name) using the SAME
# process — no global state change, no interference.
motorola_spec = {"credential_field_names": ["loginPassword"]}
# ... etc.
```

**Variations**:

- Consumer wants to also flag (not auto-redact) a non-credential field for review → pass `{"fields": {"flag_patterns": ["deploy_env"]}}` alongside.
- Consumer already has a JSON file on disk → pass the path as a string; the loader reads it and the regex cache keys off the resolved absolute path.
- Concurrent captures for different devices (threaded or asyncio) → each call sees its own pattern set because the override lives in a `ContextVar`.

**Why not edit `sensitive.json`?** That file captures universal PII rules. Device-specific credential names (`pws`, `loginPassword`, vendor-proprietary tokens) don't belong there because they'd apply to every capture across every consumer. The per-call hook keeps the universal set small and lets each consumer carry its own catalog.
