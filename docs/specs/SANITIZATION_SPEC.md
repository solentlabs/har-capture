# Sanitization Spec

## Purpose

This spec describes the three-engine sanitization pipeline that processes HAR files to remove PII. It covers the
HAR-level engine (headers, cookies, POST data, query params), the HTML content engine (multi-pass scanner pipeline), and
the heuristic engine (safe value check, entropy, credential prefix, adjacency, domain detectors). It documents the
two-pass model (auto-sanitize + interactive review) and the format-preserving hasher.

## Key Files

| File                                         | Role                                                                               |
| -------------------------------------------- | ---------------------------------------------------------------------------------- |
| `src/har_capture/sanitization/har.py`        | HAR-level orchestration (~1350 lines, 27 functions, 8 logical groups)              |
| `src/har_capture/sanitization/html.py`       | HTML/content engine, multi-pass scanner pipeline                                   |
| `src/har_capture/sanitization/heuristics.py` | Heuristic engine: entropy analysis, credential prefix, adjacency, domain detectors |
| `src/har_capture/sanitization/collector.py`  | Redaction/flag collection during sanitization                                      |
| `src/har_capture/sanitization/report.py`     | SanitizationReport data structures                                                 |
| `src/har_capture/patterns/hasher.py`         | Salted format-preserving hashing (SHA-256)                                         |

## Architecture Overview

```text
                    ┌────────────────────────────┐
                    │      Pattern Loading       │
                    │  pii.json + sensitive.json │
                    │  + domain patterns         │
                    └────────────┬───────────────┘
                                 │
              ┌──────────────────┴────────────────────┐
              │         Pass 1: Auto-Sanitize         │
              │                                       │
              │  ┌─────────────────────────────────┐  │
              │  │    HAR Engine (har.py)          │  │
              │  │    Headers → Cookies → POST →   │  │
              │  │    URLs → JSON bodies           │  │
              │  └──────────────┬──────────────────┘  │
              │                 │                     │
              │  ┌──────────────▼──────────────────┐  │
              │  │    Content Engine (html.py)     │  │
              │  │    Sequential scanner passes    │  │
              │  │    (heuristic engine embedded   │  │
              │  │     in web storage + pipe-      │  │
              │  │     delimited passes)           │  │
              │  └─────────────────────────────────┘  │
              └──────────────────┬────────────────────┘
                                 │
                                 ▼
              ┌───────────────────────────────────────┐
              │    Pass 2: Interactive Review         │
              │    apply_user_redactions(report)      │
              │    Global find-replace with same salt │
              └───────────────────────────────────────┘
```

## HAR Engine (har.py)

### Logical Groups

The ~1350-line file is organized into 8 groups:

1. **HAR Structure Validation** — `validate_har_structure()`, `HarSizeError`, `HarValidationError`
1. **Pattern Loading** — `_load_sensitive_headers()`, `_load_sensitive_field_patterns()` (module-level caching)
1. **Core Redaction Utilities** — `_redact_value()`, `is_sensitive_field()`, `is_flaggable_field()`,
   `sanitize_header_value()`
1. **Request Sanitization** — Headers, cookies, POST data (form/JSON), query strings, URL paths
1. **Response Sanitization** — Headers, cookies, content (MIME-type dispatched)
1. **Pattern-Based String Sanitization** — 10+ regex patterns for MACs, IPs, emails, SSN, credit cards
1. **Main Entry Points** — `sanitize_entry()`, `sanitize_har()`, `sanitize_har_file()`
1. **Pass 2** — `apply_user_redactions()`, `appears_sanitized()`

### Entry Points

```python
# File-level sanitization (primary API)
def sanitize_har_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    max_size: int | None = DEFAULT_MAX_HAR_SIZE,
    validate: bool = True,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> tuple[str, SanitizationReport]:
    """Load HAR, validate, sanitize, embed metadata, write output."""

# In-memory sanitization
def sanitize_har(
    har_data: dict,
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> tuple[dict, SanitizationReport]:
    """Sanitize a parsed HAR dict, return (sanitized_data, report)."""

# Single-entry sanitization
def sanitize_entry(
    entry: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    collector: RedactionCollector | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    _skip_copy: bool = False,
) -> dict[str, Any]:
    """Sanitize one HAR entry (request + response)."""
```

### Header Sanitization

Headers are classified into four tiers from `sensitive.json`:

1. **Full redact** (`headers.full_redact`): X-Auth-Token, X-Api-Key, etc. — entire value replaced.
1. **Scheme redact** (`headers.scheme_redact`): Authorization-style headers (RFC 7235 syntax: `Scheme credentials`). The
   scheme token is preserved when it matches a recognized RFC scheme (`Basic`, `Bearer`, `Digest`, `NTLM`, `Negotiate`,
   `OAuth`); the credential after the first whitespace is redacted. Unknown schemes (or values with no whitespace) fall
   through to full redaction so a non-standard leading token can't escape. Preserving the scheme lets downstream
   consumers classify the auth mechanism from a single authenticated request without needing a `401 + WWW-Authenticate`
   exchange.
1. **Cookie redact** (`headers.cookie_redact`): Cookie, Set-Cookie — cookie names preserved, values redacted. Cookie
   metadata (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, `Expires`) detected and preserved.
1. **All other headers**: Passed through unmodified.

### Field Sensitivity Classification

```python
def is_sensitive_field(name: str) -> bool:
    """100% confidence — auto-redact. Matches: password, secret, token, key, auth."""

def is_flaggable_field(name: str) -> bool:
    """Lower confidence — flag for review. Matches: username, domain, account_id."""
```

Patterns loaded from `sensitive.json` `fields.auto_redact_patterns` and `fields.flag_patterns`. Fallback patterns
(hardcoded): `["password", "secret", "token", "\\bkey\\b", "\\bauth\\b"]`.

Callers can extend these per-call via `sanitize_post_data(..., custom_patterns=...)` or
`sanitize_html(..., custom_patterns=...)`. The extension is additive (never replacing built-ins) and is applied via a
`ContextVar`-scoped override that both public entry points enter at the top of the call. Inner helpers
(`_sanitize_form_urlencoded`, `_sanitize_json_recursive`, `_sanitize_xml_fields`, the inline-script `setItem` scanner,
and any other site that calls `is_sensitive_field` / `is_flaggable_field`) pick up the active set automatically, with no
signature plumbing. Because `ContextVar` is thread- and asyncio-scoped, concurrent callers observe only their own
patterns.

### POST Data Sanitization

```python
def sanitize_post_data(
    post_data: dict[str, Any] | None,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    *,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> dict[str, Any] | None:
```

1. **Form params** (`postData.params`): Each parameter checked against `is_sensitive_field()` (auto-redact) and
   `is_flaggable_field()` (flag). A parameter whose name is not recognized but whose value is a `base64(user:pass)`
   credential (`is_base64_credential()`) is redacted as `AUTH` — mirroring the query-param fallback, so base64-wrapped
   credentials in device-specific field names (e.g. `pws`) do not slip past field-name redaction.
1. **URL-encoded body** (`_sanitize_form_urlencoded`): Detected via content type, parsed and redacted. The same
   `base64(user:pass)` value fallback applies (checking the raw and percent-decoded forms).
1. **JSON body** (`_sanitize_json_recursive`): Recursive traversal with depth limit (50). Object keys checked against
   field patterns; values redacted if key is sensitive.
1. **XML body** (`sanitize_html`): Detected via `text/xml` or `application/xml` content type. Delegated to the HTML
   content engine, which runs the full scanner pipeline. XML POST bodies from device APIs (e.g., modem XML getter/setter
   endpoints) are sanitized identically to XML response content.
1. **Raw text**: Falls through to string pattern matching.

**Per-call `custom_patterns`** extends the auto-redact and flag regex sets across all four branches (params, form, JSON,
XML) via a `ContextVar`-scoped override entered at the top of `sanitize_post_data`. The dict shape mirrors
`sensitive.json`, e.g. `{"fields": {"auto_redact_patterns": ["pws"]}}`. Module-global patterns are never mutated; the
override is scoped per thread / asyncio task. Compiled regex pairs are cached per canonical key so repeated calls with
the same extension avoid recompilation. `sanitize_html` enters the same scope, so the XML branch's delegation to the
HTML engine honors the override end-to-end.

### URL Sanitization

**Query parameters** (`_sanitize_url_query_params`):

- Parameter names checked against sensitive field patterns
- Values checked for base64-encoded credentials (`user:pass` format)
- Sensitive values redacted with hasher

**URL path** (`_sanitize_url_path`):

- UUIDs, API keys, long tokens, device serial patterns are flagged (not auto-redacted)
- Path segments preserved for URL readability

### JSON Body Traversal

```python
def _sanitize_json_recursive(data, collector, depth=0, max_depth=50):
```

- Traverses dicts and lists recursively
- For dicts: checks each key against `is_sensitive_field()` / `is_flaggable_field()`
- Depth limit of 50 prevents stack overflow on deeply nested/circular JSON
- Malformed JSON is caught, logged, and skipped (sanitization continues)

### Response Content Dispatch

```python
def _sanitize_response_content(content, collector, custom_patterns, heuristics):
```

**Decode-first discriminator** (`_decode_base64_json`): Before any MIME routing, a body made entirely of base64-alphabet
characters is tested — if it decodes to UTF-8 that parses as a JSON **object or array**, it is a structured payload, not
an opaque secret. Such bodies are sanitized value-by-value via `_sanitize_json_recursive` and **re-encoded to base64**
on the way out, preserving field names and shape. This stops devices that return raw base64-encoded JSON (e.g. the
Sercomm DM1000 `setup.cgi?todo=...` endpoints, often with an empty Content-Type) from being collapsed to a single
`AUTH_<hash>` token. Only genuinely token-shaped opaque values (base64 that does not decode to structured JSON) fall
through to the whole-body credential guard — see [Server-Token Preservation](#server-token-preservation).

MIME-type based routing (after the decode-first check):

- `text/html`, `text/xml`, `application/xml` → `sanitize_html()` from html.py
- `application/json`, `text/json` → `_sanitize_json_recursive()`
- Other `text/*` → `_sanitize_string_patterns()`
- Binary content → skipped

### String Pattern Sanitization

`_sanitize_string_patterns()` applies 10+ regex patterns:

| Pattern       | Detection                               | Redaction                              |
| ------------- | --------------------------------------- | -------------------------------------- |
| MAC addresses | `([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}` | `hasher.hash_mac()`                    |
| Private IPs   | 10.x, 172.16-31.x, 192.168.x            | `hasher.hash_ip(ip, is_private=True)`  |
| Public IPs    | All other valid IPs                     | `hasher.hash_ip(ip, is_private=False)` |
| Emails        | RFC 5321 simplified                     | `hasher.hash_email()`                  |
| SSN           | `\d{3}-\d{2}-\d{4}`                     | Flagged, not auto-redacted             |
| Credit cards  | Visa/MC/Amex with Luhn check            | `hasher.hash_value()`                  |
| Phone numbers | Various formats                         | Flagged, not auto-redacted             |

**IP address heuristic** (`is_valid_ip_address()`):

- All octets \< 20 → likely version string (e.g., `5.7.1.5`) → skip
- 10.x.x.x → always IP (private range)
- Repeated octets (8.8.8.8) → always IP
- First octet ≥ 20 → always IP

**Credit card validation**: Luhn checksum verification before redacting — reduces false positives on random 16-digit
numbers.

## HTML Content Engine (html.py)

### Scanner Pipeline

The engine runs sequential passes over HTML/JavaScript content (numbered 0–16 in the code, with sub-passes like 0b, 2b,
7a/7b, 8b). Each pass uses regex substitution with callback functions that invoke the hasher.

| Pass | Scanner                       | Pattern                                             | Redaction                              |
| ---- | ----------------------------- | --------------------------------------------------- | -------------------------------------- |
| 0    | Custom patterns               | Domain-specific PII regex                           | Per-pattern prefix                     |
| 0b   | Web storage                   | `localStorage.setItem('KEY', 'VALUE')`              | Auto-redact if key is sensitive        |
| 1    | MAC addresses                 | `([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`             | `hasher.hash_mac()`                    |
| 2    | Serial numbers (inline)       | `\bSN\b\|S/N\|Serial Number` + value                | `hasher.hash_value(val, "SERIAL")`     |
| 2b   | Serial numbers (table)        | `<td>Label\b</td><td>VALUE</td>`                    | `hasher.hash_value(val, "SERIAL")`     |
| 2c   | JS serial variables           | Names with serial+Number/Num/No or ending in serial | `hasher.hash_value(val, "SERIAL")`     |
| 2d   | WPS / pairing / default PINs  | Known PIN label + 8-digit value (issue #47)         | `hasher.hash_value(val, "PIN")`        |
| 3    | Account/subscriber IDs        | `Account\|Subscriber\|Customer\|Device` + value     | `hasher.hash_value(val, "ACCOUNT")`    |
| 4    | Private IPs                   | RFC 1918 ranges (preserves gateway IPs)             | `hasher.hash_ip(ip, is_private=True)`  |
| 5    | Public IPs                    | Non-private, non-reserved                           | `hasher.hash_ip(ip, is_private=False)` |
| 6    | IPv6 addresses                | Full + compressed, validated via `ipaddress`        | `hasher.hash_ipv6()`                   |
| 7    | Passwords/passphrases         | `password=value`, `passphrase=value`                | `hasher.hash_value(val, "PASS")`       |
| 7a   | SSID text labels              | SSID labels in HTML text nodes                      | `hasher.hash_value(val, "WIFI")`       |
| 7b   | JS password objects           | JavaScript object password fields                   | `hasher.hash_value(val, "PASS")`       |
| 8    | Password inputs               | `<input type="password" value="...">`               | `hasher.hash_value(val, "PASS")`       |
| 8b   | SSID inputs                   | SSID-related input fields                           | `hasher.hash_value(val, "WIFI")`       |
| 9    | Session tokens                | 20+ char alphanumeric with label prefix             | `hasher.hash_value(val, "TOKEN")`      |
| 10   | CSRF tokens                   | CSRF tokens in meta tags                            | `hasher.hash_value(val, "CSRF")`       |
| 11   | Email addresses               | `user+tag@sub.domain.co.uk`                         | `hasher.hash_email()`                  |
| 12   | Config paths                  | `.cfg` file references                              | `hasher.hash_value(val, "CONFIG")`     |
| 13   | Vendor JS vars                | Motorola `var CurrentPw_24g = '...'`                | `hasher.hash_value(val, "PASS")`       |
| 14   | Pipe-delimited (tagValueList) | `var name = "val1\|val2\|val3"`                     | Per-value heuristic analysis           |
| 15   | Pipe-delimited (other)        | Other pipe-delimited variables                      | Per-value heuristic analysis           |
| 16   | SSID fields in JS             | `ssid_24g: 'value'`, `guest_ssid: 'value'`          | `hasher.hash_value(val, "WIFI")`       |

**Pass 2c precision rule:** Matches variable names containing the compound `serial` + `number`/`num`/`no` (with optional
separator), and names ending with `serial`. Does NOT match `serial` followed by unrelated suffixes (`Protocol`, `Port`,
`Baud`, `ization`). Bare `serial` is excluded — too ambiguous for auto-redact.

**Sibling-element rule (passes 2, 2b, 2d):** The tag chain between a label and its value — `(?:<[^>]*>\s*)*` — permits
whitespace between tags, so label/value pairs rendered in sibling elements match (e.g. Technicolor .jst on the XB6/XB7/
XB8 family renders `<span class="readonlyLabel">Serial Number:</span>` with the value in a following sibling
`<span class="value">`). In passes 2 and 2d the separator-plus-tag run is captured and re-emitted verbatim, so redaction
replaces only the value and preserves the intermediate markup — sanitized fixtures keep their DOM structure. The same
whitespace-tolerant chain is used by the `serial_number` / `wps_pin` patterns in `pii.json` (`check_for_pii`) and the
`SERIAL_PATTERNS` detectors in `validation/secrets.py`.

### Web Storage Scanner (Pass 0b)

Detects `localStorage.setItem()` and `sessionStorage.setItem()` in inline scripts:

- **Tier A**: Key matches `is_sensitive_field()` (password, token, secret, api_key, auth_token, csrf_token) →
  auto-redact value
- **Tier B**: Value contains IPs/MACs → handled by subsequent passes
- **Tier C**: Heuristic analysis if enabled (`FLAG` or `REDACT` mode)

### Pipe-Delimited Scanner (Passes 14–15)

Handles vendor-specific data structures like Netgear's tagValueList (`"val1|val2|val3"`):

1. Match variable assignment where variable name matches pipe-delimited variable patterns (hardcoded in `html.py`)
1. Split value by `|` delimiter
1. For each value:
   - Skip if empty or matches safe values (`sensitive.tagValueList.safe_values`)
   - Skip if already redacted (contains hash prefix or format-preserving pattern)
   - Auto-redact if MAC pattern, serial number pattern (`SN-`, `S/N-`, `SN_`, `S-N-`)
   - If heuristics enabled: run through `analyze_value()` from heuristics.py
1. Reassemble pipe-delimited string

### `sanitize_html()` Signature

```python
def sanitize_html(
    html: str,
    salt: str | None = "auto",         # Salt mode
    custom_patterns: dict | str | None = None,  # Domain patterns
    collector: RedactionCollector | None = None, # Shared collector
    heuristics: HeuristicMode = HeuristicMode.DISABLED,  # Heuristic mode
) -> str:
```

### `check_for_pii()` — CI/PR Validation

```python
def check_for_pii(content: str, filename: str = "") -> list[dict]:
    """Detect unsanitized PII in fixture files. Returns list of findings."""
```

Used in CI to check test fixtures for PII. Has allowlist support for known placeholders.

## Heuristic Engine (heuristics.py)

### Analysis Pipeline

```python
def analyze_value(
    value: str,
    values_context: list[str] | None = None,
    value_index: int | None = None,
    extra_safe_patterns: list[re.Pattern] | None = None,
    compiled_detectors: list[CompiledDetector] | None = None,
) -> tuple[bool, ConfidenceLevel, str, str]:
    """Returns (should_flag, confidence, category, reason)."""
```

Detection pipeline (in order):

1. **Skip empty/safe values** — Check against 25+ compiled safe patterns (status words, dates, versions, UUIDs, dB
   values, uptime durations, etc.) plus domain `extra_safe_patterns`
1. **Run domain detectors** — If `compiled_detectors` provided, first matching detector wins. Checks: length bounds,
   letter requirement, regex patterns, CamelCase
1. **Entropy check** — Shannon entropy calculation. Returns `(True, reason)` if entropy ≥ threshold AND mixed character
   types
1. **Credential prefix check** — Regex `^(?:pass(?:word|wd)?|pwd|secret|token|key|auth)[\d!@#$%^&*]+$`
1. **Adjacency check** — If `values_context` provided, checks neighbors for redacted prefixes
1. **Combine signals** — `should_flag = detector OR entropy OR credential OR adjacent`
1. **Determine category** — Priority: credential_prefix > detector > entropy > suspicious
1. **Assign confidence** — Based on signal combination (see table below)

### Entropy Analysis

```python
def calculate_entropy(value: str) -> float:
    """Shannon entropy via character frequency analysis."""

def is_high_entropy(value: str) -> tuple[bool, str]:
    """Returns (is_high, reason_string)."""
```

Thresholds and bounds:

- Default entropy threshold: **2.8** bits/char
- Mixed threshold (3+ char types): **2.0** bits/char
- Minimum length: **8** chars
- Maximum length: **64** chars
- Character types: lowercase, uppercase, digits, special

A value is high-entropy if:

- Length in bounds AND entropy ≥ 2.8 AND 2+ character types
- OR: 3+ character types AND entropy ≥ 2.0

### Credential Prefix Detection

```python
# Pattern: pass123, token42, key!2024, secret789, auth42
_CREDENTIAL_PREFIX_RE = re.compile(
    r"^(?:pass(?:word|wd)?|pwd|secret|token|key|auth)[\d!@#$%^&*]+$",
    re.IGNORECASE
)
# Length bounds: 4-32 chars
```

### Adjacency Detection

Checks if the value at `value_index` in `values_context` is adjacent to an already-redacted value:

Redacted prefixes checked: `MAC_`, `PASS_`, `TOKEN_`, `SERIAL_`, `WIFI_`, `DEVICE_`, `CC_`, `ACCOUNT_`, `CRED_`,
`SENSITIVE_`, `FIELD_`, `AUTH_`, `COOKIE_`, `STORAGE_`, `CONFIG_`

Also checks static placeholders: `XX:XX:XX:XX:XX:XX`, `0.0.0.0`

Returns `(True, "adjacent to redacted value (before/after)")` if a neighbor is redacted.

### Confidence Scoring

```python
def get_confidence_for_value(
    detector_matched: bool,
    entropy_matched: bool,
    adjacent_matched: bool,
    detector_confidence: str | None = None,
) -> ConfidenceLevel:
```

| Signals                     | Result |
| --------------------------- | ------ |
| Adjacent + detector/entropy | HIGH   |
| Detector (high confidence)  | HIGH   |
| Detector (medium) alone     | MEDIUM |
| High entropy alone          | MEDIUM |
| Adjacent alone              | LOW    |
| Nothing matches             | LOW    |

### Domain Detectors

Each detector from domain JSON is compiled into a `CompiledDetector`:

```python
@dataclass
class CompiledDetector:
    category: str            # "wifi_ssid", "device_name", etc.
    confidence: str          # "low", "medium", "high"
    min_length: int
    max_length: int
    requires_letter: bool
    patterns: list[tuple[re.Pattern, str]]  # (compiled_regex, reason)
    camelcase: bool          # Enable CamelCase matching
```

Detection loop for each detector:

1. Check `len(value)` against `min_length` / `max_length`
1. If `requires_letter`: check value contains alphabetic chars
1. Run each regex pattern — first match wins
1. If `camelcase=True` and no pattern matched: check CamelCase pattern `^[A-Z][a-z]+[A-Z][a-zA-Z0-9]*$`

CamelCase examples: `HomeNetwork`, `MyWiFi`, `GuestAccess`

### Heuristic Modes

| Mode       | Pipe-delimited behavior                   | HAR field behavior                |
| ---------- | ----------------------------------------- | --------------------------------- |
| `DISABLED` | No heuristic analysis — skip              | Backward compatible with v0.3.1   |
| `FLAG`     | Flag values for review, preserve original | Interactive mode (user decides)   |
| `REDACT`   | Auto-redact suspicious values             | Aggressive automated sanitization |

Known patterns (MACs, IPs, emails) are **always** auto-redacted regardless of heuristic mode.

### Safe Value Patterns (25+ built-in)

Categories:

- **Status**: Good, Bad, OK, Error, Connected, Disconnected, Active, Inactive, Online, Offline
- **Technical**: Numeric (123, 0, 11), dB values (-70dBm, 50dB), interface names (eth0, wlan0, br0)
- **Versions**: 1.0, 2.3.4, v1.2.3
- **Time/Date**: HH:MM, ISO 8601, ctime, RFC 2822, uptime durations
- **Network/Config**: DHCP Client, QAM256, ATDMA, 802.11ac, WPA2, subnet masks
- **Placeholders**: UUIDs, IPv6 link-local, already-redacted values

### ReDoS Prevention

- SSID detector enforces `max_length=32` — strings longer than 32 chars are immediately rejected
- All domain detectors have length bounds
- Test suite verifies malicious input (e.g., `A * 150`) processes in \< 0.1s

## Format-Preserving Hasher (hasher.py)

### Construction

```python
hasher = Hasher.create(salt)  # salt = "auto" | None | custom_string
```

- `"auto"` / `"random"`: Generate `secrets.token_hex(16)` — 32 hex chars, cryptographically secure
- `None`: Static placeholders mode (XX:XX:XX:XX:XX:XX, 0.0.0.0, etc.)
- Custom string: Deterministic — same salt + same value = same hash

### Hash Methods

| Method                           | Input                  | Output Format                | Reserved Range                |
| -------------------------------- | ---------------------- | ---------------------------- | ----------------------------- |
| `hash_mac(mac)`                  | `AA:BB:CC:DD:EE:FF`    | `02:xx:xx:xx:xx:xx`          | IEEE locally administered bit |
| `hash_ip(ip, is_private=True)`   | `192.168.1.100`        | `10.255.x.x`                 | RFC 1918                      |
| `hash_ip(ip, is_private=False)`  | `8.8.8.8`              | `192.0.2.x`                  | RFC 5737 TEST-NET-1           |
| `hash_ipv6(ipv6)`                | `fe80::1`              | `2001:db8::xxxx:xxxx`        | RFC 3849 documentation        |
| `hash_email(email)`              | `admin@example.com`    | `user_hash@redacted.invalid` | RFC 2606 `.invalid` TLD       |
| `hash_value(val, prefix)`        | `SECRET123`            | `TOKEN_a1b2c3d4`             | N/A (prefix-based)            |
| `hash_generic(val, prefix)`      | (alias for hash_value) |                              |                               |
| `hash_sensitive_value(val, cat)` | `HomeNetwork`          | `WIFI_a1b2c3d4`              | Category → prefix mapping     |

### Algorithm

```text
input = normalize(value)  # lowercase for MAC/email
digest = SHA-256(salt + ":" + prefix + ":" + input)
output = format(digest[:N])  # N bytes depending on output format
```

### Category-to-Prefix Mapping

```python
# In hash_sensitive_value():
CATEGORY_PREFIX_MAP = {
    "wifi_ssid": "WIFI",
    "credential": "CRED",
    "device_name": "DEVICE",
    "suspicious": "SENSITIVE",
}
# Unknown categories → "SENSITIVE"
```

### Internal Caching

Per-hasher instance cache (`dict[str, str]`) keyed by `PREFIX:value`:

- Ensures same value always maps to same hash within a session
- Grows unbounded (acceptable for typical HAR sizes)
- Enables correlation preservation: if `AA:BB:CC:DD:EE:FF` appears in 50 entries, it maps to the same
  `02:xx:xx:xx:xx:xx` every time

### Static Fallbacks (salt=None)

| Type    | Static Value        |
| ------- | ------------------- |
| MAC     | `XX:XX:XX:XX:XX:XX` |
| IP      | `0.0.0.0`           |
| IPv6    | `::`                |
| Email   | `x@x.invalid`       |
| Generic | `***PREFIX***`      |

## Two-Pass Model

### Pass 1: Auto-Sanitize

Entry point: `sanitize_har()` or `sanitize_har_file()`

For each HAR entry:

1. Deep copy the entry (original preserved)
1. `_sanitize_request()` → headers, cookies, POST data, query strings, URL path
1. `_sanitize_response()` → headers, cookies, content (MIME-dispatched)
1. Collect redactions and flags in `RedactionCollector`

Output: Sanitized HAR + `SanitizationReport` containing:

- `auto_redacted_counts`: Dict of category → count
- `flagged`: List of flagged values with category, confidence, reason, context
- `salt`: Session salt (for Pass 2 consistency)

Metadata embedded via `_embed_sanitization_metadata()`:

```json
{
  "log": {
    "_har_capture": {
      "sanitization": {
        "salt_mode": "salted",
        "heuristics": "flag",
        "redaction_counts": {"mac": 12, "ip": 8, "email": 3}
      },
      "_client_side_cookies": ["credential"],
      "_sanitized_credentials": [{"entry_index": 1, "location": "url_query_param"}]
    }
  }
}
```

### URL Credential Location Annotation

`sanitize_har` pre-scans the **original** entries (before sanitization replaces credentials with `AUTH_<hash>`
placeholders) and writes `_sanitized_credentials` to `log._har_capture`. This allows downstream consumers to identify
auth entries without pattern-matching the placeholder — `AUTH_<hash>` contains an underscore that falls outside the
base64 alphabet and breaks regex-based detection in the sanitized HAR.

**Algorithm** (`_detect_url_credential_entries`):

1. Called on `har_data["log"]["entries"]` before the sanitization loop runs.
1. For each entry, check the raw URL query string segments and the structured `queryString` array for bare
   `base64(user:pass)` credentials via `is_base64_credential()`.
1. Record `{"entry_index": i, "location": "url_query_param"}` for each matching entry.

**Output**:

- Empty list (`[]`) means no URL query param credentials were detected.
- Always present after `sanitize_har` — even when empty.

```python
def _detect_url_credential_entries(entries: list[dict]) -> list[dict]:
    """Return annotations for entries whose URL query params contain bare base64 credentials."""
```

### Server-Token Preservation

For `url_token` auth flows the server responds with an opaque session token in the response body after receiving a
`base64(user:pass)` URL credential. That token is a server-issued artifact, not a user secret, and must be preserved for
HAR replay fidelity.

**Problem**: After the [decode-first discriminator](#response-content-dispatch) rules out structured base64-JSON
payloads, the response-body credential guard (`_sanitize_response_content`) fires on any remaining body that
`is_base64_credential()` matches — including server tokens that happen to decode to the `x:y` format.

**Heuristic** (`_is_echoed_credential`): When the entry's request URL contained a base64 credential, the response body
is only redacted if it **echoes** that credential:

- body equals the raw URL credential exactly, or
- body equals `btoa(username)`, `btoa(password)`, or `btoa(username:password)` derived from the decoded credential.

Otherwise the body is a server-generated token and is preserved unchanged.

When no URL credential context is available (e.g. `sanitize_entry` called in isolation), the conservative fallback
applies: any response body matching `is_base64_credential()` is redacted.

**Helpers**:

```python
def _extract_url_credential_raw(request: dict) -> str | None:
    """Return the raw base64 credential from a request's URL query params, or None."""

def _is_echoed_credential(body: str, url_cred_raw: str) -> bool:
    """True if body echoes the URL credential or a decoded component of it."""
```

**Context threading**: `sanitize_har` builds a `{entry_index: raw_cred}` map from the pre-scan results, then passes
`_url_cred_raw` through `sanitize_entry → _sanitize_response → _sanitize_response_content` for each entry that had a URL
credential.

### Cookie Origin Annotation

`sanitize_har` compares cookie names across all entries to detect cookies set client-side (via JavaScript) rather than
via `Set-Cookie` response headers. The result is written to `log._har_capture._client_side_cookies`.

**Algorithm** (`_detect_client_side_cookies`):

1. Scan every response `Set-Cookie` header across all entries; collect cookie names into a set.
1. Scan every request `Cookie` header across all entries; collect cookie names in first-appearance order (deduped).
1. Return names present in request cookies but absent from the `Set-Cookie` set.

**Output**:

- Cookie names only — no values are written.
- Empty list (`[]`) means all cookies in the capture were server-set.
- Order matches first appearance in request `Cookie` headers across the capture.

**Helpers**:

```python
def _parse_cookie_names(cookie_header_value: str) -> list[str]:
    """Parse names from a Cookie request header (name=value; name2=value2)."""

def _parse_set_cookie_name(set_cookie_value: str) -> str | None:
    """Parse the cookie name from a Set-Cookie response header value."""

def _detect_client_side_cookies(entries: list[dict]) -> list[str]:
    """Return cookie names from request headers never set by any Set-Cookie response."""
```

### Pass 2: Interactive Review

Entry point: `apply_user_redactions(report)`

1. User reviews flagged items and sets status: `USER_REDACTED` or `USER_SKIPPED`
1. For each `USER_REDACTED` item:
   - Recreate hasher with original salt from report
   - Hash value: `hasher.hash_generic(original_value, CATEGORY)`
   - JSON-escape both original and redacted values
   - Global find-and-replace in serialized HAR text
1. Parse HAR back from JSON
1. Return modified data

### Pre-Sanitization Detection

```python
def appears_sanitized(content: str) -> bool:
    """Check if file already contains redaction placeholders."""
```

Detects common redaction markers to warn users before double-sanitizing.

## Constraints / Invariants

1. **Pass ordering is critical** — Pass 1 must complete before Pass 2, because Pass 2 relies on the salt and flagged
   values from Pass 1's report.
1. **Same salt for both passes** — Pass 2 recreates the hasher with the salt stored in Pass 1's report, ensuring
   consistent hashing across passes.
1. **Scanner order matters** — Earlier scanners in html.py may redact values that later scanners check. For example, MAC
   scanner (pass 3) runs before IP scanner (pass 5), so MAC addresses aren't misidentified as hex strings.
1. **Depth limit prevents stack overflow** — JSON recursive traversal is capped at 50 levels. Exceeding the limit is
   logged, not fatal.
1. **Malformed input doesn't abort** — JSON decode errors, redaction failures, and invalid regex patterns are logged but
   don't stop sanitization of other entries.
1. **Format preservation is collision-free** — Reserved IP ranges (TEST-NET, documentation prefixes, locally
   administered MACs) cannot appear in real traffic, so hash outputs never collide with genuine values.
1. **Known patterns always apply** — MACs, IPs, and emails are auto-redacted regardless of heuristic mode. Heuristic
   mode only affects opaque/suspicious values.
1. **Cookie metadata is preserved** — Cookie attributes (HttpOnly, Secure, SameSite, Path, Domain, Expires) are detected
   and not redacted. Only cookie values are redacted.
1. **Credit card detection requires Luhn** — A 16-digit number is only redacted as a credit card if it passes Luhn
   checksum validation.
1. **Global find-replace in Pass 2** — User-selected redactions are applied via string replacement on the serialized
   JSON, ensuring all occurrences (headers, body, URLs) are caught.
1. **Scanner passes require 100% confidence** — Every regex in the HTML scanner pipeline (passes 0–16) auto-redacts
   without user review. A pattern that produces false positives is a bug. Patterns that cannot achieve 100% confidence
   belong in the heuristic engine (flagged for user review), not the scanner pipeline.
