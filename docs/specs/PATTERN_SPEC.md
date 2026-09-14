# Pattern Spec

## Purpose

This spec describes the pattern system that drives har-capture's sanitization engine. It covers the file format, core vs
domain patterns, merge order, and the section schema for each pattern type. It also documents the loader architecture
(compile, cache, invalidate).

## Key Files

| File                                                   | Role                                                                                                                                     |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `src/har_capture/patterns/loader.py`                   | Load, merge, compile, resolve, and cache patterns                                                                                        |
| `src/har_capture/patterns/pii.json`                    | Universal PII detection patterns                                                                                                         |
| `src/har_capture/patterns/sensitive.json`              | Universal headers, field patterns, safe values                                                                                           |
| `src/har_capture/patterns/allowlist.json`              | Already-redacted value recognition                                                                                                       |
| `src/har_capture/patterns/capture.json`                | Bloat extensions, session cookie names, password field names                                                                             |
| `src/har_capture/patterns/domains/__init__.py`         | Domain package init                                                                                                                      |
| `src/har_capture/patterns/domains/network_device.json` | Network device domain knowledge                                                                                                          |
| `src/har_capture/patterns/redaction.py`                | `is_redacted()` and the detection primitives shared by sanitize and validate (see [Redaction Checking](#redaction-checking-redactionpy)) |

## File Format

All pattern files are JSON with optional metadata keys prefixed by `_`:

```json
{
  "_description": "Human-readable purpose of this file",
  "_comment": "Ignored during merge",
  "section_name": { ... }
}
```

Underscore-prefixed keys are skipped during the merge process.

## Core Pattern Files

### pii.json — PII Detection Patterns

```json
{
  "patterns": {
    "pattern_name": {
      "regex": "regex_string",
      "replacement_prefix": "PREFIX",
      "flags": ["IGNORECASE"],
      "require_hex_letter": false,
      "description": "What this pattern detects"
    }
  },
  "preserved_gateway_ips": ["192.168.1.1", "10.0.0.1", "192.168.0.1"]
}
```

**Schema: `patterns` dict**

| Field                | Type       | Required | Description                                                                                                    |
| -------------------- | ---------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| `regex`              | string     | Yes      | Python regex pattern for matching PII                                                                          |
| `replacement_prefix` | string     | Yes      | Prefix used when hashing (MAC, SERIAL, EMAIL, etc.)                                                            |
| `flags`              | string\[\] | No       | Regex flags: IGNORECASE, MULTILINE, DOTALL                                                                     |
| `require_hex_letter` | bool       | No       | `check_for_pii` only: reject matches without a-f chars                                                         |
| `value_group`        | int        | No       | `check_for_pii`: the group holding the value, judged against the allowlist (default and fallback: whole match) |
| `description`        | string     | No       | Human-readable description                                                                                     |

**Built-in patterns:**

| Name              | Prefix              | What It Matches                                                                  |
| ----------------- | ------------------- | -------------------------------------------------------------------------------- |
| mac_address       | MAC                 | `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF` (`MAC_RE`)                              |
| serial_number     | SERIAL              | A serial label and its value (`SERIAL_LABEL_RE`)                                 |
| wps_pin           | PIN                 | A WPS/pairing/default PIN label and 8 digits (`WPS_PIN_LABEL_RE`)                |
| account_id        | ACCOUNT             | An Account/Subscriber/Customer/Device ID label and value (`ACCOUNT_LABEL_RE`)    |
| private_ip        | (format-preserving) | 10.x, 172.16-31.x, 192.168.x (`PRIVATE_IP_RE`)                                   |
| public_ip         | (format-preserving) | Non-private, non-reserved IPv4 (`PUBLIC_IP_RE`)                                  |
| ipv6              | (format-preserving) | IPv6 full and compressed forms (`IPV6_RE`)                                       |
| email             | (format-preserving) | RFC 5321 simplified (`EMAIL_RE`)                                                 |
| password_field    | PASS                | A password/passphrase/psk/glued-`key` label and its value (`PASSWORD_FIELD_RE`)  |
| password_input    | PASS                | An `<input type=password>` value (`PASSWORD_INPUT_RE`)                           |
| session_token     | TOKEN               | A session/token/auth/cookie label and a 20+ character value (`SESSION_TOKEN_RE`) |
| csrf_token        | CSRF                | A `<meta name=csrf-token>` content value (`CSRF_META_RE`)                        |
| config_path       | CONFIG              | .cfg file references                                                             |
| motorola_password | PASS                | Motorola `var CurrentPw… = '…'` script variables                                 |
| ssn               | SSN                 | Social Security Number (flagged, not auto-redacted)                              |
| credit_card\_\*   | CC                  | Visa/MC/Amex with Luhn validation                                                |

The labeled and tag patterns are the sanitizer's compiled regexes verbatim, pinned by a test, so `check_for_pii` reports
what the HTML engine replaces.

**`preserved_gateway_ips`**: Array of IP addresses that should never be redacted. These are common router gateway
addresses that appear in every device capture and don't constitute PII (e.g., `192.168.1.1`, `192.168.0.1`, `10.0.0.1`).

### sensitive.json — Headers, Fields, Safe Values

```json
{
  "headers": {
    "full_redact": ["x-auth-token", "x-api-key"],
    "cookie_redact": ["cookie", "set-cookie", "set-cookie2"],
    "scheme_redact": ["authorization", "proxy-authorization"]
  },
  "fields": {
    "auto_redact_patterns": ["password", "secret", "token", "\\bkey\\b", "\\bauth\\b"],
    "flag_patterns": ["username", "domain", "account_id"]
  },
  "tagValueList": {
    "safe_values": ["good", "ok", "enabled", "disabled", "locked", "success"]
  },
  "heuristics": {
    "safe_value_patterns": [
      {"regex": "^\\d+$", "_comment": "Pure numbers"},
      {"regex": "^-?\\d+\\.?\\d*\\s*dBm?V?$", "_comment": "Signal levels"}
    ],
    "detectors": []
  }
}
```

**Schema: `headers`**

Names match exactly (case-insensitive), in the sanitizer and `validate` alike: `cookie` names the `Cookie` header, not
`X-Cookie-Consent`.

| Field           | Type       | Description                                                                                                                                                                                             |
| --------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `full_redact`   | string\[\] | Header names (case-insensitive) whose values are fully replaced                                                                                                                                         |
| `cookie_redact` | string\[\] | Header names with cookie-style values (names preserved, values redacted); `set-cookie` and `set-cookie2` are read with Set-Cookie grammar, any other name as a list of pairs                            |
| `scheme_redact` | string\[\] | Header names with RFC 7235 `Scheme credentials` syntax. Recognized scheme tokens (`Basic`, `Bearer`, `Digest`, `NTLM`, `Negotiate`, `OAuth`) are preserved; unknown schemes fall through to full redact |

**Schema: `fields`**

| Field                  | Type       | Description                                                                  |
| ---------------------- | ---------- | ---------------------------------------------------------------------------- |
| `auto_redact_patterns` | string\[\] | Regex patterns for field names that trigger auto-redaction (100% confidence) |
| `flag_patterns`        | string\[\] | Regex patterns for field names that trigger flagging (lower confidence)      |

**Schema: `tagValueList`**

| Field         | Type       | Description                                                      |
| ------------- | ---------- | ---------------------------------------------------------------- |
| `safe_values` | string\[\] | Case-insensitive exact-match strings safe in pipe-delimited data |

**Schema: `heuristics`**

| Field                 | Type       | Description                                             |
| --------------------- | ---------- | ------------------------------------------------------- |
| `safe_value_patterns` | object\[\] | Regex patterns for values that should never be flagged  |
| `detectors`           | object\[\] | Heuristic detector configurations (see Domain Patterns) |

### allowlist.json — Redaction Recognition

```json
{
  "static_placeholders": {
    "values": ["XX:XX:XX:XX:XX:XX", "0.0.0.0", "::", "x@x.invalid", "[REDACTED]"]
  },
  "format_preserving_patterns": {
    "mac": {
      "pattern": "^02([:-])[0-9a-f]{2}(?:\\1[0-9a-f]{2}){4}$",
      "description": "Locally administered MAC, colon or hyphen layout"
    },
    "private_ip": {
      "pattern": "^10\\.255\\.\\d{1,3}\\.\\d{1,3}$",
      "description": "Redacted private IP (10.255.x.x)"
    },
    "public_ip": {
      "pattern": "^192\\.0\\.2\\.\\d{1,3}$",
      "description": "Redacted public IP (192.0.2.x)"
    },
    "ipv6": {
      "pattern": "^2001:db8::",
      "description": "Redacted IPv6 (2001:db8::)"
    },
    "email": {
      "pattern": "@redacted\\.invalid$",
      "description": "Redacted email (@redacted.invalid)"
    }
  },
  "hash_prefixes": {
    "values": [
      "SERIAL_", "ACCOUNT_", "PASS_", "TOKEN_", "CSRF_", "CONFIG_",
      "WIFI_", "DEVICE_", "FIELD_", "AUTH_", "COOKIE_", "STORAGE_",
      "CRED_", "SENSITIVE_", "MAC_"
    ]
  },
  "redaction_patterns": {
    "values": [
      "\\[REDACTED\\]", "REDACTED", "XXX+", "0{6,}",
      "\\*\\*\\*[A-Z]+\\*\\*\\*"
    ]
  }
}
```

Used by `is_redacted()` in `redaction.py` to determine whether a value has already been sanitized.

Check order:

1. Static placeholders — exact string match
1. Hash prefixes — `value.startswith(prefix)`
1. Format-preserving patterns — regex match
1. Redaction patterns — regex match

### capture.json — Capture Settings (Bloat Extensions, Session Cookies, Password Fields)

```json
{
  "bloat_extensions": {
    "fonts": [".woff", ".woff2", ".ttf", ".otf", ".eot"],
    "images": [".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp"],
    "media": [".mp3", ".mp4", ".wav", ".webm", ".ogg", ".avi", ".mov"],
    "sourcemaps": [".map"]
  },
  "session_cookies": {
    "name_patterns": ["^phpsessid$", "^jsessionid$", "^sess(?:ion)?_?id$", "..."]
  },
  "password_fields": {
    "name_patterns": ["pass(?:word|wd|phrase)?", "pwd", "pws", "psk"]
  }
}
```

`bloat_extensions` is used by `CaptureOptions.get_bloat_extensions()` in `browser.py`. Sourcemaps are always filtered;
fonts/images/media are filtered unless `--include-fonts/images/media` flags are set.

`session_cookies.name_patterns` is used by `get_session_cookie_patterns()` and read by
[capture-completeness validation](VALIDATION_SPEC.md#capture-completeness-validation) to detect a recording that began
mid-session. Entries are case-insensitive full-match regexes tested against cookie **names** only — no cookie values are
read, so this list carries no PII risk.

`password_fields.name_patterns` is used by `get_password_field_patterns()` and read by capture-completeness validation
to count credential submissions (POSTs carrying a password-named parameter), which drives the
[`single_credential_post`](VALIDATION_SPEC.md#capture-completeness-validation) warning. Entries are case-insensitive
substring-match regexes tested against POST parameter **names** only. The list is deliberately narrower than
`sensitive.json` `auto_redact_patterns` — token/secret fields ride along on every form and would inflate the count.

**Merge semantics:** a custom capture-settings file extends all three sections. `bloat_extensions` categories extend
per-category (unknown categories are added); `session_cookies.name_patterns` and `password_fields.name_patterns` extend
the built-in lists. Nothing replaces built-ins.

## Domain Pattern Files

### Full Schema

A domain file can contain any combination of these sections:

```json
{
  "_description": "Human-readable domain description",

  "heuristics": {
    "safe_value_patterns": [
      {"regex": "^pattern$", "flags": ["IGNORECASE"], "_comment": "What this matches"}
    ],
    "detectors": [
      {
        "category": "wifi_ssid",
        "confidence": "medium",
        "min_length": 3,
        "max_length": 32,
        "requires_letter": true,
        "patterns": [
          {"regex": "pattern", "flags": ["IGNORECASE"], "reason": "Why this matches"}
        ],
        "camelcase": true
      }
    ]
  },

  "tagValueList": {
    "safe_values": ["domain-specific-safe-value"]
  },

  "include_patterns": ["mac_address", "serial_number", "private_ip", "public_ip", "ipv6", "email"],

  "pii": {
    "patterns": {
      "pattern_name": {
        "regex": "pattern",
        "replacement_prefix": "PREFIX",
        "description": "What this detects"
      }
    }
  }
}
```

### Section: `heuristics.safe_value_patterns`

Regex patterns for values that should **never** be flagged in this domain. Extends the core safe patterns.

```json
{"regex": "^802\\.11[a-z/]+$", "flags": ["IGNORECASE"], "_comment": "WiFi standards"}
```

| Field      | Type       | Required | Description          |
| ---------- | ---------- | -------- | -------------------- |
| `regex`    | string     | Yes      | Python regex pattern |
| `flags`    | string\[\] | No       | Regex flags          |
| `_comment` | string     | No       | Ignored during load  |

Examples of domain-specific safe values:

- WiFi bands: `2.4g`, `5g`, `6g`, `2.4GHz`, `5GHz`
- Security types: `WPA`, `WPA2`, `WPA2-PSK`, `WPA2-PSK AES-CCMP`
- WiFi standards: `802.11ac`, `802.11n/ac`
- Speed descriptions: `Up to 300 Mbps`, `1000 Mbps`
- Config filenames: `GatewaySettings1.bin`, `settings.cfg`
- Hardware models: `C279T00-01`, `C3700-100NAS`

### Section: `heuristics.detectors`

Data-driven heuristic detectors that the core engine executes.

| Field             | Type       | Required | Description                                                                        |
| ----------------- | ---------- | -------- | ---------------------------------------------------------------------------------- |
| `category`        | string     | Yes      | Detection category (wifi_ssid, device_name, serial_number, credential, suspicious) |
| `confidence`      | string     | Yes      | Default confidence: "low", "medium", "high" — see the deterministic rule below     |
| `min_length`      | int        | Yes      | Minimum string length to consider                                                  |
| `max_length`      | int        | Yes      | Maximum string length to consider                                                  |
| `requires_letter` | bool       | Yes      | Must contain alphabetic character                                                  |
| `patterns`        | object\[\] | Yes      | Array of `{regex, flags, reason}`                                                  |
| `camelcase`       | bool       | No       | Enable CamelCase matching (default: false)                                         |

Detector pattern entry:

| Field    | Type       | Required | Description                          |
| -------- | ---------- | -------- | ------------------------------------ |
| `regex`  | string     | Yes      | Pattern to match suspicious values   |
| `flags`  | string\[\] | No       | Regex flags                          |
| `reason` | string     | Yes      | Human-readable explanation for match |

The detection loop in `heuristics.py`:

1. Check `len(value)` against `min_length` / `max_length` — reject if out of bounds
1. If `requires_letter`: reject if no alphabetic characters
1. Run each regex pattern — first match wins, return `(True, reason)`
1. If `camelcase=True` and no pattern matched: check `^[A-Z][a-z]+[A-Z][a-zA-Z0-9]*$`

**Deterministic rule for `serial_number` @ `high`:** a `serial_number` detector declared at **high** confidence asserts
a known vendor serial layout and is treated as deterministic, not heuristic
([ADR-13](../ARCHITECTURE_DECISIONS.md#adr-13-high-confidence-vendor-serial-formats-are-deterministic--auto-redact-and-validate-error-delimiter-aware)):
the sanitizer auto-redacts a fullmatch on a delimiter-bounded candidate token (`redact_vendor_serials`, using
`VENDOR_SERIAL_TOKEN_RE` / `high_confidence_serial_detectors` / `match_vendor_serial` from `loader.py`), and
`har-capture validate` errors on an unredacted match. Declaring `"confidence": "high"` on a `serial_number` detector
therefore carries the scanner pipeline's 100%-confidence bar — a layout that cannot meet it stays at `medium` (flag for
review). Other categories at `high` keep the ordinary heuristic meaning (review pre-selection).

### Section: `tagValueList.safe_values`

Case-insensitive exact-match strings safe in pipe-delimited data. Domain-specific technical vocabulary.

Examples for `network-device`: `qam256`, `atdma`, `bpi+`, `honor mdd`, `dhcpclient`

### Section: `include_patterns`

Top-level list of PII pattern names that are relevant to this domain. When present, only matching patterns survive the
merge — all others are removed. Supports exact names and glob wildcards. Applied by `load_pii_patterns()` after custom
patterns are merged into the core set.

```json
{
  "include_patterns": ["mac_address", "serial_number", "private_ip", "public_ip", "ipv6", "email", "docsis_account"],

  "patterns": {
    "docsis_account": {
      "regex": "\\bCM-ACCT-\\d{8,}\\b",
      "replacement_prefix": "DOCSIS",
      "description": "DOCSIS cable modem account identifier"
    }
  }
}
```

| Field              | Type       | Description                                          |
| ------------------ | ---------- | ---------------------------------------------------- |
| `include_patterns` | string\[\] | Pattern names or globs to keep in the merged PII set |

The domain knows its data. A cable modem page contains MAC addresses, IPs, and serial numbers — not credit cards or
SSNs. The domain declares which PII categories are relevant, including both core patterns and domain-added patterns from
`pii.patterns`. The inclusion filter runs after the merge, so domain-specific patterns are first-class citizens
alongside core patterns.

When `include_patterns` is absent, all core patterns are applied (backward compatible). When multiple `--patterns` files
are specified, `include_patterns` lists are accumulated across all files before being applied.

As domain-specific patterns prove valuable across multiple consumers, they can be graduated to core (`pii.json`) — at
which point existing domain files that already name them in `include_patterns` continue to work unchanged.

### Section: `pii.patterns`

Additional PII patterns for deterministic auto-redaction (Pass 0 of the HTML scanner). Same schema as `pii.json`
`patterns` entries.

**Confidence requirement:** Every pattern runs as auto-redact — the matched value is replaced without user review.
Patterns MUST achieve 100% confidence. If a pattern cannot meet this bar, use `heuristics.detectors` instead.

| Criterion      | `pii.patterns`              | `heuristics.detectors`      |
| -------------- | --------------------------- | --------------------------- |
| Confidence     | 100% — zero false positives | Lower confidence acceptable |
| Action         | Auto-redact (irreversible)  | Flag for user review        |
| Pipeline stage | Pass 0 (scanner)            | Heuristic engine            |

### Built-in Domain: `network_device.json`

The built-in network device domain provides:

- Safe value patterns for WiFi standards, modulation types, security protocols
- WiFi SSID detector (band suffixes, common prefixes, CamelCase)
- Device name detector (possessives, router brands, consumer devices)
- Serial number detectors, split by confidence: known vendor layouts (13-char Netgear formats — issue #49 C7000v2,
  CM2500 7S-prefix) at **high**, making them deterministic (auto-redacted by the sanitizer, error-level in validate —
  see the deterministic rule above), plus a generic uppercase-alphanumeric backstop at **medium** (flag for review)
- Domain-specific safe values for DOCSIS/cable modem vocabulary

## Merge Order

When multiple `--patterns` arguments are specified:

```text
Layer 1: Core patterns (always loaded)
  pii.json + sensitive.json + allowlist.json + capture.json

Layer 2: First --patterns argument
  Resolved and merged on top of core

Layer 3: Second --patterns argument
  Merged on top of Layer 2

Layer N: Nth --patterns argument
  Merged on top of Layer N-1
```

Merge semantics (applied at each layer):

```python
# Lists are extended (custom appended to builtin).
# `headers.scheme_redact` is optional in the built-in JSON; the loader uses
# setdefault to extend whether or not the built-in section declares it.
for header_key in ("full_redact", "cookie_redact", "scheme_redact"):
    if header_key in custom["headers"]:
        builtin["headers"].setdefault(header_key, []).extend(
            custom["headers"][header_key]
        )

# Field-name regex lists extend additively, tier by tier. The legacy
# `patterns` key predates the tier split; its names join the auto-redact tier.
for key, tier in (("auto_redact_patterns", "auto_redact_patterns"),
                  ("flag_patterns", "flag_patterns"),
                  ("patterns", "auto_redact_patterns")):
    builtin["fields"].setdefault(tier, []).extend(custom["fields"].get(key, []))

# Custom patterns add to the built-ins or replace them by name — except a
# built-in the sanitizer applies with a pass of its own (DEDICATED_PASS_PATTERNS:
# mac_address, serial_number, account_id, the address and email patterns, the
# HTML engine's labeled patterns), which is ignored with a warning: its pass
# does not read the file's regex, so a custom one would change what
# check_for_pii reports and nothing the sanitizer removes.
for name, definition in custom["patterns"].items():
    if name not in DEDICATED_PASS_PATTERNS:
        builtin["patterns"][name] = definition

# Missing sections are handled gracefully
builtin.setdefault("heuristics", {})
```

> **Note:** Prior to 0.7.0, `load_sensitive_patterns` merged only the legacy `fields.patterns` key and silently dropped
> `fields.auto_redact_patterns` / `fields.flag_patterns` from custom inputs — even though both keys appear in the
> built-in `sensitive.json` schema. The merge now honors all three. File- or dict-based consumers that previously worked
> around this by editing `sensitive.json` directly can switch to the `custom_patterns` kwarg.

## Loader Architecture

### Loading Functions

```python
# Load PII patterns (pii.json + custom)
def load_pii_patterns(custom_path: str | None = None) -> dict:

# Load sensitive patterns (sensitive.json + custom)
def load_sensitive_patterns(custom_path: str | None = None) -> dict:

# Load allowlist patterns (allowlist.json + custom)
def load_allowlist(custom_path: str | None = None) -> dict:

# Load capture settings (capture.json)
def load_capture_settings(custom_path: Path | str | None = None) -> dict:

# Session cookie name regexes for capture-completeness validation
def get_session_cookie_patterns(custom_path: Path | str | None = None) -> list[str]:

# Compile heuristic detectors from sensitive patterns
def compile_detectors(sensitive: dict) -> list[CompiledDetector]:

# Filter to deterministic vendor serial detectors (serial_number @ high)
def high_confidence_serial_detectors(detectors: list[CompiledDetector]) -> list[CompiledDetector]:

# Fullmatch a delimiter-bounded candidate token against vendor serial detectors
def match_vendor_serial(token: str, detectors: list[CompiledDetector]) -> str | None:

# Compile safe value patterns from sensitive patterns
def compile_safe_value_patterns(sensitive: dict) -> list[re.Pattern]:

# Resolve --patterns argument to file path
def resolve_patterns_arg(name_or_path: str) -> Path:

# List available built-in domain patterns
def list_domains() -> list[dict]:  # [{name, description, path}]
```

### Name Resolution

`resolve_patterns_arg()` handles:

- **Built-in names**: `network-device` → `patterns/domains/network_device.json`
  - Normalizes hyphens to underscores: `network-device` = `network_device`
- **File paths**: `./custom.json` → validated to exist
- **Unknown names / missing files**: Raises `PatternLoadError`

### Regex Compilation

`compile_pattern()` compiles a regex string with optional flags:

```python
def compile_pattern(pattern_dict: dict) -> re.Pattern | None:
    """Compile {regex, flags} dict. Returns None on invalid regex (logged, not fatal)."""
```

Invalid regex patterns (unclosed brackets, quantifier at start, duplicate group names) return `None` — they are skipped
with one warning per distinct pattern (compilation is cached), so one bad pattern doesn't break the entire system. The
HTML engine's pass 0 and `check_for_pii` both compile custom `pii.json` patterns through it, so every flag a pattern
names (`IGNORECASE`, `MULTILINE`, `DOTALL`) holds in both, and an invalid one crashes neither. A pattern file is user
input: `flags` may be one name or any collection of names, an entry that is not a flag name is ignored with a warning, a
pre-compiled `re.Pattern` keeps its own flags, and any other `regex` that is not a string skips the pattern with a
warning (once per distinct pattern).

### Cache

The loader uses an LRU cache for file-based patterns:

```python
_pattern_cache: OrderedDict  # {key: value}
# Key format: "{type}:{normalized_absolute_path}"
# Max size: 20 entries
# Eviction: Oldest (least recently used) removed on overflow
```

**Caching rules:**

- **Cached**: File-based patterns only (with normalized absolute path as key)
- **Not cached**: Dict-passed patterns (ephemeral, per-call)
- **No TTL**: Cache persists until explicitly cleared or session ends
- **No auto-invalidation**: File changes are not detected (session-scoped)

**Cache API:**

```python
def _cache_get(key: str) -> dict | None:
    """Get from cache, move to most-recently-used position."""

def _cache_set(key: str, value: dict) -> None:
    """Set in cache, evict oldest if at capacity."""

def clear_pattern_cache() -> None:
    """Clear all cached patterns (used in tests)."""
```

Example cache keys:

```text
"pii:/home/user/patterns/custom.json"
"sensitive:/home/user/.local/lib/python/har_capture/patterns/domains/network_device.json"
"allowlist:None"  # When no custom path
```

### Performance

- First call with a file path: loads from disk, compiles regex patterns
- Subsequent calls with same path: returns cached compiled patterns (no disk I/O, no regex compilation)
- LRU behavior: accessing a cached value moves it to the "recently used" end
- Dict-passed patterns: always processed from scratch (no caching)

## Redaction Checking (redaction.py)

### `is_redacted(value, custom_patterns=None) -> bool`

Single source of truth for checking whether a value has already been sanitized. Used by both the validation module and
the sanitization engine.

Check order:

1. **Static placeholders** — exact match against `allowlist.static_placeholders.values`
1. **Hash prefixes** — `value.startswith(prefix)` for each in `allowlist.hash_prefixes.values`
1. **Format-preserving patterns** — regex match against `allowlist.format_preserving_patterns`
1. **Redaction patterns** — regex match against `allowlist.redaction_patterns.values`

### `is_base64_credential(value) -> bool`

Detects a base64-encoded `user:pass` value:

1. Pre-filter: valid base64 characters, plausible length
1. Decode: canonical padding only, then `base64.b64decode()` with validation, strictly to UTF-8. The padding check is
   explicit because Python 3.10 accepts excess padding that 3.11+ rejects; the answer must not depend on the
   interpreter.
1. Check: the decoded string has a colon with at least one character on each side (split at the first colon, so a
   password may contain colons), and is not structured text — a URL, or an opening JSON brace or bracket

### `find_query_credential(segment) -> QueryCredential | None`

Locates a `base64(user:pass)` credential in one raw URL query segment — bare (`?<b64>`), marker-prefixed
(`?login_<b64>`), or keyed (`?t=<b64>`) — undoing URL transport encoding first. Returns the verbatim `prefix` to keep,
the `credential`, and whether it was `keyed`. Base64 of a JSON object or array or of a URL is a payload, never a
credential (`decode_base64_payload()`). Stripped padding is restored only above a length floor (11 characters) and for
printable decoded text; a segment shaped like a hash placeholder (`AUTH_d2c6b8e4`) is never read as a credential. The
single definition of a URL credential for the sanitizer, the validator and the credential annotation; see
[Sanitization Spec — URL Sanitization](SANITIZATION_SPEC.md#url-sanitization).

Companions: `query_param_segment(param)` rejoins a HAR `queryString` entry into the segment it was parsed from, and
`URL_VALUED_HEADERS` names the headers whose value is a URL (`referer`, `location`, `content-location`).

### `MAC_RE`, `mac_layout(value)` and `is_mac_value(value)`

`MAC_RE` is the one definition of a MAC address in text — six hex pairs joined by `:` or `-`, wherever they occur — for
the sanitizer, `validate`, and (through `pii.json`'s `mac_address` regex, which must equal `MAC_RE.pattern`)
`check_for_pii`. `mac_layout()` names a whole value's layout by the separator a placeholder in it is written with (`:`,
`-`, `""` for bare 12-hex, `.` for dotted 4-4-4, `None` otherwise); the hasher writes MAC placeholders from it.
`is_mac_value()` accepts any of those layouts, plus mixed separators. See
[Sanitization Spec — MAC addresses](SANITIZATION_SPEC.md#mac-addresses).

### `classify_identity_field(key, value) -> str | None`

Classifies a field whose key names a device identity and whose value has that identity's shape: `"serial_number"`,
`"mac_address"`, or `None`. The key is read as its words, lowercased and joined with `_` (`StatusSoftwareSerialNum` →
`status_software_serial_num`, `CMMACAddress` → `cmmac_address`) and as written, lowercased — an acronym run into a word
(`HWaddr`, `MACaddress`, `SERIALnumber`) splits at the wrong letter, but its spelling still names the field — and either
form must end with the identity (`SERIAL_KEY_RE`, `MAC_KEY_RE`): a serial (`serial`, `serial_number`, `serial_num`,
`serial_no`, or exactly `sn`) or a MAC (`mac`, `mac_address`, `hwaddr`, ...), optionally numbered (`macaddress_5`). The
last word may carry a glued prefix (`cmserialnumber`, `wanmacaddr`, `ethmac`) — except a word starting `hmac`, a message
authentication code; a key containing `hmac` is read as words only, since its written form has no word boundary to
exclude it by (`userHMAC`). A key whose identity is not last (`serialNumberLabel`, `MacAddressFilterEnabled`,
`macaddr.wan`) is not an identity key.

A serial value is one whitespace-free token of five or more characters carrying a digit that is not wholly a placeholder
(`is_fully_redacted()`: `SN0000001234` contains a zero run and is still a serial) — the digit rule is what excludes
status words (`N/A`, `Enabled`). A MAC value passes `is_mac_value()`; a MAC placeholder is still classified as a MAC,
since it cannot be told from a real locally administered one, and whether to skip it is the caller's decision.

`unredacted_identity(key, value, custom_patterns)` is that decision for the checkers (`validate`'s `check_json_fields`
and `check_for_pii`): `classify_identity_field()`, less a MAC placeholder in any layout (`is_mac_placeholder()`: one
uniform layout, lowercase, first octet `02` — trusted only under a MAC-named key), a constant MAC, or an allowlisted
value. `credential_value_action(value)` decides a value a response serves under a credential-named key: `"keep"` for a
button word (`Yes`, `No` — the only words the fleet's translation tables hold there), `"review"` for prose (words on
both sides of a space), `"redact"` otherwise. The sanitizer, `validate`'s response JSON check and `check_for_pii` share
it; a value a client submits is always redacted. `is_ssid_key(key)` is true when one of a key's words is `ssid`
(`ssid_24g`, `guestSSID`): the sanitizer offers such a value for review rather than redacting it.

### `PRIVATE_IP_RE`, `PUBLIC_IP_RE`, `IPV6_RE`, `EMAIL_RE` and `is_ipv6_host_address(candidate)`

The address regexes both sanitizer engines use — the HTML engine's passes 4–6 and 11 and the string patterns that JSON
values, JSON keys and text bodies take — so whether a value is redacted never depends on its body's route. `pii.json`'s
`private_ip`, `public_ip`, `ipv6` and `email` regexes must equal their `.pattern` (a test pins them), and
`check_for_pii` skips what the engines keep: `preserved_gateway_ips`, version strings, and IPv6 candidates that are not
host addresses. An `IPV6_RE` candidate (colon-terminated hex groups ending in a hex group or, for an IPv4-mapped
address, a dotted quad; not glued to a word or colon on either side) is an address only when `is_ipv6_host_address()`
accepts it: `ipaddress` parses it — after unpadding a dotted-quad tail's zero-padded octets (`::ffff:192.168.001.100`),
as the IPv4 passes read a padded quad — and it is not the unspecified `::` or loopback `::1` — protocol constants like
IPv4's `0.x` and `127.x`. `validate`'s IPv6 scan and `check_for_pii` apply the same test. Both engines run IPv6 ahead of
the IPv4 passes, so an IPv4-mapped address is hashed as one.

### `route_body(mime_type, text)`

The one routing decision for a response body's text, shared by the sanitizer and `validate`: `"json"` when the text
parses as a JSON object or array whatever the type declares (HNAP answers JSON as `text/html`); else `"html"` for a
markup `mime_kind()` and `"text"` for any other text kind; a type that says nothing about text is sniffed — `<` opens
markup, else text. It returns the route with the parsed JSON, so neither tool parses a response body twice. See
[Sanitization Spec — Response Content Dispatch](SANITIZATION_SPEC.md#response-content-dispatch).

`JSON_MAX_DEPTH` (50) is how deep the key rules reach — the sanitizer's walker, `check_json_fields` and
`check_for_pii`'s identity fields all stop there. `iter_json_strings()` yields every decoded string of a parsed body —
values and keys, at any depth — the unit of text both tools' text passes read. `ipv6_host_spans()` gives the spans of
the IPv6 host addresses in a text, so a checker does not report an IPv4-mapped address's tail again as IPv4.

### `mime_kind(mime)`, `is_text_mime(mime)` and `decode_transport_body(content)`

`mime_kind()` is the one mime vocabulary: `"markup"` (HTML, XML, any `+xml`), `"json"` (any `json` or `x-json` subtype
or `+json` suffix, whatever the type — DM1000's `applation/json` counts), `"text"` (other `text/*`, JavaScript, form
data), or `None` when the type says nothing about text. A subtype that merely contains `json` or `xml` is neither.
`is_text_mime()` is `mime_kind() is not None`.

`decode_transport_body()` returns the text a HAR body carries. A body without `encoding` is already text; a `base64`
body is decoded with the mime type's declared charset — or strictly as UTF-8 when none is declared, or the declared one
is unknown or not a text encoding (`hex`, `zlib`). When that fails under a text type, the bytes are read as latin-1.
Otherwise bytes that do not decode, an empty result, or text holding NUL mean binary, and return `None`. See
[ADR-16](../ARCHITECTURE_DECISIONS.md#adr-16-transport-encoding-is-not-content).

### `parse_json_container(text)` and `is_constant_mac(mac)`

`parse_json_container()` returns the object or array JSON text holds, or `None` — for scalars, invalid JSON, and nesting
too deep for the parser or deeper than `JSON_MAX_NESTING` (400), so hostile input never crashes either tool. An object
that repeats a key parses to a `JsonObjectWithDuplicates`: the last value of each key, as every parser reads it, with
the earlier pairs in `shadowed`. `json_members()` gives an object's members with the shadowed ones. `is_constant_mac()`
is true for a MAC that is one byte repeated (broadcast `ff:ff:…`, zero `00:00:…`): a protocol constant neither tool
treats as PII.

`parse_xml(text)` is the one XML parse for the field checks both tools run on an XML body: the root element, or `None`
when the text is not well-formed. A lone surrogate, which no encoder accepts, is read as U+FFFD, so it does not switch
off the check of every field in the body. `luhn_valid(number)` is the Luhn checksum every payment card number carries:
the text path redacts, and `check_for_pii` reports, only a card-shaped number that passes it.

### `decode_base64_payload(value)` and `find_query_payload(segment)`

`decode_base64_payload()` returns the text of a base64-wrapped structured payload — a JSON object or array that parses,
or a URL — with missing or miscounted padding tolerated, or `None`. Structured text is never a credential:
`is_base64_credential()` rejects any base64 whose text opens a JSON object or array (parsed or not) or is a URL.
`find_query_payload()` locates a payload in a URL query segment, bare or keyed, as a
`QueryPayload(prefix, encoded, text, quoted)` — `quoted` records a percent-encoded original, so a rewrite can be encoded
the same way. See [Sanitization Spec — URL Sanitization](SANITIZATION_SPEC.md#url-sanitization).

### `split_url_password(url)`

Splits out the password a URL's userinfo carries (the `user:password` part ahead of the host) as
`(before, password, after)`, so the URL reassembles byte-for-byte, or returns `None`. The authority ends at the first
`/`, `?` or `#`; its userinfo runs to the authority's last `@`, as browsers parse it, and the password starts after the
userinfo's first `:`. A port or an `@` in the path is not userinfo. Shared by the sanitizer and `check_url`.

### `split_url_query(url)`, `url_query(url)` and `iter_url_credentials(request)`

`split_url_query()` splits a URL into `(before, query, after)` with `url == before + query + after`; the query runs from
the first `?` to the next `#`, so a hash route's parameters (`#/login?password=…`) are a query and a plain fragment is
not. It never raises, unlike `urlparse`, and gives back the exact bytes it read, so the sanitizer rewrites a query in
place. `url_query()` returns the query alone. `iter_url_credentials()` yields every `find_query_credential()` hit in a
HAR request: URL string segments first, then the `queryString` array's.

### `cookie_segment_actions(value, *, set_cookie)` and `is_set_cookie_attribute(segment)`

`cookie_segment_actions()` classifies each `;`-separated segment of a cookie header as `keep`, `value` (a pair whose
value is cookie data) or `token` (a valueless segment that is a nameless cookie) — the one rule the sanitizer rewrites
and `validate` checks. `is_set_cookie_attribute()` is RFC 6265's attribute grammar, which decides whether a Set-Cookie
holds no cookie at all. `SET_COOKIE_HEADERS` names the headers read with Set-Cookie grammar. See
[Sanitization Spec — Header Sanitization](SANITIZATION_SPEC.md#header-sanitization).

## Constraints / Invariants

1. **Core patterns are always loaded** — Domain patterns extend but never replace core patterns. Even with
   `--patterns custom.json`, pii.json and sensitive.json are always present.
1. **Invalid regex is non-fatal** — `compile_pattern()` returns `None` on invalid regex. The pattern is skipped, other
   patterns continue to work.
1. **Underscore keys are metadata** — Any key starting with `_` in a pattern file is skipped during merge. This is a
   convention for comments and metadata.
1. **Lists extend, dicts update** — This is the universal merge semantic. Custom lists are appended (never replace),
   custom dict keys override (but don't delete existing keys) — except a custom `pii.json` pattern named like a built-in
   with a pass of its own (`DEDICATED_PASS_PATTERNS`), which is ignored with one warning per name.
1. **Name normalization** — Built-in domain names normalize hyphens to underscores: `network-device` and
   `network_device` resolve to the same file.
1. **Cache is session-scoped** — Pattern files are not re-read after initial load within a session. File changes require
   a new session or explicit `clear_pattern_cache()`.
1. **Allowlist patterns name placeholder formats** — Format-preserving hash ranges are chosen from reserved space:
   TEST-NET and documentation IP ranges cannot appear in legitimate traffic. Locally administered MACs can, so the MAC
   pattern also matches a real colon- or hyphen-form MAC starting `02`. The sanitizer never skips a MAC because of it
   (see [Sanitization Spec — Idempotency Boundary](SANITIZATION_SPEC.md#idempotency-boundary)); anywhere else
   `is_redacted()` is consulted, a value written exactly in that shape counts as redacted. Placeholder layouts that
   cannot be told from ordinary data in an arbitrary field — bare 12-hex, dotted — are deliberately not listed.
1. **Pattern precedence** — Custom patterns (from domain files) have higher precedence than core patterns for the same
   key in a dict. For lists, custom patterns are appended (run after core patterns).
