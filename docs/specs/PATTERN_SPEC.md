# Pattern Spec

## Purpose

This spec describes the pattern system that drives har-capture's sanitization engine. It covers the file format, core vs domain patterns, merge order, and the section schema for each pattern type. It also documents the loader architecture (compile, cache, invalidate).

## Key Files

| File                                                   | Role                                                          |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| `src/har_capture/patterns/loader.py`                   | Load, merge, compile, resolve, and cache patterns             |
| `src/har_capture/patterns/pii.json`                    | Universal PII detection patterns                              |
| `src/har_capture/patterns/sensitive.json`              | Universal headers, field patterns, safe values                |
| `src/har_capture/patterns/allowlist.json`              | Already-redacted value recognition                            |
| `src/har_capture/patterns/capture.json`                | Bloat file extension filtering                                |
| `src/har_capture/patterns/domains/__init__.py`         | Domain package init                                           |
| `src/har_capture/patterns/domains/network_device.json` | Network device domain knowledge                               |
| `src/har_capture/patterns/redaction.py`                | `is_redacted()`, `is_allowlisted()`, `is_base64_credential()` |

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

| Field                | Type       | Required | Description                                                      |
| -------------------- | ---------- | -------- | ---------------------------------------------------------------- |
| `regex`              | string     | Yes      | Python regex pattern for matching PII                            |
| `replacement_prefix` | string     | Yes      | Prefix used when hashing (MAC, SERIAL, EMAIL, etc.)              |
| `flags`              | string\[\] | No       | Regex flags: IGNORECASE, MULTILINE, DOTALL                       |
| `require_hex_letter` | bool       | No       | For IPv6: reject matches without a-f chars (avoids time strings) |
| `description`        | string     | No       | Human-readable description                                       |

**Built-in patterns:**

| Name          | Prefix              | What It Matches                                     |
| ------------- | ------------------- | --------------------------------------------------- |
| mac_address   | MAC                 | `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`            |
| serial_number | SERIAL              | SN, S/N, Serial Number labels + values              |
| account_id    | ACCOUNT             | Account, Subscriber, Customer, Device ID labels     |
| private_ip    | (format-preserving) | 10.x, 172.16-31.x, 192.168.x                        |
| public_ip     | (format-preserving) | Non-private, non-reserved IPv4                      |
| ipv6          | (format-preserving) | IPv6 full and compressed forms                      |
| email         | (format-preserving) | RFC 5321 simplified                                 |
| session_token | TOKEN               | 20+ char alphanumeric strings                       |
| csrf_token    | CSRF                | CSRF tokens in meta tags                            |
| password      | PASS                | password=, passphrase= patterns                     |
| ssn           | SSN                 | Social Security Number (flagged, not auto-redacted) |
| credit_card   | CC                  | Visa/MC/Amex with Luhn validation                   |
| config_path   | CONFIG              | .cfg file references                                |

**`preserved_gateway_ips`**: Array of IP addresses that should never be redacted. These are common router gateway addresses that appear in every device capture and don't constitute PII (e.g., `192.168.1.1`, `192.168.0.1`, `10.0.0.1`).

### sensitive.json — Headers, Fields, Safe Values

```json
{
  "headers": {
    "full_redact": ["authorization", "x-auth-token", "proxy-authorization"],
    "cookie_redact": ["cookie", "set-cookie"]
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

| Field           | Type       | Description                                                              |
| --------------- | ---------- | ------------------------------------------------------------------------ |
| `full_redact`   | string\[\] | Header names (case-insensitive) whose values are fully replaced          |
| `cookie_redact` | string\[\] | Header names with cookie-style values (names preserved, values redacted) |

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
      "pattern": "^02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$",
      "description": "Locally administered MAC (02:xx:xx:xx:xx:xx)"
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

### capture.json — Bloat Extension Filtering

```json
{
  "bloat_extensions": {
    "fonts": [".woff", ".woff2", ".ttf", ".otf", ".eot"],
    "images": [".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp"],
    "media": [".mp3", ".mp4", ".wav", ".webm", ".ogg", ".avi", ".mov"],
    "sourcemaps": [".map"]
  }
}
```

Used by `CaptureOptions.get_bloat_extensions()` in `browser.py`. Sourcemaps are always filtered; fonts/images/media are filtered unless `--include-fonts/images/media` flags are set.

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

| Field             | Type       | Required | Description                                                         |
| ----------------- | ---------- | -------- | ------------------------------------------------------------------- |
| `category`        | string     | Yes      | Detection category (wifi_ssid, device_name, credential, suspicious) |
| `confidence`      | string     | Yes      | Default confidence: "low", "medium", "high"                         |
| `min_length`      | int        | Yes      | Minimum string length to consider                                   |
| `max_length`      | int        | Yes      | Maximum string length to consider                                   |
| `requires_letter` | bool       | Yes      | Must contain alphabetic character                                   |
| `patterns`        | object\[\] | Yes      | Array of `{regex, flags, reason}`                                   |
| `camelcase`       | bool       | No       | Enable CamelCase matching (default: false)                          |

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

### Section: `tagValueList.safe_values`

Case-insensitive exact-match strings safe in pipe-delimited data. Domain-specific technical vocabulary.

Examples for `network-device`: `qam256`, `atdma`, `bpi+`, `honor mdd`, `dhcpclient`

### Section: `pii.patterns`

Additional PII detection patterns. Same schema as `pii.json` `patterns` entries.

### Built-in Domain: `network_device.json`

The built-in network device domain provides:

- Safe value patterns for WiFi standards, modulation types, security protocols
- WiFi SSID detector (band suffixes, common prefixes, CamelCase)
- Device name detector (possessives, router brands, consumer devices)
- Domain-specific safe values for DOCSIS/cable modem vocabulary

## Merge Order

When multiple `--patterns` arguments are specified:

```
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
# Lists are extended (custom appended to builtin)
builtin["headers"]["full_redact"].extend(custom["headers"]["full_redact"])

# Dicts are updated (custom overrides builtin keys)
builtin["patterns"].update(custom["patterns"])

# Missing sections are handled gracefully
builtin.setdefault("heuristics", {})
```

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
def load_capture_settings() -> dict:

# Compile heuristic detectors from sensitive patterns
def compile_detectors(sensitive: dict) -> list[CompiledDetector]:

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

Invalid regex patterns (unclosed brackets, quantifier at start, duplicate group names) return `None` — they are silently skipped to ensure one bad pattern doesn't break the entire system.

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

```
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

Single source of truth for checking whether a value has already been sanitized. Used by both the validation module and the sanitization engine.

Check order:

1. **Static placeholders** — exact match against `allowlist.static_placeholders.values`
1. **Hash prefixes** — `value.startswith(prefix)` for each in `allowlist.hash_prefixes.values`
1. **Format-preserving patterns** — regex match against `allowlist.format_preserving_patterns`
1. **Redaction patterns** — regex match against `allowlist.redaction_patterns.values`

### `is_base64_credential(value) -> bool`

Detects base64-encoded `user:pass` patterns in URL query parameters:

1. Pre-filter: valid base64 characters, plausible length
1. Decode: `base64.b64decode()` with validation
1. Check: decoded string contains exactly one colon separating non-empty parts

### `is_cookie_attribute_metadata(value) -> bool`

Distinguishes cookie attributes from cookie values:

- Metadata: `HttpOnly: true, Secure: true`, `SameSite=Lax`
- Not metadata: `session_id=abc123def456`

Used to avoid flagging cookie headers that only contain metadata.

## Constraints / Invariants

1. **Core patterns are always loaded** — Domain patterns extend but never replace core patterns. Even with `--patterns custom.json`, pii.json and sensitive.json are always present.
1. **Invalid regex is non-fatal** — `compile_pattern()` returns `None` on invalid regex. The pattern is skipped, other patterns continue to work.
1. **Underscore keys are metadata** — Any key starting with `_` in a pattern file is skipped during merge. This is a convention for comments and metadata.
1. **Lists extend, dicts update** — This is the universal merge semantic. Custom lists are appended (never replace), custom dict keys override (but don't delete existing keys).
1. **Name normalization** — Built-in domain names normalize hyphens to underscores: `network-device` and `network_device` resolve to the same file.
1. **Cache is session-scoped** — Pattern files are not re-read after initial load within a session. File changes require a new session or explicit `clear_pattern_cache()`.
1. **Allowlist patterns must not match real PII** — Format-preserving hash ranges (TEST-NET, documentation prefixes, locally administered MACs) are chosen specifically because they cannot appear in legitimate traffic.
1. **Pattern precedence** — Custom patterns (from domain files) have higher precedence than core patterns for the same key in a dict. For lists, custom patterns are appended (run after core patterns).
