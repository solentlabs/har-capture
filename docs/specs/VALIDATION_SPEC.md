# Validation Spec

## Purpose

This spec describes the post-sanitization validation pipeline that checks HAR files for PII that survived sanitization.
It covers what `secrets.py` checks, the difference between the `validate` CLI command and the pre-commit hook usage, how
`_sensitive_fields` and `_depth` parameters work in `check_json_fields`, and the relationship between validation
patterns and sanitization patterns.

## Key Files

| File                                      | Role                                                                           |
| ----------------------------------------- | ------------------------------------------------------------------------------ |
| `src/har_capture/validation/secrets.py`   | PII leak detection: `validate_har()`, `check_json_fields()`, finding dataclass |
| `src/har_capture/patterns/redaction.py`   | `is_redacted()` — checks if a value has already been sanitized                 |
| `src/har_capture/patterns/sensitive.json` | Sensitive header and field patterns used by validation                         |
| `src/har_capture/patterns/allowlist.json` | Redaction recognition patterns                                                 |
| `src/har_capture/cli/validate.py`         | `har-capture validate` CLI command                                             |

## Validation vs Sanitization

The validation module and sanitization module use overlapping pattern sources but serve fundamentally different
purposes:

| Aspect              | Validation (`secrets.py`)                      | Sanitization (`har.py`)                     |
| ------------------- | ---------------------------------------------- | ------------------------------------------- |
| **Purpose**         | Detect PII that wasn't redacted                | Remove PII from HAR files                   |
| **Action**          | Report findings; block commit                  | Replace values with hashes/placeholders     |
| **Trigger**         | Pre-commit hook or `validate` CLI              | `sanitize` CLI or `get` capture             |
| **Scope**           | Field names + header names + formats + content | Field values + response content             |
| **Pattern sources** | sensitive.json + hard-coded regexes            | pii.json + sensitive.json + domain          |
| **Heuristics**      | None — pattern-based only                      | Full engine (entropy, detectors, adjacency) |
| **Correlation**     | N/A                                            | Preserves via salted hashing                |
| **Output**          | `list[Finding]`                                | Sanitized HAR + `SanitizationReport`        |

**Interaction between the two:**

1. Sanitization (Pass 1) processes the HAR, replacing PII with hashes
1. Validation checks the sanitized output to verify nothing was missed
1. Validation calls `is_redacted()` to suppress findings for values that are already properly sanitized
1. Both modules load patterns from `sensitive.json`, but validation also uses hard-coded regexes for MAC, serial, and IP
   detection in content

## Finding Dataclass

```python
@dataclass
class Finding:
    severity: str    # "error" or "warning"
    location: str    # Where in the HAR (e.g., "Entry 0: https://192.168.1.1/")
    field: str       # Field name/path (e.g., "Authorization", "postData.password")
    value: str       # Truncated suspicious value (max 40 chars)
    reason: str      # Human explanation (e.g., "Sensitive header not redacted")
```

Severity levels:

- **error**: High-confidence PII leak — should block commit (sensitive headers, base64 credentials, auto-redact field
  patterns)
- **warning**: Lower confidence — informational (MAC addresses in content, serial numbers, public IPs)

## Entry Point

```python
def validate_har(
    har_path: str | Path,
    custom_patterns: str | None = None,
) -> list[Finding]:
    """Validate a HAR file for PII leaks. Returns empty list if clean."""
```

1. Load HAR (JSON or gzip-compressed)
1. For each entry in `log.entries`:
   - `check_url(entry.request.url)` → URL credential detection
   - `check_headers(entry.request.headers)` → Sensitive header detection
   - `check_headers(entry.response.headers)` → Same for response
   - `check_post_data(entry.request.postData)` → Form field + JSON body scanning
   - `check_content(entry.response.content)` → bare base64 credentials, MAC, serial, IP in text content
1. Return accumulated `list[Finding]`

## Check Functions

### `check_url(url, location, findings)`

Detects base64-encoded credentials in URL query parameters:

```text
https://device.local/api?auth=dXNlcjpwYXNz
                              ^^^^^^^^^^^^^^^^
                              base64("user:pass")
```

1. Parse URL query string
1. For each parameter value, call `is_base64_credential()`:
   - Pre-filter: valid base64 characters, plausible length
   - Decode with `base64.b64decode()` (with validation)
   - Check decoded string contains exactly one colon between non-empty parts
1. Also checks raw query string segments (avoids stripping base64 padding)

Severity: **error**

### `check_headers(headers, location, findings)`

Checks header names against the sensitive headers list from `sensitive.json`:

```python
# Sensitive headers (from sensitive.json: headers.full_redact +
# headers.cookie_redact + headers.scheme_redact):
# authorization, cookie, set-cookie, x-auth-token, x-api-key, ...
```

For each header:

1. Check if header name (case-insensitive) matches sensitive list
1. If matched, check if value is already redacted via `is_redacted()`
1. Special handling for Cookie/Set-Cookie: skip if value contains only attributes (`HttpOnly`, `Secure`, `SameSite`,
   `Path`, `Domain`, `Expires`) via `is_cookie_attribute_metadata()`
1. Skip empty header values

Severity: **error**

### `check_post_data(post_data, location, findings)`

Checks form field names and JSON body content:

**Form params** (`postData.params`):

1. For each parameter, check `name` against `auto_redact_patterns` and `flag_patterns`
1. If matched, check if `value` is already redacted
1. Report if value is not redacted

**JSON body** (`postData.text` with JSON content type):

1. Parse JSON
1. Call `check_json_fields()` for recursive scanning

**XML body** (`postData.text` with `text/xml` or `application/xml` content type):

1. Parse XML with `xml.etree.ElementTree`
1. Walk element tree, checking element tag names and attribute names against sensitive field patterns
1. Strip namespace prefixes if present (`{http://ns}tagname` → `tagname`)
1. Report findings for elements whose text content is not redacted
1. Report findings for attributes whose values are not redacted (e.g., `<field password="..."/>` where the attribute
   carries a real credential)
1. Malformed XML is caught and skipped (no findings, no crash)

Severity: **error**

### `check_content(content, location, findings, custom_patterns, *, has_sanitized_url_credential)`

Detects PII patterns in response content text:

**Bare base64 credentials:**

- Strips whitespace from the content, then calls `is_base64_credential()` on the entire body
- Matches only when the whole body is a bare `base64(user:pass)` token (e.g. a router echoing its auth token)
- Returns early after flagging — suppresses MAC/serial/IP checks on the same body to avoid noise
- When `has_sanitized_url_credential=True`, skips this check. Set by `validate_har` for entries listed in
  `log._har_capture._sanitized_credentials` — those entries' response bodies were already evaluated by the sanitizer's
  server-token preservation heuristic, so re-flagging them here would be a false positive.

Severity: **error**

**MAC addresses:**

- Pattern: `([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`
- Skips common test patterns (e.g., `AA:BB:CC:DD:EE:FF`)
- Checks via `is_redacted()` before reporting

**Serial numbers:**

- Pattern: `SN|S/N|Serial Number|SerialNum` + value — inline, in HTML table cells, or in sibling elements (tag chains
  tolerate whitespace between tags, per the sibling-element rule in
  [`SANITIZATION_SPEC.md`](SANITIZATION_SPEC.md#scanner-pipeline))
- Checks via `is_redacted()` before reporting

**Public IPs:**

- Non-private IPv4 addresses (excludes 10.x, 172.16-31.x, 192.168.x, localhost)
- Excludes redacted placeholders (10.255.x.x, 192.0.2.x)
- Validates via `is_valid_ip_address()` heuristic

**Line numbers:**

- Findings include line numbers in content for precise location

Severity: **warning**

### `check_json_fields(data, location, findings, path, custom_patterns, _sensitive_fields, _depth)`

Recursively scans JSON structures for sensitive field names.

#### Full Signature

```python
def check_json_fields(
    data: dict[str, Any] | list[Any],
    location: str,
    findings: list[Finding],
    path: str = "",
    custom_patterns: str | None = None,
    _sensitive_fields: list[re.Pattern[str]] | None = None,
    _depth: int = 0,
) -> None:
```

#### Public Parameters

| Parameter         | Type            | Description                                                   |
| ----------------- | --------------- | ------------------------------------------------------------- |
| `data`            | dict \| list    | JSON structure to scan                                        |
| `location`        | str             | HAR location for findings (e.g., "Entry 5 (request body)")    |
| `findings`        | list\[Finding\] | Accumulator list (mutated in-place)                           |
| `path`            | str             | Current path in structure (e.g., "user.credentials.password") |
| `custom_patterns` | str \| None     | Custom patterns file path                                     |

#### Internal Parameters

| Parameter           | Type                       | Description                                          |
| ------------------- | -------------------------- | ---------------------------------------------------- |
| `_sensitive_fields` | list\[re.Pattern\] \| None | Pre-compiled regex patterns — loaded once, reused    |
| `_depth`            | int                        | Recursion depth counter — checked against limit (50) |

**`_sensitive_fields` lifecycle:**

1. On first call (`_sensitive_fields=None`): loaded from `_compile_sensitive_fields(custom_patterns)`
1. Compilation combines `auto_redact_patterns` + `flag_patterns` from `sensitive.json` (plus custom)
1. On recursive calls: passed through explicitly — avoids recompilation per field
1. Same compiled patterns used for every key in the entire JSON structure

**`_depth` lifecycle:**

1. Starts at 0 on the initial call
1. Incremented by 1 before each recursive call
1. Checked against limit (50) at the start of each call
1. If `_depth > 50`: return immediately (logged, not fatal)
1. Prevents stack overflow from deeply nested or circular JSON

#### Recursion Logic

```python
def check_json_fields(data, location, findings, path="",
                      custom_patterns=None, _sensitive_fields=None, _depth=0):
    if _depth > 50:
        return

    if _sensitive_fields is None:
        _sensitive_fields = _compile_sensitive_fields(custom_patterns)

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            # Check key against sensitive patterns
            for pattern in _sensitive_fields:
                if pattern.search(key):
                    if not is_redacted(str(value)):
                        findings.append(Finding(...))
                    break
            # Recurse into nested structures
            if isinstance(value, (dict, list)):
                check_json_fields(value, location, findings, current_path,
                                  custom_patterns,
                                  _sensitive_fields=_sensitive_fields,
                                  _depth=_depth + 1)

    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                check_json_fields(item, location, findings, f"{path}[{i}]",
                                  custom_patterns,
                                  _sensitive_fields=_sensitive_fields,
                                  _depth=_depth + 1)
```

Key design decisions:

- **Pattern compilation is lazy**: Only compiled on first call, then reused
- **Depth limiting is defensive**: Protects against malicious or malformed JSON
- **Path tracking is informational**: Used in `Finding.field` for precise location

## CLI Command vs Pre-Commit Hook

### `har-capture validate` CLI Command

```bash
har-capture validate capture.har --patterns <domain|custom.json>
```

- Loads and validates a single HAR file
- Prints findings to stdout with severity, location, field, value
- Exit code 0 if no findings, 1 if findings detected
- Supports custom patterns via `--patterns`

### Pre-Commit Hook (Consumer Configuration)

Consumers who commit HAR files to their repositories can configure a pre-commit hook that calls `validate_har()`:

```yaml
# Example .pre-commit-config.yaml for consumer repos
- repo: local
  hooks:
    - id: check-har-secrets
      name: Check HAR files for secrets
      entry: har-capture validate --patterns base
      files: '\.har(\.gz)?$'
      types: [file]
```

This hook is not shipped with har-capture's own `.pre-commit-config.yaml` — it is an example configuration for
downstream consumers who store HAR files in version control.

Behavioral differences from CLI:

- Pre-commit runs on staged files only
- Non-zero exit blocks the commit
- Runs within the pre-commit framework's environment

## Redaction Integration

Before reporting a finding, validation checks whether the value is already redacted by delegating to `is_redacted()`
from `patterns/redaction.py`. If the value matches any redaction pattern (static placeholders, hash prefixes,
format-preserving patterns, or redaction indicators), the finding is suppressed.

See [Pattern Spec — Redaction Checking](PATTERN_SPEC.md#redaction-checking-redactionpy) for the full `is_redacted()`
check order and `allowlist.json` schema.

## Pattern Relationship

### Shared Pattern Source

Both validation and sanitization load from `sensitive.json`:

```text
sensitive.json
├── headers.full_redact      → Used by: validation (check_headers)
│                                        sanitization (sanitize_header_value)
├── headers.cookie_redact    → Used by: validation (check_headers)
│                                        sanitization (sanitize_header_value)
├── headers.scheme_redact    → Used by: validation (check_headers)
│                                        sanitization (sanitize_header_value, scheme-preserving branch)
├── fields.auto_redact_patterns → Used by: validation (check_json_fields, check_post_data)
│                                           sanitization (is_sensitive_field)
├── fields.flag_patterns     → Used by: validation (check_json_fields, check_post_data)
│                                        sanitization (is_flaggable_field)
└── tagValueList.safe_values → Used by: sanitization only (pipe-delimited scanner)
```

### Validation-Only Patterns

These patterns are hard-coded in `secrets.py` and not shared with sanitization:

| Pattern                 | Purpose                                     |
| ----------------------- | ------------------------------------------- |
| MAC regex               | Detect unsanitized MACs in response content |
| Serial regex            | Detect serial numbers in HTML tables        |
| IP regex                | Detect public IPs in response content       |
| Base64 credential check | Detect `user:pass` in URL query params      |

### Sanitization-Only Patterns

These patterns are used only during sanitization:

| Source                                  | Purpose                                                               |
| --------------------------------------- | --------------------------------------------------------------------- |
| `pii.json`                              | Full PII detection patterns with replacement prefixes                 |
| Domain `heuristics.detectors`           | WiFi SSID, device name detection                                      |
| Domain `heuristics.safe_value_patterns` | Domain-specific safe values                                           |
| HTML scanner passes                     | Pipe-delimited, password inputs, SSID fields (hardcoded in `html.py`) |

### Design Intent

Validation is intentionally simpler than sanitization:

- It doesn't need heuristics because it runs **after** sanitization — anything suspicious should already be caught
- It checks **field names** (which are structural and don't change) rather than analyzing **field values** heuristically
- It uses `is_redacted()` as the primary gate — if the value looks redacted, the finding is suppressed
- False positives in validation are preferable to false negatives — blocking a clean commit is annoying but safe;
  allowing a dirty commit is a PII leak

## Constraints / Invariants

1. **Validation runs after sanitization** — It checks sanitized output, not raw captures. Running validation on
   unsanitized HAR would produce overwhelming findings.
1. **Redacted values are always suppressed** — If `is_redacted(value)` returns True, no finding is generated. This is
   the contract between sanitization and validation.
1. **Depth limit prevents crashes** — `check_json_fields` caps recursion at 50 levels. Exceeding this is logged but does
   not crash or produce findings for deeper content.
1. **Pattern compilation is done once** — `_sensitive_fields` is compiled on the first call to `check_json_fields` and
   reused across all recursive invocations and all entries.
1. **Cookie metadata is distinguished** — Set-Cookie headers containing only attributes (`HttpOnly`, `Secure`,
   `SameSite`) are not flagged. Only headers with actual session values trigger findings.
1. **Severity is deterministic** — Headers and POST data are always "error"; content patterns are always "warning".
   There is no confidence scoring in validation (unlike sanitization's heuristic engine).
1. **Empty values are skipped** — Empty header values, empty POST data values, and empty content are not flagged.
1. **Base64 detection is conservative** — `is_base64_credential()` requires valid base64 characters, successful decode,
   and exactly one colon in the decoded string. Random base64-looking strings that don't decode to `user:pass` format
   are not flagged.
