# Technical Debt

Known improvements to address. Not blocking v0.1.0, but should be tackled before the codebase grows.

## Refactoring

### Iterative JSON Processing
`src/har_capture/sanitization/har.py` - `_sanitize_json_recursive`

The function uses recursion to traverse JSON objects. For very large or deeply nested JSON, an iterative approach using a stack would be more memory-efficient and prevent potential stack overflow errors.

**Current risk**: Low. Python's recursion limit is 1000, HAR JSON rarely exceeds 20 levels.

### Redundant Pattern Loading
`src/har_capture/validation/secrets.py` - `_load_sensitive_headers`, `_load_sensitive_fields`

These functions duplicate logic that already exists in `src/har_capture/patterns/loader.py`. Could be simplified by calling the loader module directly.

### Consolidated Redaction Checking
Logic for checking if a value is redacted is split between:
- `patterns/loader.py` (`is_allowlisted`)
- `validation/secrets.py` (`is_redacted`, `REDACTED_PATTERNS`)

Could be consolidated into a single function. `REDACTED_PATTERNS` could move to `allowlist.json` for configurability.

## Long Functions

### `sanitize_html()` - 269 lines
`src/har_capture/sanitization/html.py:39-307`

Contains 14 sequential `re.sub()` calls with nested callback functions. Handles too many PII categories in one function. Should be split into smaller, focused sanitizers.

### `capture_device_har()` - 180 lines
`src/har_capture/capture/browser.py:196-375`

Handles validation, browser setup, error handling with retry logic, compression, and sanitization. Too many responsibilities.

## Code Duplication

### `[REDACTED]` string literal
`src/har_capture/sanitization/har.py` - appears 7 times across different functions. Should be a constant.

### Sensitive field checking pattern
The pattern `if is_sensitive_field(key) and isinstance(value, str)` with conditional hasher/redaction logic appears 4+ times. Should be extracted to a helper.

## Error Handling

### Silent exception suppression
`src/har_capture/capture/browser.py:312-313`

`contextlib.suppress(Exception)` with `timeout=0` silently catches all exceptions. User might close browser without saving HAR with no indication of failure.

### Inconsistent exception patterns
- `har.py` uses custom `HarSizeError`, `HarValidationError`
- `html.py` has no custom exceptions
- `secrets.py` uses `Finding` dataclass
- `loader.py` uses `PatternLoadError`

No unified error handling strategy.

## UX Improvements

### Platform-specific Quick Start tabs
README Quick Start could use tabs (via GitHub's limited support or HTML details) to show platform-specific commands for Windows/macOS/Linux.

## Performance

### Repeated deep copies
`src/har_capture/sanitization/har.py`

Three levels of `copy.deepcopy()` for large HAR files (lines 282, 443, 481). Memory intensive for 100MB+ files. Could benefit from in-place mutation or streaming.
