# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-03-30

### Fixed

- **POST request deduplication** — `filter_and_compress_har()` used `(method, url)` as the dedup key, silently dropping POST requests to the same URL with different bodies. Devices that use a single POST endpoint differentiated only by body parameters (e.g., `param=1` vs `param=2`) lost all but the first request. The dedup key for POST/PUT/PATCH now includes a SHA-256 hash of the request body, preserving distinct requests while still deduplicating identical retries.

## [0.5.0] - 2026-03-29

### Added

- **Default command** — `har-capture <URL>` now works without typing `get` (e.g., `har-capture 192.168.1.1`). The `get` subcommand still works as an explicit alias.
- **Domain-driven pattern extensibility** — heuristic detectors (`CompiledDetector`), safe value patterns, and pipe-delimited variable matching are now data-driven via domain pattern files loaded with `--patterns`. See [Pattern Spec](docs/specs/PATTERN_SPEC.md).
- **Wait-for-data SPA capture** — JavaScript init script monkey-patches `XMLHttpRequest.send` and `window.fetch` to track in-flight requests. Polls for 2 seconds of network quiescence (vs Playwright's 500ms `networkidle`). `framenavigated` listener ensures async data completes before page transitions.
- **Test fixture extraction** — large test data moved from inline to `tests/fixtures/*.json`

### Changed

- **BREAKING**: Interactive review is now always enabled and cannot be disabled. The `--no-interactive` flag has been removed from both `get` and `sanitize` commands. In non-TTY environments (CI/CD), flagged values are written to a `.review.json` report file instead.
- **BREAKING**: `capture_device_har()` and `run_capture_phase()` now default to `interactive=True` (was `False`). API consumers can still pass `interactive=False` explicitly.
- Documentation suite rewritten — architecture doc, 4 specs, use cases, CLI reference all verified against implementation (76 findings resolved)

### Fixed

- 12 HIGH-severity documentation accuracy issues: wrong function signatures, wrong phase ordering, fabricated CLI flags (`--timeout`, `--headless`), fabricated pre-commit hook, wrong scanner pass numbering, unimplemented features documented as real (`_extends`, `html` domain section)

## [0.4.5] - 2026-03-09

### Fixed

- **Base64 credential leak in URL query strings** — Sanitizer and validator now detect base64-encoded `user:pass` tokens in URL query parameters (both bare tokens like `?YWRtaW46cGFzcw==` and param values like `?token=YWRtaW46cGFzcw==`). Handles `parse_qsl` stripping base64 `=` padding by checking raw query segments.
- **Cookie attribute metadata in headers** — Cookie/Set-Cookie headers containing serialized attribute metadata (e.g., `HttpOnly: true, Secure: true`) are now properly redacted instead of passing through unchanged. Also handles cookie headers with no `name=value` pairs.
- **Serial number in HTML table cells** — Serial numbers in adjacent `<td>` cells (e.g., `<td>Serial Number</td><td>17V541334700308</td>`) are now detected and redacted by both the sanitizer and validator.
- **Inline `setItem()` web storage scanning** — HTML response bodies containing `localStorage.setItem()` / `sessionStorage.setItem()` calls now have their values scanned. Keys matching sensitive field patterns (e.g., `PrivateKey`, `csrf_token`, `api_key`) trigger auto-redaction; remaining values are checked by PII patterns and heuristic analysis.
- **Serial numbers in pipe-delimited strings** — Serial numbers with `SN-` / `S/N-` prefixes in `tagValueList` and similar pipe-delimited JavaScript variables are now auto-redacted, consistent with serial detection in other contexts.

## [0.4.4] - 2026-03-05

### Changed

- **CI workflow_dispatch** — Added `workflow_dispatch` trigger to CI workflow for manual recovery when push events are missed

### Fixed

- **mypy no-any-return** — Fixed `apply_user_redactions()` returning `Any` from `json.loads()` instead of typed `dict[str, Any]`

### Removed

- **release.py skip flags** — Removed `--skip-tests` and `--skip-quality` flags from `release.py` to prevent bypassing quality gates

## [0.4.3] - 2026-03-05

### Added

- **Sanitization metadata in HAR** — Every sanitized HAR now embeds a `log._har_capture.sanitization` section recording tool version, timestamp, salt mode, heuristic mode, and redaction counts. Does not leak the salt value.
- **Web Storage Snapshot** — After page settles, captures localStorage (via `context.storage_state()`) and sessionStorage (via `page.evaluate()`) per origin. Stored in HAR as `log._har_capture.local_storage` and `log._har_capture.session_storage` with values sanitized using `STORAGE_` prefix. Catches auth-critical data that lives only in web storage (e.g., HNAP PrivateKey in localStorage, SJCL encryption keys in sessionStorage).

### Fixed

- **`_add_capture_metadata` clobbering** — `_add_capture_metadata()` now merges with existing `_har_capture` metadata instead of overwriting it. Previously, `browser_cookies` injected before compression were silently lost.
- **Allowlist missing hash prefixes** — Added `STORAGE_`, `CRED_`, `SENSITIVE_` to `allowlist.json` hash prefixes, preventing double-redaction on re-sanitization
- **ci-local.sh bare pytest** — Integration test step now uses `"$PYTHON" -m pytest` consistently

### Changed

- **Shared SSL context** — Extracted duplicate SSL context creation from `connectivity.py` to use shared `make_ssl_context()` from `probes.py`
- **CLI code deduplication** — Extracted `apply_reviewed_redactions()` into `cli/interactive.py`, eliminating ~55 lines of identical logic between `capture.py` and `sanitize.py`
- **Debug logging on JSON parse failure** — `_sanitize_json_text()` now logs a debug message when encountering non-JSON text instead of silently returning
- **Pre-compiled regex in secrets validation** — `check_post_data()` and `check_json_fields()` now use pre-compiled patterns via `_compile_sensitive_fields()` for better performance
- **Removed unused constant** — Deleted `_SSID_NAME_MAX_LENGTH` from `heuristics.py` (never referenced)
- **Module-level import** — Moved `RedactionCollector` from per-call lazy import in `sanitize_html()` to module-level `else` branch of `TYPE_CHECKING` block
- **Thread-safety docstring** — `RedactionCollector` now documents that it is not thread-safe
- **IPv6 docstring** — `_parse_target()` now documents IPv6 address support

## [0.4.2] - 2026-03-05

### Fixed

- **Probe 200-Path Cookies** - `probe_auth_challenge()` now captures `Set-Cookie` and `WWW-Authenticate` headers on 200 responses (previously only extracted on 401/error paths)

### Added

- **Browser Cookie Snapshot** - After Playwright navigates and page settles, `context.cookies()` captures all browser cookies (including JS-set ones like XSRF_TOKEN) with full properties (domain, path, expires, httpOnly, secure, sameSite). Stored in HAR as `log._har_capture.browser_cookies` with values sanitized.

## [0.4.1] - 2026-03-04

### Fixed

- **HTTPS Auth Probe** - `probe_auth_challenge()` passed `context=` kwarg to `OpenerDirector.open()`, which only `urlopen()` accepts. Every HTTPS target silently failed. Fixed by installing the SSL context via `HTTPSHandler` in `build_opener()`.
- **PII Test Server Password** - Changed default password from `12345` to `pw` to match documented usage.

### Added

- **HTTPS Probe Integration Tests** - Real local TLS server tests using `trustme` library, covering auth challenge, cookie capture, body preview, redirect suppression, and HEAD support over HTTPS.
- **README Screenshots** - Added "See It In Action" section with sanitization report, flagged values table, and interactive redact picker screenshots.

## [0.4.0] - 2026-02-28

### Added

- **Pre-Capture Diagnostic Probes** - Unauthenticated HTTP and ICMP probes run before the Playwright session
  - Auth challenge probe: captures `WWW-Authenticate` headers and Set-Cookie values
  - HEAD support probe: checks if the target server supports HEAD requests
  - ICMP probe: pings the host and reports latency
  - Results stored as `log._probes` metadata in HAR output
- **Public IP Sanitization** - Detects and redacts public IPv4 addresses (preserves private/loopback/link-local)
- **Serial Number Field Detection** - JSON fields named `serial`, `serial_number`, `serialnumber`, `serialnum`, `sn` are now redacted
- **Cookie Object Sanitization** - Structured cookie objects in request/response entries are now sanitized
- **Credential-Like Value Detection** - New heuristic for short passwords (`pass123`, `token42`, `key!2024`)
- **Router/Modem Brand Detection** - Heuristics now flag values containing device brand names (NETGEAR, Linksys, ASUS, etc.)
- **PII Test Server** - `scripts/pii_test_server.py` replaces `mock_modem.py` as a standalone PII-laden web server for dogfooding sanitization, with mixed sci-fi references from the '70s through '90s (Blade Runner, TRON, Alien, WarGames, The Matrix, and more)
- **Browser Auto-Reinstall** - Detects missing browser executable and auto-reinstalls before retry

### Changed

- **BREAKING**: `--interactive` flag replaced with `--no-interactive` (interactive mode is now the default for both `capture` and `sanitize` commands)
- SSID heuristic tightened: broad alphanumeric matching replaced with CamelCase-only pattern to reduce false positives
- Safe value patterns expanded: common words (`premium`, `admin`, `guest`, etc.) and already-redacted values are no longer flagged
- Phone number pattern boundary changed from `(?<!\d)` to `(?<!\w)` to prevent matching inside tokens
- `systemInfo`, `wifiInfo`, `networkInfo` now matched by pipe-delimited variable sanitization
- Codecov patch coverage check set to informational (reports but doesn't block)

### Fixed

- **Security Hardening** - Sanitization coverage improvements across HAR, HTML, and heuristic analysis
- Pre-commit hooks fixed for relocated repository (stale venv paths)
- `ci-local.sh` now uses venv Python directly instead of bare `ruff`/`pytest` commands
- Various ruff and mypy errors resolved (type annotations, import sorting, unused suppressions)

### Migration Guide

**CLI flag change:**

```bash
# Before (v0.3.x)
har-capture get http://device --interactive

# After (v0.4.0) — interactive is now the default
har-capture get http://device
har-capture get http://device --no-interactive  # to disable
```

## [0.3.3] - 2026-02-06

### Fixed

- **5-Octet IPv4 Corruption** - Private IP addresses now produce valid 4-octet format instead of invalid 5-octet format (e.g., `10.123.45.67` is correctly sanitized to `10.255.x.x` instead of `10.255.x.x.67`)
- **Version String Preservation** - Firmware version strings like `5.7.1.5` are now correctly preserved instead of being sanitized as IP addresses. Version strings are not PII and must remain for diagnostics.

## [0.3.2] - 2026-02-06

### Added

- **HeuristicMode Enum** - Fine-grained control over heuristic behavior with three modes:
  - `DISABLED` (default) - Skip heuristics, only redact known patterns (safe, backward compatible)
  - `FLAG` - Flag suspicious values for manual review (interactive mode)
  - `REDACT` - Auto-redact suspicious values (automated workflows)
- **Custom Patterns from Dict** - `custom_patterns` now accepts dict or file path
  - Enables passing patterns directly from modem.yaml or other configs
  - No need to write temporary files for API integration
- **Category-Aware Hashing** - New `hash_sensitive_value()` method for heuristically-detected values
  - Generates prefixed hashes: `WIFI_xxxxx`, `CRED_xxxxx`, `DEVICE_xxxxx`
  - Preserves correlation while indicating detection category

### Changed

- **BREAKING**: Replaced `flag_suspicious` boolean with `heuristics: HeuristicMode` parameter
  - Old: `sanitize_har(data, flag_suspicious=True)`
  - New: `sanitize_har(data, heuristics=HeuristicMode.FLAG)`
  - Affects: `sanitize_html()`, `sanitize_har()`, `sanitize_har_file()`, CLI, browser capture
- **Custom Pattern Precedence** - Custom patterns now applied first, preventing generic patterns from overriding them
- **Already-Redacted Protection** - Account ID and heuristic patterns skip already-redacted values (e.g., `MODEM_SN_xxxxx`)

### Fixed

- **Custom Patterns Not Applied** - Custom patterns were loaded but never applied during sanitization
- **Pattern Re-Redaction** - Account ID pattern no longer re-hashes custom-redacted values
- **Multi-Underscore Prefixes** - Heuristics now correctly skip prefixes with underscores (e.g., `MODEM_SN_`)

### Migration Guide

**For API Users:**

```python
# Before (v0.3.1)
from har_capture.sanitization.har import sanitize_har_file
sanitize_har_file(path, flag_suspicious=True)

# After (v0.3.2)
from har_capture.sanitization.har import sanitize_har_file
from har_capture.sanitization.report import HeuristicMode

# Interactive mode (manual review)
sanitize_har_file(path, heuristics=HeuristicMode.FLAG)

# Automated mode (auto-redact, may over-redact)
sanitize_har_file(path, heuristics=HeuristicMode.REDACT)

# Safe mode (default, only known patterns)
sanitize_har_file(path, heuristics=HeuristicMode.DISABLED)
# or simply: sanitize_har_file(path)
```

**For cable_modem_monitor Integration:**

```python
# Pass custom patterns as dict
modem_patterns = {
    "patterns": {
        "modem_serial": {
            "regex": r"SN[0-9]{10}",
            "replacement_prefix": "MODEM_SN"
        }
    }
}
sanitize_har_file(
    path,
    heuristics=HeuristicMode.REDACT,
    custom_patterns=modem_patterns  # Dict instead of file path
)
```

## [0.3.1] - 2026-02-04

### Fixed

- **Interactive Mode Display** - Fixed summary panel not displaying when `keep_raw=False` (default)
  - Now shows version, auto-redacted counts, and file paths at start of review
  - Fixed double screen clearing that was hiding the summary
- **Interactive Mode File Handling** - Keep sanitized HAR file when interactive mode is enabled
  - Previously deleted uncompressed file, causing "Missing sanitization data" error
  - Now preserves file for user review and redaction application
- **Test Linting** - Fixed RUF059 warnings for unused unpacked variables in tests
- **Type Checking** - Re-added necessary type ignore for json.loads return type

### Added

- **Solent Labs™ Branding** - Added watermark to interactive mode panels
- **Improved Instructions** - Clearer checkbox prompts ("Enter when done", pre-selected items noted)
- **Better UX** - Simplified keybindings (A/N for all/none work now), removed redundant Ctrl+C mention

## [0.3.0] - 2026-02-04

### Added

- **Interactive Sanitization Mode** - Review and approve edge cases (WiFi SSIDs, device names, credentials) with beautiful CLI interface
  - Checkbox selection for flagged values with confidence indicators
  - Context display (surrounding HTML/values) for informed decisions
  - Quick actions (redact all, redact high confidence, skip review)
  - Two-pass workflow: auto-redaction + user review
- **Heuristic Detection** - ML-free detection of suspicious values:
  - SSID-like patterns (WiFi network names)
  - Device name patterns (router hostnames)
  - High-entropy values (potential passwords)
  - Values adjacent to redacted content
- **Sanitization Reports** - Structured reports with:
  - Auto-redaction statistics
  - Flagged values with confidence levels (high/medium/low)
  - User decisions (redacted/skipped)
  - Salt preservation for Pass 2
- **Consolidated Redaction Checking** - Single source of truth in `patterns/redaction.py`
  - Moved hard-coded patterns to `allowlist.json` configuration
  - Custom pattern support with merge logic
  - 99% test coverage with 71 parameterized tests

### Changed

- **BREAKING**: Removed deprecated `patterns.loader.is_allowlisted()` - Use `patterns.is_allowlisted` instead
- **BREAKING**: Removed deprecated `validation.secrets.REDACTED_PATTERNS` - Now in `allowlist.json`
- Version bump to 0.3.0 (major release with breaking changes)
- Simplified README comparison table for better readability
- All test files now have comprehensive docstrings
- Tests refactored to table-driven style with `@pytest.mark.parametrize`

### Removed

- Deprecated backward compatibility shims (clean v0.3.0 API)
- `docs/TECH_DEBT.md` (observations now tracked via TODO comments or issues)

### Fixed

- ReDoS prevention with length checks before regex matching
- Input validation in `apply_user_redactions` with clear error messages
- Exception handling in interactive mode (graceful terminal error recovery)

### Migration Guide

**Breaking Changes:**

```python
# ❌ No longer works:
from har_capture.patterns.loader import is_allowlisted
from har_capture.validation.secrets import REDACTED_PATTERNS

# ✅ Use instead:
from har_capture.patterns import is_allowlisted
from har_capture.patterns import is_redacted  # Recommended
```

**New Features:**

```bash
# Interactive mode - review edge cases
har-capture sanitize input.har --interactive

# Customize patterns
har-capture sanitize input.har --patterns custom-allowlist.json
```

## [0.2.5] - 2026-02-01

### Changed

- Browser auto-installs on first `har-capture get` (no prompt, no manual step)

## [0.2.4] - 2026-02-01

### Added

- Release automation script (`scripts/release.py`) for consistent version bumps

### Security

- Raw HAR capture now uses temp files; PII is never written to user's directory
- Only sanitized content is saved to user-specified output path

### Changed

- Extracted `REDACTED` constant and `_redact_value()` helper to reduce code duplication

## [0.2.3] - 2026-01-31

### Changed

- HAR files are now pretty-printed by default (indent=2) for better readability
- Compressed output size unchanged (whitespace compresses well)

## [0.2.2] - 2026-01-31

### Fixed

- **Security**: Compressed files now contain sanitized content (was compressing raw file)
- Workflow order: sanitize first, then compress the sanitized file

### Added

- Version consistency test to prevent `__init__.py` / `pyproject.toml` mismatch
- Documentation clarifying that `get` command sanitizes by default

## [0.2.1] - 2026-01-30

### Fixed

- Python 3.10 compatibility for version test (use regex instead of tomllib)

## [0.2.0] - 2026-01-30

### Added

- Correlation-preserving redaction with salted hashes
- Format-preserving replacements (MAC, IP, email stay valid formats)
- Custom pattern support via external JSON files
- `--salt` and `--no-salt` CLI options
- Comprehensive test coverage (84%+)

### Changed

- Default sanitization now uses random salt per session
- Refactored `CaptureResult` with composition pattern

## [0.1.2] - 2026-01-29

### Added

- Auto-prompt to install browser on first capture (Y/n with default Yes)
- "Next steps" guidance after capture completes
- New functions: `check_browser_installed()`, `install_browser()`

### Fixed

- README Quick Start: `--ip` flag → positional argument

## [0.1.1] - 2026-01-29

### Fixed

- Downloads badge now renders correctly on PyPI (switched to shields.io)

### Added

- Quick Start section in README for copy-paste installation

## [0.1.0] - 2026-01-29

### Added

- Initial release extracted from cable_modem_monitor
- `sanitization.html`: HTML sanitization with PII detection
  - MAC address redaction
  - IP address redaction (preserves common gateway IPs)
  - IPv6 address redaction
  - Serial number redaction
  - Password/credential redaction
  - Email address redaction
  - WiFi credential detection in JavaScript variables
- `sanitization.har`: HAR file sanitization
  - Header sanitization (Authorization, Cookie, etc.)
  - POST data sanitization
  - Response content sanitization
  - JSON field sanitization
- `validation.secrets`: PII leak detection for pre-commit validation
- `capture.browser`: Playwright-based browser capture
- CLI commands: `capture`, `sanitize`, `validate`
- Zero dependencies for core sanitization (stdlib only)
- Optional dependencies for capture (playwright), CLI (typer)

[0.1.0]: https://github.com/solentlabs/har-capture/releases/tag/v0.1.0
[0.1.1]: https://github.com/solentlabs/har-capture/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/solentlabs/har-capture/compare/v0.1.1...v0.1.2
[0.2.0]: https://github.com/solentlabs/har-capture/compare/v0.1.2...v0.2.0
[0.2.1]: https://github.com/solentlabs/har-capture/compare/v0.2.0...v0.2.1
[0.2.2]: https://github.com/solentlabs/har-capture/compare/v0.2.1...v0.2.2
[0.2.3]: https://github.com/solentlabs/har-capture/compare/v0.2.2...v0.2.3
[0.2.4]: https://github.com/solentlabs/har-capture/compare/v0.2.3...v0.2.4
[0.2.5]: https://github.com/solentlabs/har-capture/compare/v0.2.4...v0.2.5
[0.3.0]: https://github.com/solentlabs/har-capture/compare/v0.2.5...v0.3.0
[0.3.1]: https://github.com/solentlabs/har-capture/compare/v0.3.0...v0.3.1
[0.3.2]: https://github.com/solentlabs/har-capture/compare/v0.3.1...v0.3.2
[0.3.3]: https://github.com/solentlabs/har-capture/compare/v0.3.2...v0.3.3
[0.4.0]: https://github.com/solentlabs/har-capture/compare/v0.3.3...v0.4.0
[0.4.1]: https://github.com/solentlabs/har-capture/compare/v0.4.0...v0.4.1
[0.4.2]: https://github.com/solentlabs/har-capture/compare/v0.4.1...v0.4.2
[0.4.3]: https://github.com/solentlabs/har-capture/compare/v0.4.2...v0.4.3
[0.4.4]: https://github.com/solentlabs/har-capture/compare/v0.4.3...v0.4.4
[0.4.5]: https://github.com/solentlabs/har-capture/compare/v0.4.4...v0.4.5
[0.5.0]: https://github.com/solentlabs/har-capture/compare/v0.4.5...v0.5.0
[0.5.1]: https://github.com/solentlabs/har-capture/compare/v0.5.0...v0.5.1
[unreleased]: https://github.com/solentlabs/har-capture/compare/v0.5.1...HEAD
