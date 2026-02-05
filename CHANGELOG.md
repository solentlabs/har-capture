# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## \[0.3.0\] - 2026-02-04

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
[unreleased]: https://github.com/solentlabs/har-capture/compare/v0.2.5...HEAD
