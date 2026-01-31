# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
[unreleased]: https://github.com/solentlabs/har-capture/compare/v0.2.3...HEAD
