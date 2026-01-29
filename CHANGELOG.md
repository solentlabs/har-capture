# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/solentlabs/har-capture/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/solentlabs/har-capture/releases/tag/v0.1.0
