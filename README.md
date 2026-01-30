# har-capture

[![PyPI version](https://badge.fury.io/py/har-capture.svg)](https://pypi.org/project/har-capture/)
[![Downloads](https://img.shields.io/pypi/dm/har-capture)](https://pypi.org/project/har-capture/)
[![codecov](https://codecov.io/gh/solentlabs/har-capture/branch/main/graph/badge.svg)](https://codecov.io/gh/solentlabs/har-capture)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI Assisted](https://img.shields.io/badge/AI-Claude%20Assisted-5A67D8.svg)](https://claude.ai)

Capture and sanitize [HAR (HTTP Archive)](http://www.softwareishard.com/blog/har-12-spec/) files. HAR files record browser HTTP activity and are commonly used for debugging, diagnostics, and test fixtures.

## Quick Start

<details open>
<summary><b>Windows</b></summary>

1. Install Python from the [Microsoft Store](https://apps.microsoft.com/detail/9NRWMJP3717K) or [python.org](https://www.python.org/downloads/)
2. Open PowerShell and run:

```bash
pip install har-capture[full]
python -m har_capture get https://example.com
```

</details>

<details>
<summary><b>macOS / Linux</b></summary>

```bash
pip install har-capture[full]
har-capture get https://example.com
```

</details>

<details>
<summary><b>Already have a HAR file?</b></summary>

```bash
pip install har-capture
har-capture sanitize myfile.har
```
</details>

<details>
<summary><b>Python API</b></summary>

```python
from har_capture.sanitization import sanitize_har

with open("input.har") as f:
    har_data = json.load(f)

sanitized = sanitize_har(har_data)
```
</details>

---

## Why har-capture?

[Chrome DevTools v130+](https://developer.chrome.com/blog/new-in-devtools-130) now sanitizes cookies and auth headers by default when exporting HAR files. That's a good start, but HAR files contain much more sensitive data:

- IP addresses, MAC addresses, email addresses
- Passwords and credentials in form bodies
- Serial numbers, device names, session tokens

**har-capture** provides **deep sanitization** and **CLI automation**:

```bash
har-capture get <TARGET>     # Capture + sanitize in one step
```

### Comparison with Existing Tools

| Feature | har-capture | [DevTools](https://developer.chrome.com/docs/devtools/network/reference) | [Google](https://github.com/google/har-sanitizer) | [Cloudflare](https://blog.cloudflare.com/introducing-har-sanitizer-secure-har-sharing/) | [Edgio](https://github.com/Edgio/har-tools) |
|---------|-------------|----------|--------|------------|-------|
| **Sanitization** |
| Cookies/auth headers | Yes | Yes | Yes | Yes | Yes |
| IPs, MACs, emails | **Yes** | No | No | No | No |
| Passwords in forms | **Yes** | No | Yes | No | Yes |
| JWT smart redaction | No | No | No | **Yes** | No |
| Correlation-preserving | **Yes** | No | No | No | No |
| **Usability** |
| No installation needed | No | **Yes** | No | **Yes** | **Yes** |
| Data stays local | **Yes** | **Yes** | No | **Yes** | **Yes** |
| CLI/scriptable | **Yes** | No | Yes | No | Yes |
| Preview before redact | Yes | No | **Yes** | No | No |
| **Extras** |
| Integrated capture | **Yes** | **Yes** | No | No | No |
| Custom patterns | **Yes** | No | Yes | No | No |
| Validation | **Yes** | No | No | No | No |

### Target Use Cases

- **Support diagnostics**: Users submit sanitized HAR files without exposing credentials
- **Web development**: Capture and analyze HTTP traffic for debugging
- **Test fixtures**: Generate reproducible traffic captures for testing
- **Security review**: Validate HAR files for PII leaks before sharing

## Features

- **Zero Dependencies Core**: Core sanitization uses only Python stdlib
- **HAR Capture**: Browser-based capture using Playwright (optional)
- **PII Sanitization**: Remove sensitive data from HTML and HAR files
- **Correlation-Preserving Redaction**: Salted hashes maintain value relationships
- **Custom Patterns**: External JSON files for easy pattern updates
- **Validation**: Check HAR files for PII leaks before committing
- **CLI Interface**: Easy-to-use command line tools

## Installation

```bash
# Core only (zero dependencies)
pip install har-capture

# With browser capture
pip install har-capture[capture]
playwright install chromium  # Install browser

# With CLI
pip install har-capture[cli]

# Full installation
pip install har-capture[full]
```

## Quick Start

### Python API

```python
from har_capture.sanitization import sanitize_html, sanitize_har

# Sanitize HTML (correlation-preserving by default)
clean_html = sanitize_html(raw_html)

# Sanitize with consistent salt (correlate across files)
clean_html = sanitize_html(raw_html, salt="my-secret-key")

# Use static placeholders (legacy mode)
clean_html = sanitize_html(raw_html, salt=None)

# Sanitize HAR file
from har_capture.sanitization import sanitize_har_file
sanitize_har_file("capture.har")  # Creates capture.sanitized.har
```

### CLI

```bash
# Capture HTTP traffic
har-capture get <TARGET>

# Sanitize a HAR file (uses random salt by default)
har-capture sanitize capture.har

# Sanitize with consistent salt
har-capture sanitize capture.har --salt my-key

# Sanitize with static placeholders
har-capture sanitize capture.har --no-salt

# Use custom patterns
har-capture sanitize capture.har --patterns custom.json

# Validate for PII leaks
har-capture validate capture.har
```

## Correlation-Preserving Redaction

By default, har-capture uses **format-preserving salted hashes** for redaction:

- Same value → same hash (within a session)
- Different values → different hashes
- Output remains valid format (parseable by analysis tools)
- Uses reserved/documentation ranges that won't collide with real data

**Example:**
```
Before:
  MAC: AA:BB:CC:DD:EE:FF (appears 3 times)
  MAC: 11:22:33:44:55:66 (appears 2 times)

With salted hash (default):
  MAC: 02:a1:b2:c3:d4:e5 (appears 3 times - same device, valid MAC format)
  MAC: 02:7f:8e:9d:2c:01 (appears 2 times - different device)

With static placeholders (--no-salt):
  MAC: XX:XX:XX:XX:XX:XX (appears 5 times - correlation lost)
```

**Format-preserving ranges used:**
| Type | Range | Standard |
|------|-------|----------|
| MAC | `02:xx:xx:xx:xx:xx` | Locally administered bit |
| Private IP | `10.255.x.x` | RFC 1918 |
| Public IP | `192.0.2.x` | RFC 5737 TEST-NET-1 |
| IPv6 | `2001:db8::` | RFC 3849 documentation |
| Email | `user_xxx@redacted.invalid` | RFC 2606 .invalid TLD |

**Salt options:**
- `--salt auto` (default): Random salt per session
- `--salt my-key`: Consistent hashing across runs
- `--no-salt`: Static placeholders (legacy mode)

## Custom Patterns

Patterns are stored in external JSON files for easy customization:

```
src/har_capture/patterns/
├── pii.json          # PII detection patterns
├── sensitive.json    # Sensitive headers/fields
└── allowlist.json    # Safe placeholder values
```

**Add custom patterns via CLI:**
```bash
har-capture sanitize capture.har --patterns my_patterns.json
har-capture validate capture.har --patterns my_patterns.json
```

**Add custom patterns via Python:**
```python
from har_capture.sanitization import sanitize_html

clean = sanitize_html(html, custom_patterns="my_patterns.json")
```

**Example custom patterns file:**
```json
{
  "patterns": {
    "my_custom_id": {
      "regex": "CUST-[A-Z0-9]{8}",
      "replacement_prefix": "CUSTID",
      "description": "Customer ID pattern"
    }
  }
}
```

## PII Categories Removed

The sanitization removes the following types of PII:

- **MAC Addresses**: `AA:BB:CC:DD:EE:FF` → `02:a1:b2:c3:d4:e5`
- **Private IPs**: `192.168.1.100` → `10.255.42.17`
- **Public IPs**: `8.8.8.8` → `192.0.2.42`
- **IPv6 Addresses**: `fe80::1` → `2001:db8::a1b2:c3d4`
- **Email Addresses**: `user@example.com` → `user_a1b2c3d4@redacted.invalid`
- **Passwords/Credentials**: In forms, headers, and JavaScript → `PASS_a1b2c3d4`
- **Session Tokens**: In cookies and headers → `TOKEN_a1b2c3d4`
- **Serial Numbers**: → `SERIAL_a1b2c3d4`
- **WiFi Credentials**: In JavaScript variables
- **Device Names**: In network device lists

## CLI Commands

### get

Capture HTTP traffic using a browser.

```bash
har-capture get <TARGET>
har-capture get <TARGET> --output capture.har
har-capture get <TARGET> --no-sanitize
```

### sanitize

Remove PII from HAR files.

```bash
har-capture sanitize capture.har
har-capture sanitize capture.har --output clean.har --compress
har-capture sanitize capture.har --salt my-key      # Consistent hash
har-capture sanitize capture.har --no-salt          # Static placeholders
har-capture sanitize capture.har --patterns custom.json
har-capture sanitize capture.har --max-size 500     # Allow up to 500MB
har-capture sanitize capture.har --compression-level 6  # Faster compression
```

### validate

Check for PII leaks.

```bash
har-capture validate capture.har
har-capture validate --dir ./captures --recursive
har-capture validate capture.har --strict
har-capture validate capture.har --patterns custom.json
```

## Platform Support

| Component | Windows | macOS | Linux |
|-----------|---------|-------|-------|
| Sanitization | Yes | Yes | Yes |
| Validation | Yes | Yes | Yes |
| CLI | Yes | Yes | Yes |
| Capture | Yes | Yes | Yes |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .

# Type checking
mypy src/har_capture
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
