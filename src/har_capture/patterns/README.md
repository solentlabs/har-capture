# Pattern Files

This directory contains JSON configuration files for PII detection, sanitization, and validation.

## Files

| File | Purpose |
|------|---------|
| `pii.json` | PII detection patterns (MAC, IP, email, etc.) |
| `sensitive.json` | Sensitive headers and form field patterns |
| `allowlist.json` | Patterns for recognizing already-redacted values |
| `capture.json` | File extensions to filter during capture |

## File Schemas

### pii.json

Defines regex patterns for detecting PII in content.

```json
{
  "patterns": {
    "pattern_name": {
      "regex": "...",
      "replacement_prefix": "MAC",
      "description": "Human-readable description",
      "flags": ["IGNORECASE"]
    }
  },
  "preserved_gateway_ips": ["192.168.0.1", "192.168.1.1"]
}
```

**Fields:**
- `regex`: Python regex pattern
- `replacement_prefix`: Prefix for hashed replacement (e.g., `MAC` → `02:xx:xx:xx:xx:xx`)
- `flags`: Optional list of regex flags (`IGNORECASE`, `MULTILINE`, `DOTALL`)
- `preserved_gateway_ips`: IPs to leave unchanged (common gateway addresses)

### sensitive.json

Defines sensitive HTTP headers and form fields to redact.

```json
{
  "headers": {
    "full_redact": ["Authorization", "X-Api-Key"],
    "cookie_redact": ["Cookie", "Set-Cookie"]
  },
  "fields": {
    "patterns": ["password", "secret", "token", "credential"]
  },
  "tagValueList": {
    "safe_values": ["Online", "Offline", "Enabled"]
  }
}
```

**Fields:**
- `headers.full_redact`: Headers to completely redact
- `headers.cookie_redact`: Headers where cookie values are redacted but names preserved
- `fields.patterns`: Regex patterns matching sensitive form field names
- `tagValueList.safe_values`: Values to preserve in device tag lists

### allowlist.json

Defines patterns for recognizing already-redacted values (to avoid double-flagging).

```json
{
  "static_placeholders": {
    "values": ["XX:XX:XX:XX:XX:XX", "0.0.0.0", "x@x.invalid"]
  },
  "format_preserving_patterns": {
    "mac": {
      "pattern": "^02:[0-9a-f]{2}:...",
      "description": "Locally administered MAC"
    }
  },
  "hash_prefixes": {
    "values": ["SERIAL_", "TOKEN_", "PASS_"]
  }
}
```

**Fields:**
- `static_placeholders.values`: Exact values produced when `salt=None`
- `format_preserving_patterns`: Regex patterns for RFC-reserved ranges
- `hash_prefixes.values`: Prefixes for non-format-preserving hashes (`PREFIX_xxxxxxxx`)

### capture.json

Defines file extensions to filter during HAR capture.

```json
{
  "bloat_extensions": {
    "fonts": [".woff", ".woff2", ".ttf"],
    "images": [".png", ".jpg", ".gif"],
    "media": [".mp3", ".mp4"],
    "sourcemaps": [".map"]
  }
}
```

**Fields:**
- Categories can be selectively included via CLI flags (`--include-fonts`, etc.)

## Custom Patterns

You can extend the built-in patterns without modifying this library.

### Via CLI

```bash
har-capture sanitize device.har --patterns my_patterns.json
har-capture validate device.har --patterns my_patterns.json
```

### Via Python API

```python
from har_capture.sanitization import sanitize_html, sanitize_har

clean = sanitize_html(html, custom_patterns="my_patterns.json")
clean = sanitize_har(har_data, custom_patterns="my_patterns.json")
```

### Custom Pattern File Example

Create a JSON file with any of the structures above. Custom patterns are **merged** with built-in patterns.

```json
{
  "patterns": {
    "policy_number": {
      "regex": "POL-[A-Z0-9]{10}",
      "replacement_prefix": "POLICY",
      "description": "Insurance policy number"
    }
  },
  "fields": {
    "patterns": ["policy_?id", "member_?number"]
  }
}
```

## Domain-Specific Patterns

This library provides **generic** PII patterns that work across domains. For domain-specific patterns (modems, IoT devices, specific vendors), create custom pattern files in your project.

**Example: Modem-specific patterns (in your project, not here)**

```json
{
  "patterns": {
    "docsis_config": {
      "regex": "/[a-z0-9]+\\.cfg",
      "replacement_prefix": "CONFIG",
      "description": "DOCSIS config file path"
    }
  },
  "fields": {
    "patterns": ["cm_mac", "cable_modem_serial"]
  }
}
```

Then pass to har-capture:

```python
sanitize_har(har_data, custom_patterns="your_project/patterns/modem.json")
```

## Contributing

To add patterns to the core library:

1. Patterns should be **universally applicable** (not domain-specific)
2. Include a clear `description` for each pattern
3. Test patterns don't cause false positives on common data
4. Submit a PR with examples of what the pattern matches

For vendor or domain-specific patterns, maintain them in your own project and pass via `custom_patterns`.
