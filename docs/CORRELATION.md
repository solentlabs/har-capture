# Correlation-Preserving Redaction

## Overview

By default, har-capture uses **format-preserving salted hashes** for redaction. This preserves the ability to correlate values across multiple requests while maintaining data privacy.

## How It Works

**Key principles:**

- Same value → same hash (within a session)
- Different values → different hashes
- Output remains valid format (parseable by analysis tools)
- Uses reserved/documentation ranges that won't collide with real data

## Example

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

## Format-Preserving Ranges

har-capture uses standardized reserved ranges to ensure output doesn't conflict with real data:

| Type       | Range                       | Standard                 |
| ---------- | --------------------------- | ------------------------ |
| MAC        | `02:xx:xx:xx:xx:xx`         | Locally administered bit |
| Private IP | `10.255.x.x`                | RFC 1918                 |
| Public IP  | `192.0.2.x`                 | RFC 5737 TEST-NET-1      |
| IPv6       | `2001:db8::`                | RFC 3849 documentation   |
| Email      | `user_xxx@redacted.invalid` | RFC 2606 .invalid TLD    |

## Salt Options

### Auto (Default)

```bash
har-capture sanitize capture.har
```

- Random salt generated per session
- Values correlated within single HAR file
- Different runs produce different hashes

**Use when:** You want correlation within a file but don't need to correlate across multiple captures.

### Consistent Salt

```bash
har-capture sanitize capture.har --salt my-secret-key
```

- Same salt used across multiple runs
- Values correlated across different HAR files
- Reproducible output

**Use when:** You need to correlate values across multiple captures (e.g., debugging across sessions).

### Static Placeholders (Legacy)

```bash
har-capture sanitize capture.har --no-salt
```

- All IPs become `192.0.2.1`
- All MACs become `02:00:00:00:00:00`
- Correlation is lost
- Compatible with tools expecting static values

**Use when:** Your analysis tools don't support varied values, or you need maximum simplicity.

## Python API

```python
from har_capture.sanitization import sanitize_html

# Auto salt (random per session)
clean = sanitize_html(html)

# Consistent salt
clean = sanitize_html(html, salt="my-secret-key")

# Static placeholders
clean = sanitize_html(html, salt=None)
```

## Why Correlation Matters

**Example use case: Debugging device connectivity**

```
Request 1: Device with MAC 02:a1:b2:c3:d4:e5 connects
Request 2: Same device (02:a1:b2:c3:d4:e5) authenticates
Request 3: Same device (02:a1:b2:c3:d4:e5) fetches data
Request 4: Different device (02:7f:8e:9d:2c:01) connects
```

With correlation, you can track the same device across requests. Without it, all MACs become `XX:XX:XX:XX:XX:XX` and you lose the ability to trace device behavior.

## Security Considerations

**Salted hashes are NOT encryption:**

- Given enough samples, an attacker might reverse-engineer values
- Use consistent salts carefully (don't share across untrusted parties)
- For maximum security, use `--no-salt` for public sharing

**Best practices:**

- Use auto salt for single-file sanitization
- Use consistent salt only when needed for debugging
- Never share the salt with sanitized HAR files
- For public sharing, use `--no-salt` to eliminate correlation
