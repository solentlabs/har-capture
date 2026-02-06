# PII Categories

## Overview

har-capture sanitizes the following categories of personally identifiable information (PII) and sensitive data.

## Network Identifiers

### MAC Addresses

**Pattern:** `XX:XX:XX:XX:XX:XX` or `XX-XX-XX-XX-XX-XX`

**Examples:**

```
AA:BB:CC:DD:EE:FF → 02:a1:b2:c3:d4:e5
00-11-22-33-44-55 → 02-7f-8e-9d-2c-01
```

**Format-preserving hash:**

- Uses locally administered bit (`02:` prefix)
- Maintains valid MAC format
- Preserves correlation across requests

### IP Addresses (Private)

**Pattern:** RFC 1918 private ranges

**Examples:**

```
192.168.1.100   → 10.255.42.17
10.0.0.5        → 10.255.73.29
172.16.0.1      → 10.255.91.44
```

**Format-preserving hash:**

- Uses `10.255.x.x` range
- Maintains valid IP format
- Different IPs get different hashes

### IP Addresses (Public)

**Pattern:** Any non-private IPv4

**Examples:**

```
8.8.8.8         → 192.0.2.42
1.1.1.1         → 192.0.2.73
203.0.113.5     → 192.0.2.91
```

**Format-preserving hash:**

- Uses RFC 5737 TEST-NET-1 range (`192.0.2.x`)
- Maintains valid IP format
- Safe for documentation/examples

### IPv6 Addresses

**Pattern:** Any IPv6 address

**Examples:**

```
fe80::1                    → 2001:db8::a1b2:c3d4
2001:0db8::8a2e:0370:7334 → 2001:db8::e5f6:a7b8
```

**Format-preserving hash:**

- Uses RFC 3849 documentation range (`2001:db8::`)
- Maintains valid IPv6 format

## Personal Identifiers

### Email Addresses

**Pattern:** Standard email format

**Examples:**

```
user@example.com     → user_a1b2c3d4@redacted.invalid
john.doe@company.org → john.doe_e5f6a7b8@redacted.invalid
```

**Format-preserving hash:**

- Preserves username structure
- Uses RFC 2606 `.invalid` TLD
- Safe placeholder domain

### Phone Numbers

**Pattern:** Various formats (US, international)

**Examples:**

```
+1-555-123-4567  → PHONE_a1b2c3d4
(555) 123-4567   → PHONE_e5f6a7b8
555.123.4567     → PHONE_1a2b3c4d
```

## Credentials

### Passwords  <!-- pragma: allowlist secret -->

**Locations:**

- Form data (`password`, `passwd`, `pwd` fields)
- HTTP Basic Auth headers
- JavaScript variables (`password`, `pwd`)
- JSON payloads

**Examples:**

```
password=secret123     → password=PASS_a1b2c3d4  # pragma: allowlist secret
Authorization: Basic   → Authorization: Basic PASS_e5f6a7b8  # pragma: allowlist secret
var pwd = "hunter2"    → var pwd = "PASS_1a2b3c4d"  # pragma: allowlist secret
```

### Session Tokens

**Locations:**

- Cookies (`session`, `token`, `auth`)
- Authorization headers
- URL query parameters
- JSON Web Tokens (JWT)

**Examples:**

```
Cookie: session=abc123      → Cookie: session=TOKEN_a1b2c3d4
Authorization: Bearer xyz   → Authorization: Bearer TOKEN_e5f6a7b8
?token=def456               → ?token=TOKEN_1a2b3c4d
```

### API Keys  <!-- pragma: allowlist secret -->

**Pattern:** Various formats (AWS, Stripe, etc.)

**Examples:**

```
AKIAIOSFODNN7EXAMPLE     → APIKEY_a1b2c3d4  # pragma: allowlist secret
sk_live_abcd1234         → APIKEY_e5f6a7b8  # pragma: allowlist secret
```

## Device Identifiers

### Serial Numbers

**Pattern:** Various formats

**Examples:**

```
SN1234567890    → SERIAL_a1b2c3d4
S/N: AB-12345   → S/N: SERIAL_e5f6a7b8
```

### Device Names

**Pattern:** Common naming patterns

**Examples:**

```
Johns-iPhone        → DEVICE_a1b2c3d4
MyLaptop-Home       → DEVICE_e5f6a7b8
SmartTV-LivingRoom  → DEVICE_1a2b3c4d
```

### WiFi SSIDs

**Pattern:** Detected in JavaScript, HTML

**Examples:**

```
MyHomeWiFi      → SSID_a1b2c3d4
Apartment_5B    → SSID_e5f6a7b8
```

**Note:** Common SSIDs (xfinitywifi, etc.) are allowlisted

### WiFi Credentials  <!-- pragma: allowlist secret -->

**Locations:**

- JavaScript variables (`wifiPassword`, `wpaKey`)
- Configuration forms
- JSON payloads

**Examples:**

```
wifiPassword: "secret"  → wifiPassword: "WIFIPASS_a1b2c3d4"  # pragma: allowlist secret
wpaKey: "hunter2"       → wpaKey: "WIFIPASS_e5f6a7b8"  # pragma: allowlist secret
```

## HTTP-Specific

### Sensitive Headers

**Always sanitized:**

- `Authorization`
- `Cookie`
- `Set-Cookie`
- `Proxy-Authorization`
- `WWW-Authenticate`
- `X-API-Key`
- `X-Auth-Token`

**Examples:**

```
Authorization: Bearer abc123  → Authorization: Bearer TOKEN_a1b2c3d4
Cookie: session=xyz           → Cookie: session=TOKEN_e5f6a7b8
```

### Sensitive Query Parameters

**Pattern:** `token`, `key`, `password`, `secret`, `auth`

**Examples:**

```
?api_key=abc123           → ?api_key=TOKEN_a1b2c3d4
?password=secret          → ?password=PASS_e5f6a7b8
?oauth_token=xyz          → ?oauth_token=TOKEN_1a2b3c4d
```

### Form Fields

**Sensitive field names:**

- `password`, `passwd`, `pwd`
- `ssn`, `social_security`
- `credit_card`, `cc_number`
- `cvv`, `cvc`

**Examples:**

```
password=hunter2       → password=PASS_a1b2c3d4
cc_number=4111111111   → cc_number=CCNUM_e5f6a7b8
```

## Heuristic Detection

When enabled (`HeuristicMode.FLAG` or `HeuristicMode.REDACT`), har-capture also detects:

### Suspicious Strings

- Short base64-encoded strings (likely tokens)
- UUID-like patterns
- Long alphanumeric strings (40+ chars)
- Hex strings (32+ chars)

**Examples:**

```
YWJjZGVmMTIzNDU2    → (flagged for review)
550e8400-e29b-41d4  → (flagged for review)
```

### Device-Specific Patterns

- Serial number patterns
- Model numbers
- MAC-like sequences

## Allowlist

Certain values are never redacted:

- Common WiFi SSIDs (xfinitywifi, etc.)
- Standard error messages
- Common placeholder values
- Reserved IP ranges already in use

See `src/har_capture/patterns/allowlist.json` for complete list.

## Customization

Add your own patterns using [Custom Patterns](CUSTOM_PATTERNS.md).

## See Also

- [Custom Patterns Guide](CUSTOM_PATTERNS.md) - Add organization-specific patterns
- [Correlation-Preserving Redaction](CORRELATION.md) - How hashing works
- [Interactive Sanitization](INTERACTIVE_SANITIZATION.md) - Review edge cases manually
