# Interactive Sanitization Mode

Interactive sanitization mode allows you to review and approve suspicious values that couldn't be automatically redacted. This is useful for edge cases like WiFi SSIDs, device names, or credentials that don't match standard patterns.

## Quick Start

```bash
# Review suspicious values interactively
har-capture sanitize device.har --interactive

# Save a detailed JSON report
har-capture sanitize device.har --report sanitization-report.json
```

## How It Works

Sanitization happens in **two passes**:

### Pass 1: Auto-Redact and Flag

- Automatically redacts known patterns (MAC addresses, IPs, passwords, etc.)
- Flags suspicious values that need manual review using heuristics
- Generates a report with flagged values and context

### Pass 2: Apply User Decisions

- You review flagged values and decide which to redact
- Selected values are redacted via global find-replace
- Salt is preserved to ensure consistent hashing across both passes

## Flagging Heuristics

Values are flagged based on several detection methods:

| Heuristic                | Example                                   | Confidence  | Description                                                |
| ------------------------ | ----------------------------------------- | ----------- | ---------------------------------------------------------- |
| **SSID-like strings**    | `HomeNetwork-5G`, `Office-Guest`          | HIGH/MEDIUM | 3-32 characters with patterns like `Name-5G`, `WiFi-Guest` |
| **Device names**         | `Johns-iPhone`, `Living-Room-TV`          | MEDIUM      | Contains possessives, device types, or room names          |
| **High entropy**         | `MyS3cur3Pass`, `P@ssw0rd!`               | MEDIUM      | 8+ characters with mixed case, numbers, special chars      |
| **Adjacent to redacted** | Value next to `MAC_xxxxx` or `PASS_xxxxx` | HIGH        | Appears before/after an already-redacted value             |

### Safe Values (Never Flagged)

Common technical values are automatically considered safe:

- Status values: `Good`, `Bad`, `OK`, `Error`, `Enabled`, `Disabled`
- Security types: `WPA`, `WPA2`, `WPA3`, `Open`
- Band indicators: `2.4g`, `5g`, `6g`
- Numbers, versions, timestamps, percentages
- Already redacted placeholders

## Interactive Review UI

When you use `--interactive`, you'll see a beautiful table of flagged values:

```
┌─ Flagged Values for Review ─────────────────────────────────────────┐
│  #  Match  Type            Value                  Context            │
├─────────────────────────────────────────────────────────────────────┤
│  1    ●    📶 WiFi SSID    HomeNetwork-5G        ...Good|>>>Home... │
│  2    ●    📶 WiFi SSID    HomeNetwork-2G        ...5g|>>>HomeNe... │
│  3    ●    🔑 Password     secret123             ...5G|>>>secret... │
│  4    ●    📱 Device       Johns-iPhone (2x)     ...>>>Johns-iP... │
└─────────────────────────────────────────────────────────────────────┘
```

### Quick Actions

Choose how to handle flagged values:

- **📋 Select individually** - Review each item with checkboxes
- **✅ Redact ALL flagged values** - Redact everything
- **🔴 Redact HIGH confidence only** - Only redact high-confidence items
- **🔴🟡 Redact HIGH + MEDIUM** - Skip low-confidence items
- **⏭️ Skip review** - Keep all values as-is

### Individual Selection

Use checkboxes to select specific values to redact:

- `↑↓` - Navigate
- `Space` - Toggle selection
- `a` - Select all
- `n` - Deselect all
- `Enter` - Confirm
- `Backspace/ESC` - Go back

Passwords/credentials are pre-selected by default, but you can adjust any selection.

## Examples

### Basic Interactive Review

```bash
har-capture sanitize device.har --interactive
```

Output:

```
Sanitizing device.har...
  Auto-redacted: 47 values

Found 5 suspicious values that may need review:
[interactive table shows here]

How would you like to handle flagged values?
> 📋 Select individually (5 items)

[checkbox interface shows here]

✓ Marked 4 items for redaction, skipped 1.

Review complete!
  Auto-redacted: 47
  User redacted: 4
  User skipped: 1

Sanitized: device.sanitized.har
```

### Generate Report for Later Review

```bash
har-capture sanitize device.har --report review.json
```

The report contains:

```json
{
  "input_file": "device.har",
  "output_file": "device.sanitized.har",
  "salt": "a1b2c3d4e5f6",  # pragma: allowlist secret
  "summary": {
    "auto_redacted": 47,
    "user_redacted": 0,
    "user_skipped": 0
  },
  "auto_redacted_counts": {
    "mac_address": 12,
    "private_ip": 15,
    "password": 8
  },
  "flagged": [
    {
      "value": "HomeNetwork-5G",
      "category": "wifi_ssid",
      "confidence": "high",
      "reason": "SSID-like pattern: ends with band/extension suffix",
      "occurrences": 2,
      "status": "flagged"
    }
  ]
}
```

### Non-Interactive Mode (CI/CD)

When running in a non-TTY environment (like CI):

```bash
har-capture sanitize device.har --interactive 2>&1
# Warning: --interactive requires a terminal. Writing flagged values to report instead.
# Sanitized: device.sanitized.har
# Report: device.har.review.json
```

## Edge Cases Handled

### No Suspicious Values

```
Sanitizing device.har...
  Auto-redacted: 47 values
  Flagged for review: 0

✓ No suspicious values found. All values were handled automatically.
Sanitized: device.sanitized.har
```

### Common Word Warnings

If a flagged value appears many times, you'll see a warning:

```
  WARNING: "Guest" appears 47 times in the file.
  Redacting will replace ALL occurrences.
```

This helps you make informed decisions about common words.

### Already Sanitized Files

```
Warning: This file appears to already be sanitized.
  Found redaction placeholders (MAC_xxxxx, PASS_xxxxx, etc.)
  Proceeding may double-hash already redacted values.

Continue? [y/N]
```

## Python API

You can also use interactive sanitization programmatically:

```python
from har_capture.sanitization import sanitize_har, apply_user_redactions
from har_capture.cli.interactive import run_interactive_review
import json

# Pass 1: Auto-redact and flag
with open("device.har") as f:
    har_data = json.load(f)

sanitized, report = sanitize_har(har_data, flag_suspicious=True)

# Interactively review (if there are flagged values)
if report.flagged:
    run_interactive_review(report)

# Pass 2: Apply user decisions
if report.total_user_redacted > 0:
    final = apply_user_redactions(sanitized, report)
else:
    final = sanitized

# Save result
with open("device.sanitized.har", "w") as f:
    json.dump(final, f, indent=2)
```

## Salt Preservation

The salt used for hashing is stored in the report and reused in Pass 2. This ensures:

- Consistent hashing across both passes
- Same sensitive value produces same placeholder (`MAC_abc123ef`)
- Correlation is preserved (same MAC address always becomes the same placeholder)

## Tips

1. **High confidence items** are usually safe to redact (e.g., values next to passwords)
1. **Medium confidence** often includes SSIDs and device names - review the context
1. **Low confidence** items need careful review to avoid false positives
1. Use the **occurrence count** to assess impact - redacting "test" that appears 100 times might affect legitimate content
1. **ESC/Backspace** lets you go back and change your mind
1. **Ctrl+C** cancels the review (file is still sanitized, but flagged values remain unchanged)

## Troubleshooting

### Terminal encoding issues

If you see garbled characters, ensure your terminal supports UTF-8:

```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```

### InquirerPy errors

If the interactive prompts crash, the tool falls back gracefully and writes a report file instead.

### Performance with large HAR files

For very large HAR files (>50MB), consider using `--report` to review flagged values separately rather than doing it interactively.

## Related Documentation

- [Sanitization Overview](../README.md#sanitization) - Main sanitization features
- [Custom Patterns](../README.md#custom-patterns) - Add your own redaction patterns
