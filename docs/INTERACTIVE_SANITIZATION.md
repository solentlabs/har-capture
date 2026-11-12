# Interactive Sanitization

Interactive review is always enabled. After auto-sanitization, suspicious values that couldn't be automatically
classified are presented for your review. This catches edge cases like WiFi SSIDs, device names, or credentials that
don't match standard patterns.

## Quick Start

```bash
# Sanitize and review flagged values
har-capture sanitize device.har --patterns network-device

# Also save a detailed JSON report
har-capture sanitize device.har --patterns network-device --report sanitization-report.json
```

## How It Works

Sanitization happens in **two passes**:

### Pass 1: Auto-Redact and Flag

- Automatically redacts known patterns (MAC addresses, IPs, passwords, etc.)
- Flags suspicious values that need manual review using heuristics
- Generates a report with flagged values and context

### Pass 2: Apply User Decisions

- You review flagged values and decide which to redact
- Selected values are redacted everywhere a string holds them, escaped and percent-encoded copies included
- Values under three characters are never offered: replacing one everywhere would rewrite unrelated text
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

When flagged values are found, you'll see a table for review:

```text
┌─ Flagged Values for Review ─────────────────────────────────────────┐
│  #  Match  Type            Value                  Context           │
├─────────────────────────────────────────────────────────────────────┤
│  1    ●    📶 WiFi SSID    HomeNetwork-5G        ...Good|>>>Home... │
│  2    ●    📶 WiFi SSID    HomeNetwork-2G        ...5g|>>>HomeNe... │
│  3    ●    🔑 Password     secret123             ...5G|>>>secret... │
│  4    ●    📱 Device       Johns-iPhone (2x)     ...>>>Johns-iP...  │
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
har-capture sanitize device.har --patterns network-device
```

Output:

```yaml
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
har-capture sanitize device.har --patterns network-device --report review.json
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

### Non-TTY Environment (CI/CD)

When no terminal is available nobody can be prompted, so the sanitized file records that nobody reviewed its flagged
values (`review: no_tty`), and `--report` hands them over as a JSON report. `har-capture validate` fails that file until
the values are decided.

The report holds each flagged value as captured, and the hashing salt. Pass it through the standard streams and it is
never written to disk:

```bash
# 1. The report on standard output; every message goes to standard error
har-capture sanitize device.har --patterns network-device --report - > review.tmp   # or read the pipe directly

# 2. Decide each item: "user" redacts the value, "skipped" keeps it
#      {"value": "MyNetwork-5G", "category": "wifi_ssid", "status": "user"},
#      {"value": "Link Down", "category": "credential", "status": "skipped"}

# 3. The decisions on standard input
har-capture sanitize device.har --patterns network-device --apply-review - < review.tmp
#   Applied 1 user redaction(s)
#   Recorded review: completed
```

A script or an AI session reads the report from the first command's output and writes the decided report to the second
command's input; the redirections above only show the shape. Decisions are matched on the value, so the report from one
run decides the same values in the next. A value left `flagged`, or one the report does not list, fails the run with
exit 1: the decisions made are applied, the file records `review: cancelled`, and the report comes back for the rest —
on standard output when the decisions came from standard input.

Without `--report`, a no-terminal run writes no report: the flagged values stay in the sanitized file and nowhere else.
`--report FILE` and `--apply-review FILE` take a file where one is wanted. That file is as sensitive as the raw capture:
delete it once the review is recorded and keep it out of version control (`*.review.json` in `.gitignore`).

`har-capture get` without a terminal writes no report at all: the raw capture never persists on disk. Run `sanitize` on
the sanitized file it produced, with `--report -`, to review its flagged values.

### Recorded Outcome

Every sanitized file says how its review ended, in `log._har_capture.sanitization.review`: `completed`, `skipped`,
`cancelled`, `no_tty` or `none_flagged` (absent when no review was recorded). Check it before relying on a file someone
else sanitized — `skipped`, `cancelled` and `no_tty` mean its flagged values were never redacted. `har-capture validate`
reports `cancelled` and `no_tty` as an error while the file has flagged values nobody decided. Run
`har-capture sanitize` on the file from a terminal to review them, or decide them in its report and pass
`--apply-review`.

## Edge Cases Handled

### No Suspicious Values

```text
Sanitizing device.har...
  Auto-redacted: 47 values
  Flagged for review: 0

✓ No suspicious values found. All values were handled automatically.
Sanitized: device.sanitized.har
```

### Common Word Warnings

If a flagged value appears many times, you'll see a warning:

```text
  WARNING: "Guest" appears 47 times in the file.
  Redacting will replace ALL occurrences.
```

This helps you make informed decisions about common words.

### Already Sanitized Files

```text
Warning: This file appears to already be sanitized.
  Found redaction placeholders (MAC_xxxxx, PASS_xxxxx, etc.)
  Proceeding may double-hash already redacted values.

Continue? [y/N]
```

## Python API

You can also use interactive sanitization programmatically:

```python
from har_capture.sanitization import sanitize_har, apply_user_redactions
from har_capture.sanitization.report import HeuristicMode
from har_capture.cli.interactive import run_interactive_review
import json

# Pass 1: Auto-redact and flag suspicious values
with open("device.har") as f:
    har_data = json.load(f)

sanitized, report = sanitize_har(har_data, heuristics=HeuristicMode.FLAG)

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
1. Use the **occurrence count** to assess impact - redacting "test" that appears 100 times might affect legitimate
   content
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

For very large HAR files (>50MB), consider using `--report` to review flagged values separately rather than doing it
interactively.

## Related Documentation

- [Sanitization Overview](../README.md#usage) - Main sanitization features
- [Custom Patterns](CUSTOM_PATTERNS.md) - Add your own redaction patterns
