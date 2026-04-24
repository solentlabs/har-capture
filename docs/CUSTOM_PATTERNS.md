# Custom Patterns Guide

## Overview

har-capture's pattern matching system is fully extensible. You can add custom patterns for organization-specific data (employee IDs, product serials, custom tokens) without modifying the package.

## Pattern Files

Patterns are stored in external JSON files:

```
src/har_capture/patterns/
├── pii.json          # PII detection patterns
├── sensitive.json    # Sensitive headers/fields
├── allowlist.json    # Safe placeholder values
└── capture.json      # Browser capture patterns
```

## Creating Custom Patterns

### Basic Pattern Structure

```json
{
  "patterns": {
    "pattern_name": {
      "regex": "PATTERN_HERE",
      "replacement_prefix": "PREFIX",
      "description": "Human-readable description"
    }
  }
}
```

### Example: Customer ID Pattern

```json
{
  "patterns": {
    "customer_id": {
      "regex": "CUST-[A-Z0-9]{8}",
      "replacement_prefix": "CUSTID",
      "description": "Customer ID in format CUST-XXXXXXXX"
    }
  }
}
```

**Input:** `Customer: CUST-A1B2C3D4`
**Output:** `Customer: CUSTID_e5f6a7b8` (salted hash)
**Output (no-salt):** `Customer: CUSTID_REDACTED`

## Pattern Fields

### Required Fields

- **`regex`** (string): Regular expression to match
- **`replacement_prefix`** (string): Prefix for redacted value

### Optional Fields

- **`description`** (string): Human-readable description
- **`case_sensitive`** (boolean): Case-sensitive matching (default: false)
- **`flags`** (array): Regex flags (e.g., `["IGNORECASE", "MULTILINE"]`)

## Using Custom Patterns

### CLI

```bash
# Single file
har-capture sanitize capture.har --patterns my_patterns.json

# With validation
har-capture validate capture.har --patterns my_patterns.json

# With capture
har-capture get https://example.com --patterns my_patterns.json
```

### Python API

```python
from har_capture.sanitization import sanitize_html, sanitize_har_file

# From file path
clean = sanitize_html(html, custom_patterns="my_patterns.json")

# From dict (e.g., loaded from YAML)
patterns_dict = {
    "patterns": {
        "modem_serial": {
            "regex": r"SN[0-9]{10}",
            "replacement_prefix": "MODEM_SN"
        }
    }
}
sanitize_har_file("capture.har", custom_patterns=patterns_dict)
```

## Extending Sensitive Field Detection

The examples above extend `pii.patterns` — value-based regexes that match anywhere in content (e.g. a customer-ID string format). Field-level redaction is a separate pass: when sanitizing form bodies, JSON bodies, XML elements, `postData.params`, or inline `localStorage.setItem` calls, the engine checks the **field name** against two regex sets loaded from `sensitive.json`:

- **`fields.auto_redact_patterns`** — field names that trigger automatic redaction of the associated value (100% confidence, e.g. `password`, `secret`, `token`).
- **`fields.flag_patterns`** — field names that flag the value for interactive review (e.g. `username`, `account_id`).

To add a field name that the built-ins don't recognize — for instance, a device-specific credential field like `pws`, `loginPassword`, or a product-specific token name — use the same `custom_patterns` kwarg with the `fields` schema. Extensions are additive (built-ins continue to apply) and scoped to the single call via a `ContextVar`, so module state is never mutated and concurrent callers don't observe each other's patterns.

### Schema

```json
{
  "fields": {
    "auto_redact_patterns": ["pws", "custom_token"],
    "flag_patterns": ["deploy_env"]
  }
}
```

Each entry is a regex (same syntax as the built-in `sensitive.json`). Matching is case-insensitive; use `\b` boundaries to avoid accidental substring hits.

### Python API — per-call extension

```python
from har_capture.sanitization import sanitize_post_data

# Device-specific credential field from a product catalog at runtime.
custom = {"fields": {"auto_redact_patterns": ["pws"]}}

post_data = {
    "mimeType": "application/x-www-form-urlencoded",
    "text": "user=admin&pws=hunter2",
}

result = sanitize_post_data(post_data, custom_patterns=custom)
# result["text"] == "user=admin&pws=[REDACTED]"
```

The same extension applies to `sanitize_html` for inline-script field matching:

```python
from har_capture.sanitization import sanitize_html

html = 'localStorage.setItem("pws", "hunter2")'
clean = sanitize_html(html, custom_patterns=custom)
# "hunter2" is redacted; key name "pws" is preserved.
```

And to the top-level entry points that delegate to these:

```python
from har_capture.sanitization import sanitize_har_file

sanitize_har_file(
    "capture.har",
    custom_patterns={"fields": {"auto_redact_patterns": ["pws"]}},
)
```

### File form (same schema)

Anywhere a dict works, a file path containing the same JSON works too:

```json
{
  "_comment": "custom_fields.json",
  "fields": {
    "auto_redact_patterns": ["pws", "custom_token"]
  }
}
```

```bash
har-capture sanitize capture.har --patterns custom_fields.json
```

### Scope and isolation

- The override applies only to the call that passes `custom_patterns`.
- Module-level patterns (`sensitive.json`) are never mutated.
- The override uses a `ContextVar`, so concurrent threads / asyncio tasks observe their own patterns with no cross-talk.
- Compiled regexes are cached per canonical key, so repeated calls with the same extension skip the recompile.

### Combining with `pii.patterns`

A single dict (or file) can extend both `pii.patterns` and `fields` at once:

```python
custom = {
    "patterns": {
        "modem_serial": {"regex": r"SN[0-9]{10}", "replacement_prefix": "MODEM_SN"},
    },
    "fields": {
        "auto_redact_patterns": ["pws"],
        "flag_patterns": ["deploy_env"],
    },
}
sanitize_har_file("capture.har", custom_patterns=custom)
```

## Pattern Examples

### Serial Numbers

```json
{
  "patterns": {
    "modem_serial": {
      "regex": "SN[0-9]{10}",
      "replacement_prefix": "SERIAL",
      "description": "Modem serial number"
    }
  }
}
```

### API Keys

```json
{
  "patterns": {
    "api_key": {
      "regex": "sk_live_[a-zA-Z0-9]{32}",
      "replacement_prefix": "APIKEY",
      "description": "Stripe API key"
    }
  }
}
```

### Employee IDs

```json
{
  "patterns": {
    "employee_id": {
      "regex": "EMP[0-9]{6}",
      "replacement_prefix": "EMPID",
      "description": "6-digit employee ID"
    }
  }
}
```

### Device Names

```json
{
  "patterns": {
    "device_name": {
      "regex": "MyDevice-[A-Z]{2}[0-9]{4}",
      "replacement_prefix": "DEVICE",
      "description": "Device naming pattern"
    }
  }
}
```

## Advanced: Multi-Field Patterns

### Combining Multiple Patterns

```json
{
  "patterns": {
    "order_id": {
      "regex": "ORD-[0-9]{8}",
      "replacement_prefix": "ORDER"
    },
    "invoice_id": {
      "regex": "INV-[0-9]{8}",
      "replacement_prefix": "INVOICE"
    },
    "tracking_number": {
      "regex": "TRACK-[A-Z0-9]{12}",
      "replacement_prefix": "TRACKING"
    }
  }
}
```

## Pattern Testing

### Test Pattern Matching

```python
import re
from har_capture.patterns import load_patterns

# Load your patterns
patterns = load_patterns("my_patterns.json")

# Test against sample data
sample = "Customer CUST-A1B2C3D4 placed order ORD-12345678"

for name, pattern in patterns["patterns"].items():
    regex = re.compile(pattern["regex"])
    matches = regex.findall(sample)
    if matches:
        print(f"{name}: {matches}")
```

### Validation

```bash
# Validate that your patterns catch what they should
echo "Test data: CUST-A1B2C3D4" > test.txt
har-capture validate test.txt --patterns my_patterns.json
```

## Pattern Best Practices

### 1. Be Specific

❌ **Too broad:**

```json
{
  "regex": "[A-Z0-9]+"  // Matches everything
}
```

✅ **Specific:**

```json
{
  "regex": "CUST-[A-Z0-9]{8}"  // Matches only customer IDs
}
```

### 2. Use Anchors When Needed

```json
{
  "regex": "^API_KEY:[a-z0-9]{32}$"  // Exact match
}
```

### 3. Escape Special Characters

```json
{
  "regex": "order\\#[0-9]+"  // Matches "order#123"
}
```

### 4. Test with Real Data

Always test patterns against real examples before deploying.

## Pattern Organization

### Single Project

`patterns/custom.json`:

```json
{
  "patterns": {
    "project_specific_1": {...},
    "project_specific_2": {...}
  }
}
```

### Multiple Projects

```
patterns/
├── base.json           # Common patterns
├── project_a.json      # Project A specific
└── project_b.json      # Project B specific
└── combined.json       # Merged patterns for project A
```

**Note:** The CLI currently supports only one `--patterns` file at a time. To use multiple pattern sets, merge them into a single file:

```bash
# Merge patterns (example with jq)
jq -s '.[0] * .[1]' patterns/base.json patterns/project_a.json > patterns/combined.json

# Use combined patterns
har-capture sanitize capture.har --patterns patterns/combined.json
```

Alternatively, use the Python API which accepts pattern dictionaries that can be merged programmatically.

## Troubleshooting

### Pattern Not Matching

1. **Check regex syntax**: Test with online regex tools
1. **Check case sensitivity**: Add `"case_sensitive": false`
1. **Check escaping**: Ensure special chars are escaped
1. **Enable verbose mode**: `har-capture sanitize --verbose`

### Over-Redacting

If pattern matches too much:

1. Make pattern more specific
1. Add context anchors (word boundaries, etc.)
1. Test against diverse samples

### Under-Redacting

If pattern misses cases:

1. Check for variations (case, spacing, format)
1. Broaden pattern carefully
1. Consider adding multiple patterns for variants

## See Also

- [Interactive Sanitization Guide](INTERACTIVE_SANITIZATION.md) - Review edge cases manually
- [PII Categories](PII_CATEGORIES.md) - Built-in patterns
- [CLI Reference](CLI_REFERENCE.md) - Command line usage
