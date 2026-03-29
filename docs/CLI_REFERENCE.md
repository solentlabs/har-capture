# CLI Reference

## Commands

- [`get`](#get) - Capture HTTP traffic
- [`sanitize`](#sanitize) - Remove PII from HAR files
- [`validate`](#validate) - Check for PII leaks

______________________________________________________________________

## get

Capture HTTP traffic using a browser. **By default, the output is sanitized and compressed** - you get a single `.sanitized.har.gz` file ready to share.

`get` is the default command — you can omit it when the first argument is a URL, hostname, or IP address.

### Basic Usage

```bash
har-capture <TARGET>
har-capture get <TARGET>
```

### Arguments

- `TARGET` - URL or local file path to capture

### Options

#### Output Options

- `--output PATH` - Output file path (default: `<target>.har`)
- `--keep-raw` - Keep unsanitized `.har` file (deleted by default)
- `--no-sanitize` - Skip sanitization (not recommended)
- `--no-compress` - Skip compression

#### Capture Options

- `--browser {chromium,firefox,webkit}` - Browser engine (default: chromium)
- `--wait-for-data / --no-wait-for-data` - Wait for async data to load on each page (default: enabled)
- `--username TEXT` - Username for HTTP Basic Auth
- `--password TEXT` - Password for HTTP Basic Auth

#### Sanitization Options

- `--salt TEXT` - Consistent salt for correlation (default: random)
- `--no-salt` - Use static placeholders instead of salted hashes
- `--patterns PATH` - Custom patterns JSON file

Interactive review of flagged values is always enabled after capture.

### Examples

```bash
# Basic capture (outputs: example.com.sanitized.har.gz)
har-capture https://example.com

# Explicit 'get' subcommand (equivalent)
har-capture get https://example.com

# Custom output path
har-capture 192.168.1.1 --output modem.har

# Keep raw unsanitized file for debugging
har-capture https://example.com --keep-raw

# Use consistent salt for correlation across captures
har-capture https://example.com --salt my-debug-key

# Disable async data wait for faster capture of simple sites
har-capture https://example.com --no-wait-for-data
```

### Default Workflow

1. Captures all HTTP traffic to a raw `.har` file
1. Sanitizes PII → creates `.sanitized.har`
1. Compresses → creates `.sanitized.har.gz`
1. Deletes intermediate files (raw and uncompressed sanitized)

Use `--keep-raw` to preserve the original unsanitized file.

______________________________________________________________________

## sanitize

Remove PII from HAR files.

### Basic Usage

```bash
har-capture sanitize INPUT.har
```

### Arguments

- `INPUT` - HAR file to sanitize

### Options

#### Output Options

- `--output PATH` - Output file path (default: `INPUT.sanitized.har`)
- `--compress` - Compress output to `.har.gz`
- `--compression-level INT` - Compression level 1-9 (default: 9, max compression)

#### Sanitization Options

- `--salt TEXT` - Consistent salt for correlation (default: random)
- `--no-salt` - Use static placeholders instead of salted hashes
- `--patterns PATH` - Custom patterns JSON file
- `--report PATH` - Save sanitization report to JSON file

Interactive review of flagged values is always enabled. If no TTY is available, flagged values are written to a report file instead.

#### Size Limits

- `--max-size INT` - Maximum HAR size in MB (default: 100)

### Examples

```bash
# Basic sanitization
har-capture sanitize capture.har

# Custom output with compression
har-capture sanitize capture.har --output clean.har --compress

# Generate sanitization report
har-capture sanitize capture.har --report report.json

# Consistent salt for correlation across files
har-capture sanitize capture.har --salt my-debug-key

# Static placeholders (no correlation)
har-capture sanitize capture.har --no-salt

# Custom patterns
har-capture sanitize capture.har --patterns modem_patterns.json

# Allow larger files
har-capture sanitize capture.har --max-size 500

# Faster compression (lower ratio)
har-capture sanitize capture.har --compress --compression-level 6
```

### Interactive Review

Interactive review is always enabled. After sanitization, suspicious values that don't match standard patterns (WiFi SSIDs, device names, custom credentials) are presented for review.

- **TTY available**: Interactive table where you select values to redact
- **No TTY (CI/CD)**: Flagged values written to a JSON report file

See [Interactive Sanitization Guide](INTERACTIVE_SANITIZATION.md) for details.

______________________________________________________________________

## validate

Check HAR files for PII leaks.

### Basic Usage

```bash
har-capture validate INPUT.har
```

### Arguments

- `INPUT` - HAR file or directory to validate

### Options

#### Validation Options

- `--dir PATH` - Validate all `.har` files in directory
- `--recursive` - Recursively scan subdirectories
- `--strict` - Fail on warnings (not just errors)
- `--patterns PATH` - Custom patterns JSON file

### Examples

```bash
# Validate single file
har-capture validate capture.har

# Validate all HAR files in directory
har-capture validate --dir ./captures

# Recursive validation
har-capture validate --dir ./captures --recursive

# Strict mode - fail on warnings
har-capture validate capture.har --strict

# Custom patterns
har-capture validate capture.har --patterns custom.json
```

### Exit Codes

- `0` - No PII found (or warnings only in non-strict mode)
- `1` - PII found or validation error
- `2` - File not found or invalid arguments

______________________________________________________________________

## Global Options

Available for all commands:

- `--help` - Show help message
- `--version` - Show version number
- `-v, --verbose` - Verbose output
- `-q, --quiet` - Suppress non-error output

______________________________________________________________________

## Examples by Use Case

### Support Diagnostics

User captures and sanitizes HAR file for support ticket:

```bash
# User runs this
har-capture https://myapp.example.com

# Outputs: myapp.example.com.sanitized.har.gz
# User attaches to support ticket
```

### Automated Testing

Generate sanitized test fixtures:

```bash
# Capture with consistent salt for reproducible output
har-capture get https://api.example.com --salt test-fixture-key --output api_test.har
```

### Batch Processing

Sanitize multiple HAR files:

```bash
# Validate all files first
har-capture validate --dir ./raw_hars --recursive

# Sanitize each file
for file in ./raw_hars/*.har; do
  har-capture sanitize "$file" --compress --patterns custom.json
done
```

### Security Review

Check for PII leaks before sharing:

```bash
# Strict validation
har-capture validate capture.har --strict

# If clean, compress and share
gzip capture.har
```
