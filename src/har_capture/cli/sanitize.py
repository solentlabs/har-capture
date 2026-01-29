"""Sanitize command for har-capture CLI."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Annotated

import typer

from har_capture.patterns import PatternLoadError


def sanitize(
    input_file: Annotated[
        Path,
        typer.Argument(help="HAR file to sanitize"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output filename (default: input.sanitized.har)"),
    ] = None,
    compress: Annotated[
        bool,
        typer.Option("--compress", "-c", help="Also create compressed .har.gz file"),
    ] = False,
    salt: Annotated[
        str | None,
        typer.Option(
            "--salt", "-s", help="Salt for hashed redaction (auto=random, none=static placeholders)"
        ),
    ] = "auto",
    no_salt: Annotated[
        bool,
        typer.Option("--no-salt", help="Use static placeholders instead of hashed values"),
    ] = False,
    patterns: Annotated[
        Path | None,
        typer.Option("--patterns", "-p", help="Custom patterns JSON file"),
    ] = None,
    max_size: Annotated[
        int | None,
        typer.Option("--max-size", help="Max file size in MB (default: 100, 0=unlimited)"),
    ] = 100,
    compression_level: Annotated[
        int,
        typer.Option("--compression-level", help="Gzip compression level 1-9 (default: 9)"),
    ] = 9,
) -> None:
    """Remove PII from a HAR file.

    Sanitizes headers, POST data, and response content to remove
    passwords, tokens, MAC addresses, IPs, and other PII.

    By default, uses salted hashes for redaction which preserves correlation
    (same value -> same hash) while hiding actual values.

    Args:
        input_file: HAR file to sanitize
        output: Output filename (default: input.sanitized.har)
        compress: Also create compressed .har.gz file
        salt: Salt for hashed redaction (default: random per session)
        no_salt: Use static placeholders instead of hashed values
        patterns: Custom patterns JSON file to merge with defaults
        max_size: Maximum file size in MB (default: 100, 0=unlimited)
        compression_level: Gzip compression level 1-9 (default: 9)

    Example:
        har-capture sanitize device.har
        har-capture sanitize device.har --output clean.har --compress
        har-capture sanitize device.har --salt my-key  # Consistent hashing
        har-capture sanitize device.har --no-salt  # Static placeholders
        har-capture sanitize device.har --max-size 500  # Allow up to 500MB
        har-capture sanitize device.har --max-size 0  # No size limit
    """
    from har_capture.sanitization import HarSizeError, HarValidationError, sanitize_har_file

    if not input_file.exists():
        typer.echo(f"Error: File not found: {input_file}", err=True)
        raise typer.Exit(1)

    # Validate compression level
    if not 1 <= compression_level <= 9:
        typer.echo(f"Error: compression-level must be 1-9, got {compression_level}", err=True)
        raise typer.Exit(1)

    # Validate max_size (must be >= 0)
    if max_size is not None and max_size < 0:
        typer.echo(f"Error: max-size must be >= 0, got {max_size}", err=True)
        raise typer.Exit(1)

    output_path = str(output) if output else None
    custom_patterns = str(patterns) if patterns else None

    # Convert max_size from MB to bytes (0 = unlimited)
    max_size_bytes: int | None = None
    if max_size is not None and max_size > 0:
        max_size_bytes = max_size * 1024 * 1024

    # Handle salt options
    effective_salt: str | None = salt
    if no_salt:
        effective_salt = None

    typer.echo(f"Sanitizing {input_file}...")
    if effective_salt == "auto":
        typer.echo("  Using random salt (correlation within file)")
    elif effective_salt is None:
        typer.echo("  Using static placeholders (no correlation)")
    else:
        typer.echo("  Using provided salt (consistent across runs)")

    try:
        result_path = sanitize_har_file(
            str(input_file),
            output_path,
            salt=effective_salt,
            custom_patterns=custom_patterns,
            max_size=max_size_bytes,
        )
        typer.echo(f"  Sanitized: {result_path}")

        if compress:
            result_path_obj = Path(result_path)
            compressed_path = result_path_obj.with_suffix(".har.gz")
            with (
                open(result_path, "rb") as f_in,
                gzip.open(compressed_path, "wb", compresslevel=compression_level) as f_out,
            ):
                f_out.write(f_in.read())
            gz_size = compressed_path.stat().st_size / 1024 / 1024
            typer.echo(f"  Compressed: {compressed_path} ({gz_size:.1f} MB)")
    except HarSizeError as e:
        size_mb = e.size / 1024 / 1024
        limit_mb = e.max_size / 1024 / 1024
        typer.echo(f"Error: File too large ({size_mb:.1f} MB > {limit_mb:.1f} MB limit)", err=True)
        typer.echo("  Use --max-size to increase limit or --max-size 0 to disable", err=True)
        raise typer.Exit(1) from None
    except HarValidationError as e:
        typer.echo(f"Error: Invalid HAR file: {e}", err=True)
        raise typer.Exit(1) from None
    except FileNotFoundError as e:
        typer.echo(f"Error: File not found: {e.filename}", err=True)
        raise typer.Exit(1) from None
    except PermissionError as e:
        typer.echo(f"Error: Permission denied: {e.filename}", err=True)
        raise typer.Exit(1) from None
    except json.JSONDecodeError as e:
        typer.echo(f"Error: Invalid JSON in HAR file: {e.msg} at line {e.lineno}", err=True)
        raise typer.Exit(1) from None
    except PatternLoadError as e:
        typer.echo(f"Error: Failed to load patterns: {e}", err=True)
        raise typer.Exit(1) from None
    except OSError as e:
        typer.echo(f"Error: I/O error: {e}", err=True)
        raise typer.Exit(1) from None

    typer.echo()
    typer.echo("WARNING: Automated sanitization is best-effort.")
    typer.echo("Before sharing, search the .har file for:")
    typer.echo("  - Your WiFi network name (SSID)")
    typer.echo("  - Your WiFi password")
    typer.echo("  - Your router admin password")
    typer.echo()
