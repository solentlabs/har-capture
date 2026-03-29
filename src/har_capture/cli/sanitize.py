"""Sanitize command for har-capture CLI."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Annotated, Any

import typer

from har_capture.patterns import PatternLoadError
from har_capture.sanitization.report import HeuristicMode


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
        list[str] | None,
        typer.Option("--patterns", "-p", help="Pattern names or JSON file paths (repeatable)"),
    ] = None,
    max_size: Annotated[
        int | None,
        typer.Option("--max-size", help="Max file size in MB (default: 100, 0=unlimited)"),
    ] = 100,
    compression_level: Annotated[
        int,
        typer.Option("--compression-level", help="Gzip compression level 1-9 (default: 9)"),
    ] = 9,
    no_interactive: Annotated[
        bool,
        typer.Option("--no-interactive", help="Skip interactive review of suspicious values"),
    ] = False,
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Write JSON report to file"),
    ] = None,
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
        no_interactive: Skip interactive review of suspicious values
        report: Write JSON report to file

    Example:
        har-capture sanitize device.har
        har-capture sanitize device.har --output clean.har --compress
        har-capture sanitize device.har --salt my-key  # Consistent hashing
        har-capture sanitize device.har --no-salt  # Static placeholders
        har-capture sanitize device.har --max-size 500  # Allow up to 500MB
        har-capture sanitize device.har --max-size 0  # No size limit
        har-capture sanitize device.har --no-interactive  # Skip interactive review
        har-capture sanitize device.har --report sanitize-report.json
    """
    import sys

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

    # Handle interactive mode TTY check
    # Interactive is on by default; skip with --no-interactive
    interactive = not no_interactive
    run_heuristics = interactive
    interactive_terminal = interactive and sys.stdin.isatty()

    if interactive and not sys.stdin.isatty():
        typer.echo(
            "Note: No terminal detected. Writing flagged values to report instead.",
            err=True,
        )
        if report is None:
            report = Path(str(input_file) + ".review.json")

    output_path = str(output) if output else None

    # Resolve --patterns args (names → built-in paths, file paths → validated)
    custom_patterns: str | dict[str, Any] | None = None
    if patterns:
        from har_capture.patterns.loader import merge_pattern_files, resolve_patterns_arg

        resolved = [resolve_patterns_arg(p) for p in patterns]
        if len(resolved) == 1:
            custom_patterns = str(resolved[0])
        else:
            custom_patterns = merge_pattern_files(resolved)

    # Convert max_size from MB to bytes (0 = unlimited)
    max_size_bytes: int | None = None
    if max_size is not None and max_size > 0:
        max_size_bytes = max_size * 1024 * 1024

    # Handle salt options
    effective_salt: str | None = salt
    if no_salt:
        effective_salt = None

    typer.echo(f"Sanitizing {input_file}...")

    # Determine salt mode description for display
    if effective_salt == "auto":
        salt_mode = "random (correlation within file)"
    elif effective_salt is None:
        salt_mode = "static placeholders (no correlation)"
    else:
        salt_mode = "provided (consistent across runs)"

    try:
        # Check if file appears already sanitized
        from har_capture.sanitization import appears_sanitized

        with open(input_file, encoding="utf-8") as f:
            har_data_check = json.load(f)

        is_sanitized, match_count = appears_sanitized(har_data_check)
        if is_sanitized:
            typer.echo()
            typer.echo("Warning: This file appears to already be sanitized.")
            typer.echo(f"  Found {match_count} redaction placeholder(s) (MAC_xxxxx, PASS_xxxxx, etc.)")
            typer.echo("  Proceeding may double-hash already redacted values.")
            typer.echo()
            if sys.stdin.isatty():
                confirm = typer.confirm("Continue anyway?", default=False)
                if not confirm:
                    typer.echo("Aborted.")
                    raise typer.Exit(0)
            else:
                typer.echo("  (Non-interactive mode: proceeding anyway)")

        # Determine heuristics mode
        # Interactive mode enables heuristics for flagging suspicious values
        heuristics = HeuristicMode.FLAG if run_heuristics else HeuristicMode.DISABLED

        result_path, sanitization_report = sanitize_har_file(
            str(input_file),
            output_path,
            salt=effective_salt,
            custom_patterns=custom_patterns,
            max_size=max_size_bytes,
            heuristics=heuristics,
        )

        # Interactive review mode (requires TTY)
        if interactive_terminal and sanitization_report.flagged:
            from har_capture.cli.interactive import run_interactive_review

            review_completed = run_interactive_review(
                sanitization_report,
                input_path=str(input_file),
                output_path=result_path,
                salt_mode=salt_mode,
            )

            if review_completed and sanitization_report.total_user_redacted > 0:
                from har_capture.cli.interactive import apply_reviewed_redactions

                apply_reviewed_redactions(sanitization_report, result_path)

            # Display summary
            from har_capture.cli.interactive import display_summary

            display_summary(sanitization_report)

        else:
            # Non-interactive mode: display sanitization summary
            from har_capture.cli.interactive import display_sanitization_summary

            display_sanitization_summary(sanitization_report, str(input_file), result_path, salt_mode)

            if run_heuristics and not sanitization_report.flagged:
                typer.echo()
                typer.echo("No suspicious values found. All values were handled automatically.")

        # Write report if requested
        if report:
            with open(report, "w", encoding="utf-8") as f:
                json.dump(sanitization_report.to_dict(), f, indent=2)
            typer.echo(f"  Report: {report}")

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
    typer.echo("Before sharing, review the .har file for any remaining sensitive data.")
    typer.echo()
