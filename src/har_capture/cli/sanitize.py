"""Sanitize command for har-capture CLI."""

from __future__ import annotations

import contextlib
import gzip
import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from har_capture.cli import interactive
from har_capture.cli._completeness_display import display_completeness
from har_capture.cli._patterns_resolver import require_patterns
from har_capture.patterns import PatternLoadError
from har_capture.sanitization.report import HeuristicMode, ReviewOutcome
from har_capture.validation import analyze_har_file

# The name that stands for a standard stream in --report and --apply-review.
_STREAM = "-"


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
        typer.Option(
            "--patterns",
            "-p",
            help="Required. Pattern domain (e.g. 'network-device'), 'base' for universal PII only, or JSON path. Repeatable.",
        ),
    ] = None,
    max_size: Annotated[
        int | None,
        typer.Option("--max-size", help="Max file size in MB (default: 100, 0=unlimited)"),
    ] = 100,
    compression_level: Annotated[
        int,
        typer.Option("--compression-level", help="Gzip compression level 1-9 (default: 9)"),
    ] = 9,
    report: Annotated[
        Path | None,
        typer.Option(
            "--report",
            "-r",
            help="Write the JSON report to a file, or to standard output with '-' (messages then go to standard error)",
        ),
    ] = None,
    apply_review: Annotated[
        Path | None,
        typer.Option(
            "--apply-review",
            help=(
                "Decide the flagged values from a review report instead of prompting: a file, or standard "
                "input with '-'. In the report, set each item's status to 'user' (redact) or 'skipped' (keep)."
            ),
        ),
    ] = None,
    keep_static_addresses: Annotated[
        bool,
        typer.Option(
            "--keep-static-addresses",
            help=(
                "Leave MAC and IP addresses alone in JavaScript, CSS and plain-text response bodies "
                "(example addresses in help text). Default: redact them. Use only for static assets."
            ),
        ),
    ] = False,
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
        report: Write JSON report to file
        apply_review: Review report whose decisions replace the interactive review
        keep_static_addresses: Leave MAC and IP addresses in static script, CSS and text bodies

    Example:
        har-capture sanitize device.har --patterns network-device
        har-capture sanitize device.har --patterns network-device --output clean.har --compress
        har-capture sanitize device.har --patterns network-device --salt my-key  # Consistent hashing
        har-capture sanitize device.har --patterns network-device --no-salt  # Static placeholders
        har-capture sanitize device.har --patterns network-device --max-size 500  # Allow up to 500MB
        har-capture sanitize device.har --patterns network-device --max-size 0  # No size limit
        har-capture sanitize device.har --patterns network-device --report sanitize-report.json
        har-capture sanitize device.har --patterns network-device --keep-static-addresses
        har-capture sanitize device.har --patterns network-device --report - > /dev/null  # report on stdout
        har-capture sanitize device.har --patterns network-device --apply-review - < decisions.json
    """
    from har_capture.sanitization import (
        HarSizeError,
        HarValidationError,
        apply_review_decisions,
        load_review_decisions,
        read_review_decisions,
        sanitize_har_file,
    )

    # Validate --patterns up front so a user running `har-capture sanitize FILE`
    # without choosing a domain gets the listing error before any disk I/O.
    custom_patterns = require_patterns(patterns)

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

    # A decided review report stands in for the prompt. Read it before any
    # work, so a report that cannot be used stops the run with nothing written.
    # `-` names a standard stream for either report, so the flagged values a
    # report holds need never be written to disk.
    decisions = None
    decisions_from_stdin = apply_review is not None and str(apply_review) == _STREAM
    if apply_review is not None:
        try:
            decisions = (
                read_review_decisions(json.load(sys.stdin))
                if decisions_from_stdin
                else load_review_decisions(apply_review)
            )
        except (OSError, ValueError) as e:
            source = "standard input" if decisions_from_stdin else str(apply_review)
            typer.echo(f"Error: Cannot read review report from {source}: {e}", err=True)
            raise typer.Exit(1) from None
    report_to_stdout = report is not None and str(report) == _STREAM
    # Decisions that came through a stream get any undecided remainder back
    # through one, so standard output is kept for it.
    stdout_reserved = report_to_stdout or (report is None and decisions_from_stdin)

    # Interactive review is always enabled. One answer for both uses: the
    # already-sanitized confirmation and the review itself. Without a terminal
    # nobody is asked, and the flagged values reach a report only where
    # --report asks for one: a report holds them as captured, so none is
    # written to disk unasked.
    run_heuristics = True
    interactive_terminal = interactive.stdin_is_tty() and decisions is None

    if decisions is None and not interactive_terminal:
        typer.echo(
            "Note: No terminal detected, so nobody is asked about the flagged values."
            + ("" if report else " Add --report - to get them on standard output."),
            err=True,
        )

    output_path = str(output) if output else None

    # Convert max_size from MB to bytes (0 = unlimited)
    max_size_bytes: int | None = None
    if max_size is not None and max_size > 0:
        max_size_bytes = max_size * 1024 * 1024

    # Handle salt options
    effective_salt: str | None = salt
    if no_salt:
        effective_salt = None

    # With standard output kept for the report, every message goes to standard
    # error: what a caller reads from the pipe is the report and nothing else.
    report_stream = sys.stdout
    with contextlib.redirect_stdout(sys.stderr) if stdout_reserved else contextlib.nullcontext():
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
                if interactive_terminal:
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
                keep_static_addresses=keep_static_addresses,
            )

            # Interactive review mode (requires TTY). Every flagged run records
            # how its review ended; save_review regenerates an existing .gz.
            review_refreshed_sibling = bool(sanitization_report.flagged)
            undecided = 0
            if decisions is not None and sanitization_report.flagged:
                # The report's decisions are the review. Any value it leaves
                # undecided makes the review unfinished: what was decided is
                # applied, the rest is written back to a report, and the run fails.
                interactive.display_sanitization_summary(
                    sanitization_report, str(input_file), result_path, salt_mode
                )
                undecided = apply_review_decisions(sanitization_report, decisions)
                outcome = ReviewOutcome.CANCELLED if undecided else ReviewOutcome.COMPLETED
                interactive.save_review(sanitization_report, result_path, outcome)
                # Decisions that came through a stream get the remainder back
                # through one; a report file is written only where --report names it.
                if undecided and report is None and decisions_from_stdin:
                    report_to_stdout = True

            elif interactive_terminal and sanitization_report.flagged:
                outcome = interactive.run_interactive_review(
                    sanitization_report,
                    input_path=str(input_file),
                    output_path=result_path,
                    salt_mode=salt_mode,
                )
                interactive.save_review(sanitization_report, result_path, outcome)
                interactive.display_summary(sanitization_report)

            else:
                # Non-interactive mode: display sanitization summary
                interactive.display_sanitization_summary(
                    sanitization_report, str(input_file), result_path, salt_mode
                )

                if sanitization_report.flagged:
                    interactive.save_review(sanitization_report, result_path, ReviewOutcome.NO_TTY)
                    interactive.warn_unreviewed(len(sanitization_report.flagged), result_path)
                else:
                    typer.echo()
                    typer.echo("No suspicious values found. All values were handled automatically.")

            # Write report if requested
            if report_to_stdout:
                json.dump(sanitization_report.to_dict(), report_stream, indent=2)
                report_stream.write("\n")
            elif report:
                with open(report, "w", encoding="utf-8", newline="\n") as f:
                    json.dump(sanitization_report.to_dict(), f, indent=2)
                typer.echo(f"  Report: {report}")

            if undecided:
                typer.echo(
                    f"Error: {undecided} flagged value(s) have no decision. They remain in {result_path} as "
                    "captured, and the file records review: cancelled. "
                    + (
                        "Decide them in the report on standard output"
                        if report_to_stdout
                        else f"Decide them in {report}"
                        if report
                        else "Add --report - to see them, decide them"
                    )
                    + " and run the command again with --apply-review.",
                    err=True,
                )
                raise typer.Exit(1)

            # The sanitize pass rewrites result_path even with zero redactions
            # (fresh salt each run), so a compressed sibling from an earlier
            # --compress run is stale the moment we get here. --compress
            # rewrites it below and the review path just refreshed it; every
            # other path refreshes it now so the .har/.har.gz pair never
            # diverges.
            if not compress and not review_refreshed_sibling:
                sibling = Path(str(result_path) + ".gz")
                if sibling.exists():
                    interactive.regenerate_compressed_har(Path(result_path), sibling)

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

            # Report against the sanitized output — the file the operator shares.
            typer.echo()
            display_completeness(analyze_har_file(result_path))
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
