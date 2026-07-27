"""Validate command for har-capture CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from har_capture.cli._completeness_display import display_completeness
from har_capture.cli._patterns_resolver import require_patterns


def validate(
    har_file: Annotated[
        Path | None,
        typer.Argument(help="HAR file to validate"),
    ] = None,
    directory: Annotated[
        Path | None,
        typer.Option("--dir", "-d", help="Directory to scan for HAR files"),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", "-s", help="Treat warnings as errors"),
    ] = False,
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r", help="Scan directory recursively"),
    ] = False,
    patterns: Annotated[
        list[str] | None,
        typer.Option(
            "--patterns",
            "-p",
            help="Required. Pattern domain (e.g. 'network-device'), 'base' for universal PII only, or JSON path. Repeatable.",
        ),
    ] = None,
) -> None:
    """Validate HAR files for secrets and PII.

    Scans HAR files for sensitive data that should be redacted before
    sharing or committing to version control.

    Args:
        har_file: Single HAR file to validate
        directory: Directory containing HAR files to scan
        strict: Treat warnings as errors (exit code 1)
        recursive: Scan directory recursively for HAR files
        patterns: Pattern names or JSON paths (repeatable); 'base' for universal PII only

    Example:
        har-capture validate device.har --patterns network-device
        har-capture validate --dir ./captures --recursive --patterns base
        har-capture validate device.har --strict --patterns network-device
    """
    from har_capture.validation import analyze_har_file, validate_har

    custom_patterns = require_patterns(patterns)

    har_files: list[Path] = []

    if directory:
        if not directory.exists():
            typer.echo(f"Error: Directory not found: {directory}", err=True)
            raise typer.Exit(1)

        if recursive:
            har_files.extend(directory.rglob("*.har"))
            har_files.extend(directory.rglob("*.har.gz"))
        else:
            har_files.extend(directory.glob("*.har"))
            har_files.extend(directory.glob("*.har.gz"))
    elif har_file:
        if not har_file.exists():
            typer.echo(f"Error: File not found: {har_file}", err=True)
            raise typer.Exit(1)
        har_files.append(har_file)
    else:
        typer.echo("Error: Provide either a HAR file or --dir option", err=True)
        raise typer.Exit(1)

    if not har_files:
        typer.echo("No HAR files found")
        raise typer.Exit(0)

    total_errors = 0
    total_warnings = 0

    # Completeness gaps are reported, never counted as findings: they say what
    # evidence the file lacks, not that it leaked something. Exit codes and
    # --strict stay driven by PII findings alone.
    #
    # Keyed on invocation mode, not file count: a --dir scan is a bulk/pre-commit
    # context and must render the same whether it matches one file or fifty.
    show_summary = directory is None

    for file_path in har_files:
        findings = validate_har(file_path, custom_patterns=custom_patterns)

        if findings:
            typer.echo(f"\n{file_path}:")
            for finding in findings:
                icon = "[ERROR]" if finding.severity == "error" else "[WARN]"
                typer.echo(f"  {icon} [{finding.location}]")
                typer.echo(f"     {finding.field}: {finding.value}")
                typer.echo(f"     Reason: {finding.reason}")

                if finding.severity == "error":
                    total_errors += 1
                else:
                    total_warnings += 1
        else:
            typer.echo(f"[OK] {file_path}: Clean")

        report = analyze_har_file(file_path)
        if show_summary or report.warnings:
            typer.echo()
            if not show_summary:
                typer.echo(f"{file_path}:")
            display_completeness(report, summary=show_summary)

    typer.echo(f"\nSummary: {total_errors} errors, {total_warnings} warnings")

    if total_errors > 0:
        raise typer.Exit(1)
    if strict and total_warnings > 0:
        raise typer.Exit(1)
