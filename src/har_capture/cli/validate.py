"""Validate command for har-capture CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer


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
        Path | None,
        typer.Option("--patterns", "-p", help="Custom patterns JSON file"),
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
        patterns: Custom patterns JSON file to merge with defaults

    Example:
        har-capture validate device.har
        har-capture validate --dir ./captures --recursive
        har-capture validate device.har --strict
        har-capture validate device.har --patterns custom.json
    """
    from har_capture.validation import validate_har

    har_files: list[Path] = []
    custom_patterns = str(patterns) if patterns else None

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

    typer.echo(f"\nSummary: {total_errors} errors, {total_warnings} warnings")

    if total_errors > 0:
        raise typer.Exit(1)
    if strict and total_warnings > 0:
        raise typer.Exit(1)
