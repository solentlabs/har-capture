"""Shared CLI helper for resolving ``--patterns`` arguments.

The CLI requires ``--patterns`` to be specified for every command that
runs sanitization, so contributors capturing a HAR for downstream
consumers (e.g., cable_modem_monitor) cannot accidentally ship a HAR
sanitized only with universal PII rules. ``base`` is a reserved
sentinel meaning "core universal PII only, no domain extensions."
"""

from __future__ import annotations

from typing import Any

import typer

# Reserved CLI sentinel: explicit opt-in to core-universal-PII-only.
# Acts as a no-op in the resolved pattern list; its only purpose is to
# satisfy the "I have explicitly chosen" requirement so a user running
# generic web/API captures doesn't have to load a device domain.
_BASE_SENTINEL = "base"


def require_patterns(patterns: list[str] | None) -> str | dict[str, Any] | None:
    """Validate ``--patterns`` is present and resolve to library ``custom_patterns``.

    Args:
        patterns: Raw values from the ``--patterns`` typer option (repeatable).

    Returns:
        - ``None`` if the user passed only ``base`` (or equivalently,
          a list reduced to empty after stripping ``base``).
        - A path string for a single resolved domain or custom file.
        - A merged dict for multiple resolved sources.

    Raises:
        typer.Exit: If ``patterns`` is empty/``None``. Prints the
            available domains (plus ``base``) to stderr before exit.
    """
    if not patterns:
        _print_missing_patterns_error()
        raise typer.Exit(2)

    non_base = [p for p in patterns if p != _BASE_SENTINEL]
    if not non_base:
        return None

    from har_capture.patterns.loader import merge_pattern_files, resolve_patterns_arg

    resolved = [resolve_patterns_arg(p) for p in non_base]
    if len(resolved) == 1:
        return str(resolved[0])
    return merge_pattern_files(resolved)


def _print_missing_patterns_error() -> None:
    """Print a domain-listing error to stderr when ``--patterns`` is omitted."""
    from har_capture.patterns.loader import list_domains

    typer.echo("Error: --patterns is required. Choose one or more:", err=True)
    typer.echo("", err=True)
    typer.echo("  base            Universal PII only (no domain extensions)", err=True)
    for d in list_domains():
        name = d["name"].replace("_", "-")
        description = d.get("description") or ""
        typer.echo(f"  {name:<15s} {description}", err=True)
    typer.echo("  <path/to.json>  Custom pattern file", err=True)
    typer.echo("", err=True)
    typer.echo("Example: har-capture get https://router.local --patterns network-device", err=True)
