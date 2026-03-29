"""Patterns command for har-capture CLI."""

from __future__ import annotations

from typing import Annotated

import typer


def patterns(
    show: Annotated[
        str | None,
        typer.Option("--show", help="Show details of a specific pattern domain"),
    ] = None,
) -> None:
    """List available built-in pattern domains.

    Pattern domains provide domain-specific safe-value patterns for
    reducing false positives during sanitization.

    Use with --patterns on other commands:

        har-capture get 192.168.100.1 --patterns network-device

        har-capture sanitize file.har --patterns network-device
    """
    from har_capture.patterns.loader import list_domains, load_json_file, resolve_patterns_arg

    if show:
        try:
            path = resolve_patterns_arg(show)
        except Exception as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(1) from None

        data = load_json_file(path)
        typer.echo(f"Pattern: {show}")
        typer.echo(f"File:    {path}")
        if "_description" in data:
            typer.echo(f"         {data['_description']}")
        typer.echo()

        # Show heuristic safe value patterns
        heuristics = data.get("heuristics", {})
        safe_patterns = heuristics.get("safe_value_patterns", [])
        if safe_patterns:
            typer.echo(f"  Safe value patterns ({len(safe_patterns)}):")
            for p in safe_patterns:
                comment = p.get("_comment", p.get("regex", ""))
                typer.echo(f"    - {comment}")

        # Show tagValueList safe values
        tag_values = data.get("tagValueList", {}).get("safe_values", [])
        if tag_values:
            typer.echo(f"  Tag safe values ({len(tag_values)}):")
            typer.echo(f"    {', '.join(tag_values)}")

        return

    domains = list_domains()
    if not domains:
        typer.echo("No built-in pattern domains found.")
        return

    typer.echo("Available pattern domains:")
    typer.echo()
    for d in domains:
        typer.echo(f"  {d['name']:<20} {d['description']}")
    typer.echo()
    typer.echo("Usage: har-capture get <url> --patterns <name>")
    typer.echo("       har-capture sanitize <file> --patterns <name>")
    typer.echo()
    typer.echo("Show details: har-capture patterns --show <name>")
