"""Main CLI entry point for har-capture.

Provides commands for:
- <TARGET>: Capture HTTP traffic (default command, same as 'get')
- get: Capture HTTP traffic (explicit alias)
- sanitize: Remove PII from HAR files
- validate: Check HAR files for PII leaks
"""

from __future__ import annotations

try:
    import click
    import typer
    from typer.core import TyperGroup
except ImportError as e:
    raise ImportError("CLI dependencies not installed. Install with: pip install har-capture[cli]") from e

from har_capture.cli.capture import capture
from har_capture.cli.patterns import patterns
from har_capture.cli.sanitize import sanitize
from har_capture.cli.validate import validate


class _DefaultGetGroup(TyperGroup):
    """Typer group that falls back to 'get' when the first arg isn't a known command.

    Allows ``har-capture http://192.168.1.1`` as shorthand for
    ``har-capture get http://192.168.1.1``.
    """

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            args.insert(0, "get")
            return super().resolve_command(ctx, args)


app = typer.Typer(
    name="har-capture",
    help="Capture and sanitize HAR files.",
    no_args_is_help=True,
    cls=_DefaultGetGroup,
)
app.command(name="get", help="Capture HTTP traffic from a URL")(capture)
app.command()(sanitize)
app.command()(validate)
app.command()(patterns)


def version_callback(value: bool) -> None:
    """Print version and exit.

    Args:
        value: True if --version flag was provided
    """
    if value:
        from har_capture import __version__

        typer.echo(f"har-capture {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    r"""Capture and sanitize HAR files.

    \b
    Examples:
        har-capture https://example.com
        har-capture http://192.168.1.1 --output capture.har
        har-capture sanitize myfile.har
        har-capture validate myfile.har
    """


if __name__ == "__main__":
    app()
