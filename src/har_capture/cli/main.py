"""Main CLI entry point for har-capture.

Provides commands for:
- [default]: Capture HTTP traffic (har-capture <TARGET>)
- get: Capture HTTP traffic (alias for default)
- sanitize: Remove PII from HAR files
- validate: Check HAR files for PII leaks
"""

from __future__ import annotations

try:
    import typer
except ImportError as e:
    raise ImportError("CLI dependencies not installed. Install with: pip install har-capture[cli]") from e

from har_capture.cli.capture import capture
from har_capture.cli.sanitize import sanitize
from har_capture.cli.validate import validate

app = typer.Typer(
    name="har-capture",
    help="Capture and sanitize HAR files.",
    no_args_is_help=True,
)

app.command(name="get", help="Capture HTTP traffic from a URL")(capture)
app.command()(sanitize)
app.command()(validate)


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
        har-capture get https://example.com
        har-capture get 192.168.1.1 --output capture.har
        har-capture sanitize myfile.har
        har-capture validate myfile.har
    """


if __name__ == "__main__":
    app()
