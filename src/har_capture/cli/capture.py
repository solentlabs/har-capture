"""Capture command for har-capture CLI - captures HTTP traffic to HAR files."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    from har_capture.capture.workflow import CaptureWorkflowResult


def capture(
    target: Annotated[
        str,
        typer.Argument(help="URL, hostname, or IP address to capture"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output HAR filename"),
    ] = None,
    browser: Annotated[
        str,
        typer.Option("--browser", "-b", help="Browser to use"),
    ] = "chromium",
    username: Annotated[
        str | None,
        typer.Option("--username", "-u", help="Username for HTTP Basic Auth"),
    ] = None,
    password: Annotated[
        str | None,
        typer.Option("--password", "-p", help="Password for HTTP Basic Auth"),
    ] = None,
    no_sanitize: Annotated[
        bool,
        typer.Option("--no-sanitize", help="Skip automatic sanitization"),
    ] = False,
    no_compress: Annotated[
        bool,
        typer.Option("--no-compress", help="Skip compression"),
    ] = False,
    keep_raw: Annotated[
        bool,
        typer.Option("--keep-raw", help="Keep the raw (unsanitized) HAR file"),
    ] = False,
    include_fonts: Annotated[
        bool,
        typer.Option("--include-fonts", help="Include font files in capture (.woff, .ttf, etc.)"),
    ] = False,
    include_images: Annotated[
        bool,
        typer.Option("--include-images", help="Include image files in capture (.png, .jpg, etc.)"),
    ] = False,
    include_media: Annotated[
        bool,
        typer.Option("--include-media", help="Include media files in capture (.mp3, .mp4, etc.)"),
    ] = False,
) -> None:
    """Capture HTTP traffic using Playwright browser.

    Opens a browser window where you can interact with a website or device.
    All HTTP traffic is recorded to a HAR file.

    By default, font/image/media files are filtered out to reduce HAR size.
    Use --include-fonts, --include-images, or --include-media to keep them.

    Args:
        target: URL, hostname, or IP address to capture
        output: Output HAR filename (auto-generated if not provided)
        browser: Browser engine to use (chromium, firefox, webkit)
        username: Username for HTTP Basic Auth if required
        password: Password for HTTP Basic Auth if required
        no_sanitize: Skip automatic PII sanitization
        no_compress: Skip HAR compression
        keep_raw: Keep the raw (unsanitized) HAR file
        include_fonts: Include font files in capture
        include_images: Include image files in capture
        include_media: Include media files in capture

    Example:
        har-capture get https://example.com
        har-capture get 192.168.100.1 --output capture.har
        har-capture get router.local --include-images
    """
    try:
        from har_capture.capture.deps import install_browser
        from har_capture.capture.workflow import (
            check_auth_phase,
            check_browser_phase,
            check_connectivity_phase,
            run_capture_phase,
        )
    except ImportError:
        typer.echo("Capture requires Playwright. Install with: pip install har-capture[capture]", err=True)
        raise typer.Exit(1) from None

    # Phase 1: Check browser installation
    result = check_browser_phase(browser)
    if result.needs_browser_install:
        typer.echo()
        typer.echo(f"Browser '{browser}' is not installed.")
        typer.echo()
        if typer.confirm(f"Download and install {browser}? (~150MB, one-time)", default=True):
            typer.echo(f"Installing {browser}...")
            if not install_browser(browser):
                typer.echo(
                    f"Failed to install {browser}. Try manually: playwright install {browser}", err=True
                )
                raise typer.Exit(1)
            typer.echo(f"  ✓ {browser.capitalize()} installed successfully!")
            typer.echo()
        else:
            typer.echo(f"Run manually: playwright install {browser}")
            raise typer.Exit(1)

    # Display header
    _display_header(target, browser, output)

    # Phase 2: Check connectivity
    typer.echo("Checking connectivity...")
    result = check_connectivity_phase(target, result)
    if not result.connectivity_ok:
        typer.echo(f"  ERROR: {result.connectivity_error}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  Connected:  {result.target_url}")

    # Phase 3: Check authentication
    typer.echo()
    typer.echo("Checking authentication type...")
    result = check_auth_phase(result.target_url, result)

    http_credentials = _handle_auth(result, username, password)

    # Display instructions
    _display_instructions()

    # Phase 4: Run capture
    result = run_capture_phase(
        target=target,
        output=output,
        browser=browser,
        http_credentials=http_credentials,
        sanitize=not no_sanitize,
        compress=not no_compress,
        keep_raw=keep_raw,
        include_fonts=include_fonts,
        include_images=include_images,
        include_media=include_media,
        result=result,
    )

    if not result.capture_success:
        typer.echo(f"Capture failed: {result.capture_error}", err=True)
        raise typer.Exit(1)

    # Display results
    _display_results(result)


def _display_header(target: str, browser: str, output: Path | None) -> None:
    """Display capture header."""
    typer.echo("=" * 60)
    typer.echo("HAR CAPTURE")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"  Target:     {target}")
    typer.echo(f"  Browser:    {browser}")
    if output:
        typer.echo(f"  Output:     {output}")
    typer.echo()


def _handle_auth(
    result: CaptureWorkflowResult,
    username: str | None,
    password: str | None,
) -> dict[str, str] | None:
    """Handle authentication based on workflow result."""
    if result.requires_basic_auth:
        realm_msg = f" ({result.auth_realm})" if result.auth_realm else ""
        typer.echo(f"  Detected: HTTP Basic Auth{realm_msg}")
        if username is not None and password is not None:
            return {"username": username, "password": password}
        typer.echo()
        if result.auth_realm:
            typer.echo(f"This site ({result.auth_realm}) requires HTTP Basic Authentication.")
        else:
            typer.echo("This site requires HTTP Basic Authentication.")
        typer.echo()
        prompted_user = typer.prompt("Username", default="admin")
        prompted_pass = typer.prompt("Password", hide_input=True)
        return {"username": prompted_user, "password": prompted_pass or ""}
    typer.echo("  Detected: Form-based or no auth required")
    return None


def _display_instructions() -> None:
    """Display capture instructions."""
    typer.echo()
    typer.echo("Instructions:")
    typer.echo("  1. Interact with the site when the browser opens")
    typer.echo("  2. Visit all pages you want to capture")
    typer.echo("  3. IMPORTANT: Wait 3-5 seconds on each page for data to load!")
    typer.echo("  4. Close the browser window when done")
    typer.echo()


def _display_results(result: CaptureWorkflowResult) -> None:
    """Display capture results."""
    typer.echo()
    typer.echo("=" * 60)
    typer.echo("CAPTURE COMPLETE")
    typer.echo("=" * 60)
    typer.echo()
    if result.har_path:
        typer.echo(f"  Raw HAR: {result.har_path}")
    if result.compressed_path:
        typer.echo(f"  Compressed: {result.compressed_path}")
    if result.sanitized_path:
        typer.echo(f"  Sanitized: {result.sanitized_path}")
    if result.stats:
        removed = result.stats.get("removed_entries", 0)
        orig = result.stats.get("original_entries", 0)
        filt = result.stats.get("filtered_entries", 0)
        typer.echo(f"  Removed {removed} bloat entries ({orig} -> {filt})")
    typer.echo()

    # Show next steps
    main_file = result.sanitized_path or result.compressed_path or result.har_path
    typer.echo("Next steps:")
    if result.sanitized_path:
        typer.echo(f"  • Share the sanitized file (PII removed): {result.sanitized_path}")
    else:
        typer.echo(f"  • Sanitize before sharing: har-capture sanitize {main_file}")
    typer.echo(f"  • Validate for secrets:    har-capture validate {main_file}")
    typer.echo()
