"""Capture command for har-capture CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer


def capture(
    ip: Annotated[
        str,
        typer.Argument(help="Device IP address or hostname"),
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
    """Capture device traffic using Playwright browser.

    Opens a browser window where you can interact with your device.
    Network traffic is recorded to a HAR file.

    By default, font/image/media files are filtered out to reduce HAR size.
    Use --include-fonts, --include-images, or --include-media to keep them.

    Args:
        ip: Device IP address to capture traffic from
        output: Output HAR filename (auto-generated if not provided)
        browser: Browser engine to use (chromium, firefox, webkit)
        username: Username for HTTP Basic Auth if required
        password: Password for HTTP Basic Auth if required
        no_sanitize: Skip automatic PII sanitization
        no_compress: Skip HAR compression
        include_fonts: Include font files in capture
        include_images: Include image files in capture
        include_media: Include media files in capture

    Example:
        har-capture capture router.local
        har-capture capture 10.0.0.1 --output device.har
        har-capture capture mydevice.local --include-images
    """
    try:
        from har_capture.capture import capture_device_har, check_basic_auth, check_device_connectivity
        from har_capture.capture.deps import check_browser_installed, install_browser
    except ImportError:
        typer.echo("Capture requires Playwright. Install with: pip install har-capture[capture]", err=True)
        raise typer.Exit(1) from None

    # Check if browser is installed
    if not check_browser_installed(browser):
        typer.echo()
        typer.echo(f"Browser '{browser}' is not installed.")
        typer.echo()
        install = typer.confirm(f"Download and install {browser}? (~150MB, one-time)", default=True)
        if install:
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

    typer.echo("=" * 60)
    typer.echo("DEVICE TRAFFIC CAPTURE")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"  Device IP:  {ip}")
    typer.echo(f"  Browser:    {browser}")
    if output:
        typer.echo(f"  Output:     {output}")
    typer.echo()

    # Check connectivity
    typer.echo("Checking device connectivity...")
    reachable, scheme, error = check_device_connectivity(ip)

    if not reachable:
        typer.echo(f"  ERROR: {error}", err=True)
        raise typer.Exit(1)

    device_url = f"{scheme}://{ip}/"
    typer.echo(f"  Connected:  {device_url}")

    # Check for Basic Auth
    http_credentials = None
    typer.echo()
    typer.echo("Checking authentication type...")
    requires_basic, realm = check_basic_auth(device_url)

    if requires_basic:
        typer.echo(f"  Detected: HTTP Basic Auth{f' ({realm})' if realm else ''}")
        if username and password:
            http_credentials = {"username": username, "password": password}
        else:
            typer.echo()
            if realm:
                typer.echo(f"This device ({realm}) requires HTTP Basic Authentication.")
            else:
                typer.echo("This device requires HTTP Basic Authentication.")
            typer.echo()
            username = typer.prompt("Username", default="admin")
            password = typer.prompt("Password", hide_input=True)
            http_credentials = {"username": username, "password": password}
    else:
        typer.echo("  Detected: Form-based or no auth required")

    typer.echo()
    typer.echo("Instructions:")
    typer.echo("  1. Log into your device when the browser opens")
    typer.echo("  2. Visit ALL pages to capture complete API data")
    typer.echo("  3. IMPORTANT: Wait 3-5 seconds on each page for data to load!")
    typer.echo("  4. Close the browser window when done")
    typer.echo()

    result = capture_device_har(
        ip=ip,
        output=output,
        browser=browser,
        http_credentials=http_credentials,
        sanitize=not no_sanitize,
        compress=not no_compress,
        include_fonts=include_fonts,
        include_images=include_images,
        include_media=include_media,
    )

    if not result.success:
        typer.echo(f"Capture failed: {result.error}", err=True)
        raise typer.Exit(1)

    typer.echo()
    typer.echo("=" * 60)
    typer.echo("CAPTURE COMPLETE")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"  Raw HAR: {result.har_path}")
    if result.compressed_path:
        typer.echo(f"  Compressed: {result.compressed_path}")
    if result.sanitized_path:
        typer.echo(f"  Sanitized: {result.sanitized_path}")
    if result.stats:
        removed = result.stats["removed_entries"]
        orig = result.stats["original_entries"]
        filt = result.stats["filtered_entries"]
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
