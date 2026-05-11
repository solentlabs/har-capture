"""Capture command for har-capture CLI - captures HTTP traffic to HAR files."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    from har_capture.capture.workflow import CaptureWorkflowResult


from har_capture.cli._patterns_resolver import require_patterns


def capture(
    target: Annotated[
        str,
        typer.Argument(
            help="URL or bare hostname/IP to capture. Scheme auto-detected when omitted.",
        ),
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
    patterns: Annotated[
        list[str] | None,
        typer.Option(
            "--patterns",
            help="Required. Pattern domain (e.g. 'network-device'), 'base' for universal PII only, or JSON path. Repeatable.",
        ),
    ] = None,
    wait_for_data: Annotated[
        bool,
        typer.Option(
            "--wait-for-data/--no-wait-for-data",
            help="Wait for async data to load on each page before navigating",
        ),
    ] = True,
    minimal: Annotated[
        bool,
        typer.Option(
            "--minimal",
            help="Minimal pre-flight for single-session devices "
            "(skips probes, auth check, uses domcontentloaded)",
        ),
    ] = False,
) -> None:
    """Capture HTTP traffic using Playwright browser.

    Opens a browser window where you can interact with a website or device.
    All HTTP traffic is recorded to a HAR file.

    By default, font/image/media files are filtered out to reduce HAR size.
    Use --include-fonts, --include-images, or --include-media to keep them.

    Args:
        target: URL or bare hostname/IP to capture (scheme auto-detected via TCP/TLS probes when omitted)
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
        patterns: Pattern names or JSON file paths (repeatable)
        wait_for_data: Wait for async data to load on each page
        minimal: Minimal pre-flight for single-session devices

    Example:
        har-capture https://example.com
        har-capture 192.168.100.1                # auto-detect HTTP vs HTTPS
        har-capture http://192.168.100.1 --output capture.har
        har-capture get http://router.local --include-images
    """
    # Validate --patterns up front so a user running `har-capture get URL`
    # without choosing a domain gets the listing error before we trigger
    # the browser install prompt.
    custom_patterns = require_patterns(patterns)

    try:
        from har_capture.capture.deps import install_browser
        from har_capture.capture.workflow import (
            check_browser_phase,
            check_connectivity_phase,
            check_session_phase,
            run_capture_phase,
            run_probes_phase,
        )
    except ImportError:
        typer.echo("Capture requires Playwright. Install with: pip install har-capture[capture]", err=True)
        raise typer.Exit(1) from None

    # Resolve minimal mode overrides
    if minimal:
        wait_for_data = False

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
                    f"Failed to install {browser}. Try manually: python -m playwright install {browser}",
                    err=True,
                )
                raise typer.Exit(1)
            typer.echo(f"  ✓ {browser.capitalize()} installed successfully!")
            typer.echo()
        else:
            typer.echo(f"Run manually: python -m playwright install {browser}")
            raise typer.Exit(1)

    # Display header
    _display_header(target, browser, output)

    # Phase 2: Check connectivity (skipped in minimal mode)
    if not minimal:
        typer.echo("Checking connectivity...")
        result = check_connectivity_phase(target, result)
        if not result.connectivity_ok:
            typer.echo(f"  ERROR: {result.connectivity_error}", err=True)
            raise typer.Exit(1)
        typer.echo(f"  Connected:  {result.target_url}")

        # Phase 3: Session contamination check
        result = check_session_phase(result.target_url, result)
        if result.session_contaminated:
            typer.echo(f"  ERROR: {result.session_message}", err=True)
            raise typer.Exit(1)

    # Credentials handling: if user provides --username/--password, we set
    # http_credentials on the Playwright context (handles Basic Auth automatically).
    # When http_credentials is set, Playwright suppresses the 401 response in the
    # HAR, so we auto-run the auth probe to capture that data (see ADR-3).
    has_credentials = username is not None and password is not None
    http_credentials: dict[str, str] | None = None

    if has_credentials:
        # has_credentials guarantees both are str (not None)
        http_credentials = {"username": str(username), "password": str(password)}
        # Auto-run auth probe to capture the 401 that http_credentials will suppress
        if not minimal:
            typer.echo()
            typer.echo("Running auth probe (credentials provided)...")
            result = run_probes_phase(result.target_url, result=result)
            if result.probe_data:
                auth_probe = result.probe_data.get("auth_challenge", {})
                auth_status = auth_probe.get("status_code", "?")
                typer.echo(f"  Auth status: {auth_status}")

    # Display instructions
    _display_instructions()

    # Phase 3: Run capture — pass pre-computed target_url to avoid duplicate connectivity check
    page_load_strategy = "domcontentloaded" if minimal else "networkidle"
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
        interactive=True,
        result=result,
        custom_patterns=custom_patterns,
        wait_for_data=wait_for_data,
        target_url=result.target_url if result.connectivity else None,
        page_load_strategy=page_load_strategy,
    )

    if not result.capture_success:
        typer.echo(f"Capture failed: {result.capture_error}", err=True)
        raise typer.Exit(1)

    # Display results
    _display_results(result)

    # Interactive review of flagged values (always enabled)
    if result.capture and result.capture.sanitization_report:
        _run_interactive_review(result)


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
    main_file = result.compressed_path or result.sanitized_path or result.har_path

    # Check if file is already sanitized (either sanitized_path set or compressed path contains .sanitized)
    is_sanitized = result.sanitized_path or (
        result.compressed_path and ".sanitized" in str(result.compressed_path)
    )

    typer.echo("Next steps:")
    if is_sanitized:
        typer.echo(f"  • Share the file (PII removed): {main_file}")
    else:
        typer.echo(f"  • Sanitize before sharing: har-capture sanitize {main_file}")
    typer.echo(f"  • Validate for secrets:    har-capture validate {main_file}")
    typer.echo()

    if is_sanitized:
        typer.echo("WARNING: Automated sanitization is best-effort.")
        typer.echo("Before sharing, review the .har file for any remaining sensitive data.")
        typer.echo()


def _run_interactive_review(result: CaptureWorkflowResult) -> None:
    """Run interactive review of flagged values after capture."""
    # Type narrowing: ensure we have capture data
    if not result.capture:
        typer.echo("Error: No capture data available for interactive review", err=True)
        return

    report = result.capture.sanitization_report
    sanitized_path = result.capture.sanitized_path
    raw_path = result.capture.har_path

    # Ensure we have required data for interactive review
    if not report or not sanitized_path:
        typer.echo("Error: Missing sanitization data for interactive review", err=True)
        return

    if not report.flagged:
        typer.echo("No suspicious values found. All values were handled automatically.")
        return

    from har_capture.cli.interactive import display_summary, run_interactive_review

    # Determine salt mode for display
    salt_mode = "random (correlation within file)" if report.salt else "static placeholders"

    # Use raw_path as input if available, otherwise use sanitized_path
    # (raw_path is None when keep_raw=False, which is the default)
    input_display = str(raw_path) if raw_path else str(sanitized_path)

    review_completed = run_interactive_review(
        report,
        input_path=input_display,
        output_path=str(sanitized_path),
        salt_mode=salt_mode,
    )

    if review_completed and report.total_user_redacted > 0:
        from har_capture.cli.interactive import apply_reviewed_redactions

        apply_reviewed_redactions(report, sanitized_path)

    # Display summary
    display_summary(report)
