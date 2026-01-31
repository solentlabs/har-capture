"""Browser-based HAR capture using Playwright.

This module provides the core HAR capture functionality using Playwright.
Requires the 'capture' optional dependency: pip install har-capture[capture]
"""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from har_capture.capture.connectivity import _parse_target, check_device_connectivity
from har_capture.capture.deps import check_playwright, install_browser_deps
from har_capture.patterns import get_bloat_extensions

_LOGGER = logging.getLogger(__name__)

# Known error patterns that indicate missing browser dependencies
# Playwright raises generic exceptions with these messages on Linux
_MISSING_DEPS_PATTERNS = (
    "missing dependencies",
    "libasound",
    "libnss3",
    "libnspr4",
    "host system is missing dependencies",
)


def _sanitize_error_message(error: str, credentials: dict[str, str] | None) -> str:
    """Remove credentials from error messages to prevent leakage.

    Args:
        error: Error message that may contain credentials
        credentials: Dict with 'username' and 'password' keys

    Returns:
        Sanitized error message with credentials replaced
    """
    if not credentials:
        return error

    result = error
    if credentials.get("username"):
        result = result.replace(credentials["username"], "[USERNAME]")
    if credentials.get("password"):
        result = result.replace(credentials["password"], "[PASSWORD]")
    return result


@dataclass
class CaptureResult:
    """Result of a HAR capture operation.

    Attributes:
        har_path: Path to the raw HAR file (None if deleted after sanitization)
        compressed_path: Path to compressed .har.gz file if created
        sanitized_path: Path to sanitized HAR file if created
        stats: Dict with capture statistics (entry counts, sizes)
        success: True if capture succeeded
        error: Error message if capture failed
    """

    har_path: Path | None = None
    compressed_path: Path | None = None
    sanitized_path: Path | None = None
    stats: dict[str, Any] | None = None
    success: bool = True
    error: str | None = None


@dataclass
class CaptureOptions:
    """Options for HAR capture filtering.

    Attributes:
        include_fonts: If True, don't filter font files (.woff, .ttf, etc.)
        include_images: If True, don't filter image files (.png, .jpg, etc.)
        include_media: If True, don't filter media files (.mp3, .mp4, etc.)
    """

    include_fonts: bool = False
    include_images: bool = False
    include_media: bool = False

    def get_bloat_extensions(self) -> set[str]:
        """Get the set of extensions to filter based on options."""
        return get_bloat_extensions(
            include_fonts=self.include_fonts,
            include_images=self.include_images,
            include_media=self.include_media,
        )


def _add_capture_metadata(har: dict[str, Any], tool_name: str = "har-capture") -> None:
    """Add capture metadata to HAR file.

    Adds a _har_capture section to the HAR log with tool info and settings.

    Args:
        har: HAR data dict to modify in-place
        tool_name: Name of the capture tool to record
    """
    har["log"]["_har_capture"] = {
        "tool": tool_name,
        "captured_at": datetime.now().isoformat(),
        "cache_disabled": True,
        "service_workers_blocked": True,
    }


def filter_and_compress_har(
    har_path: Path,
    options: CaptureOptions | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Filter out bloat from HAR and compress it.

    Args:
        har_path: Path to HAR file
        options: Capture options controlling what to filter

    Returns:
        Tuple of (compressed_path, stats_dict)
    """
    if options is None:
        options = CaptureOptions()

    bloat_extensions = options.get_bloat_extensions()

    with open(har_path, encoding="utf-8") as f:
        har = json.load(f)

    # Add metadata
    _add_capture_metadata(har)

    original_count = len(har["log"]["entries"])
    original_size = har_path.stat().st_size

    # Filter entries
    seen_requests: set[tuple[str, str]] = set()
    filtered_entries = []

    for entry in har["log"]["entries"]:
        request = entry.get("request", {})
        method = request.get("method", "GET")
        url = request.get("url", "")

        # Skip bloat file types
        url_lower = url.lower().split("?")[0]  # Remove query params for extension check
        if any(url_lower.endswith(ext) for ext in bloat_extensions):
            continue

        # Skip duplicates (keep first occurrence of each method+url combination)
        # This preserves both GET and POST to the same URL (e.g., login form + submit)
        request_key = (method, url)
        if request_key in seen_requests:
            continue
        seen_requests.add(request_key)

        filtered_entries.append(entry)

    har["log"]["entries"] = filtered_entries
    filtered_count = len(filtered_entries)

    # Write filtered HAR (pretty-printed for readability)
    with open(har_path, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2)

    filtered_size = har_path.stat().st_size

    # Compress
    compressed_path = har_path.with_suffix(".har.gz")
    with (
        open(har_path, "rb") as f_in,
        gzip.open(compressed_path, "wb", compresslevel=9) as f_out,
    ):
        f_out.write(f_in.read())

    compressed_size = compressed_path.stat().st_size

    return compressed_path, {
        "original_entries": original_count,
        "filtered_entries": filtered_count,
        "removed_entries": original_count - filtered_count,
        "original_size": original_size,
        "filtered_size": filtered_size,
        "compressed_size": compressed_size,
    }


def capture_device_har(
    ip: str,
    output: str | Path | None = None,
    browser: str = "chromium",
    http_credentials: dict[str, str] | None = None,
    sanitize: bool = True,
    compress: bool = True,
    keep_raw: bool = False,
    include_fonts: bool = False,
    include_images: bool = False,
    include_media: bool = False,
    headless: bool = False,
    timeout: int | None = None,
) -> CaptureResult:
    """Capture HTTP traffic using Playwright browser.

    This function launches a browser window and records all network traffic
    while the user interacts with the target. The user logs in manually -
    the browser handles authentication regardless of the method used.

    Args:
        ip: Target URL, hostname, or IP address (e.g., "example.com", "10.0.0.1")
        output: Output HAR filename (default: capture_<timestamp>.har)
        browser: Browser to use ("chromium", "firefox", "webkit")
        http_credentials: Optional dict with "username" and "password" for HTTP Basic Auth
        sanitize: Whether to sanitize the HAR after capture
        compress: Whether to compress the HAR after capture
        keep_raw: If True, keep the raw (unsanitized) HAR file
        include_fonts: If True, don't filter font files (.woff, .ttf, etc.)
        include_images: If True, don't filter image files (.png, .jpg, etc.)
        include_media: If True, don't filter media files (.mp3, .mp4, etc.)
        headless: If True, run browser in headless mode (for automated capture)
        timeout: Seconds to wait before closing browser (None = wait for user to close)

    Returns:
        CaptureResult with paths to generated files

    Raises:
        ImportError: If Playwright is not installed

    Example:
        >>> result = capture_device_har("router.local")
        >>> print(result.har_path)

        # Automated capture (headless with timeout)
        >>> result = capture_device_har("example.com", headless=True, timeout=10)
    """
    capture_options = CaptureOptions(
        include_fonts=include_fonts,
        include_images=include_images,
        include_media=include_media,
    )

    # Check Playwright
    if not check_playwright():
        return CaptureResult(
            har_path=Path(),
            success=False,
            error="Playwright not installed. Run: pip install har-capture[capture]",
        )

    from playwright.sync_api import sync_playwright

    # Determine output path
    if output is None:
        captures_dir = Path.cwd() / "captures"
        captures_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = captures_dir / f"capture_{timestamp}.har"
    else:
        output_path = Path(output)

    # Ensure .har extension
    if output_path.suffix != ".har":
        output_path = output_path.with_suffix(".har")

    # Parse target to extract hostname (handles URLs like "https://example.com")
    host, _ = _parse_target(ip)

    # Check connectivity and determine scheme
    reachable, scheme, error = check_device_connectivity(ip)
    if not reachable:
        return CaptureResult(
            har_path=output_path,
            success=False,
            error=error or f"Cannot connect to {host}",
        )

    target_url = f"{scheme}://{host}/"

    def launch_browser_and_capture() -> bool:
        """Launch browser and capture HAR. Returns True on success."""
        with sync_playwright() as p:
            # Select browser
            if browser == "firefox":
                browser_type = p.firefox
            elif browser == "webkit":
                browser_type = p.webkit
            else:
                browser_type = p.chromium

            # Launch browser with HAR recording
            browser_instance = browser_type.launch(headless=headless)

            # Build context options
            context_options: dict[str, Any] = {
                "record_har_path": str(output_path),
                "record_har_content": "embed",  # Embed response bodies in HAR
                "ignore_https_errors": True,  # Devices often have self-signed certs
                "service_workers": "block",  # Disable service workers to prevent caching
            }

            # Add HTTP Basic Auth credentials if needed
            if http_credentials:
                context_options["http_credentials"] = http_credentials

            context = browser_instance.new_context(**context_options)

            # Enable route interception to disable HTTP cache
            context.route("**/*", lambda route: route.continue_())

            # Create page and navigate to device
            page = context.new_page()
            page.goto(target_url, wait_until="networkidle")

            if timeout is not None:
                # Automated mode: wait for timeout then close
                import time

                time.sleep(timeout)
            else:
                # Interactive mode: wait for user to close browser
                _LOGGER.info("Browser opened. Interact with your device, then close the browser.")
                with contextlib.suppress(Exception):
                    page.wait_for_event("close", timeout=0)

            # Close context to save HAR
            context.close()
            browser_instance.close()
        return True

    def _is_missing_deps_error(error_msg: str) -> bool:
        """Check if error indicates missing browser dependencies."""
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in _MISSING_DEPS_PATTERNS)

    try:
        launch_browser_and_capture()
    except Exception as e:
        error_str = _sanitize_error_message(str(e), http_credentials)
        if _is_missing_deps_error(error_str):
            _LOGGER.warning("Browser dependencies missing. Installing...")
            if install_browser_deps():
                _LOGGER.info("Dependencies installed. Retrying...")
                try:
                    launch_browser_and_capture()
                except Exception as e2:
                    return CaptureResult(
                        har_path=output_path,
                        success=False,
                        error=_sanitize_error_message(str(e2), http_credentials),
                    )
            else:
                return CaptureResult(
                    har_path=output_path,
                    success=False,
                    error="Failed to install browser dependencies",
                )
        else:
            return CaptureResult(
                har_path=output_path,
                success=False,
                error=error_str,
            )

    result = CaptureResult(har_path=output_path)

    # Sanitize first (must happen before compression)
    if sanitize:
        try:
            from har_capture.sanitization import sanitize_har_file

            sanitized_path = sanitize_har_file(str(output_path))
            result.sanitized_path = Path(sanitized_path)
        except Exception as e:
            _LOGGER.warning("Sanitization failed: %s", e)

    # Compress the sanitized file (never compress unsanitized)
    if compress and result.sanitized_path and result.sanitized_path.exists():
        try:
            compressed_path, stats = filter_and_compress_har(result.sanitized_path, capture_options)
            result.compressed_path = compressed_path
            result.stats = stats

            # Delete uncompressed sanitized file
            if not keep_raw:
                try:
                    result.sanitized_path.unlink()
                    result.sanitized_path = None
                except Exception as e:
                    _LOGGER.warning("Failed to delete uncompressed sanitized HAR: %s", e)
        except Exception as e:
            _LOGGER.warning("Compression failed: %s", e)

    # Delete raw file unless keep_raw is set
    if not keep_raw and (result.sanitized_path or result.compressed_path):
        try:
            output_path.unlink()
            result.har_path = None
        except Exception as e:
            _LOGGER.warning("Failed to delete raw HAR: %s", e)

    return result
