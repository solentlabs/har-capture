"""Browser-based HAR capture using Playwright.

This module provides the core HAR capture functionality using Playwright.
Requires the 'capture' optional dependency: pip install har-capture[capture]
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from har_capture import __version__
from har_capture.capture.connectivity import _parse_target, check_device_connectivity
from har_capture.capture.deps import (
    check_browser_installed,
    check_playwright,
    install_browser,
    install_browser_deps,
)
from har_capture.patterns import get_bloat_extensions
from har_capture.sanitization.report import HeuristicMode

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

# Error patterns indicating the browser executable is missing or corrupted
# Distinct from _MISSING_DEPS_PATTERNS: fix is reinstalling the browser, not apt-get
_MISSING_BROWSER_PATTERNS = (
    "executable doesn't exist",
    "executable does not exist",
)

# ---------------------------------------------------------------------------
# Wait-for-data: ensure async JS data fetches complete before navigation
# ---------------------------------------------------------------------------

# Seconds of network silence required before considering data loaded
_DATA_WAIT_QUIESCENCE_S = 2.0
# Maximum seconds to wait for data per page
_DATA_WAIT_TIMEOUT_S = 30.0
# Maximum seconds to wait for pending requests in the navigation route handler
_DATA_WAIT_NAV_TIMEOUT_S = 15.0
# Poll interval in milliseconds (used with page.wait_for_timeout)
_DATA_WAIT_POLL_MS = 200

# Injected into every page when wait_for_data is enabled.
# Monkey-patches XMLHttpRequest.send and fetch() to track in-flight requests.
# Exposes window.__harCapturePendingRequests for Playwright to query.
_WAIT_FOR_DATA_INIT_SCRIPT = """\
(function () {
  var __hcPending = 0;
  var _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function () {
    __hcPending++;
    this.addEventListener("loadend", function () {
      __hcPending = Math.max(0, __hcPending - 1);
    });
    return _xhrSend.apply(this, arguments);
  };
  if (window.fetch) {
    var _fetch = window.fetch;
    window.fetch = function () {
      __hcPending++;
      return _fetch.apply(this, arguments)["finally"](function () {
        __hcPending = Math.max(0, __hcPending - 1);
      });
    };
  }
  Object.defineProperty(window, "__harCapturePendingRequests", {
    get: function () { return __hcPending; },
    configurable: true
  });
})();
"""


def _wait_for_pending_data(page: Any, timeout_s: float = _DATA_WAIT_NAV_TIMEOUT_S) -> None:
    """Wait until in-flight JS requests (XHR/fetch) reach zero.

    Used inside the navigation route handler to delay page transitions
    until the current page's async data fetches have completed.

    Args:
        page: Playwright Page object (must have the init script injected).
        timeout_s: Maximum seconds to wait.
    """
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        try:
            pending = page.evaluate("window.__harCapturePendingRequests || 0")
        except Exception:
            return  # Page closed or JS context gone
        if pending <= 0:
            return
        page.wait_for_timeout(_DATA_WAIT_POLL_MS)
    _LOGGER.debug("Pending-data wait timed out after %.1fs", timeout_s)


def _wait_for_network_quiescence(
    page: Any,
    quiescence_s: float = _DATA_WAIT_QUIESCENCE_S,
    timeout_s: float = _DATA_WAIT_TIMEOUT_S,
) -> None:
    """Wait until no JS-initiated network requests for *quiescence_s* seconds.

    Polls ``window.__harCapturePendingRequests`` (set by the init script).
    More robust than Playwright's built-in ``networkidle`` which only requires
    500 ms of silence — too short for SPAs that fire XHR after a brief JS
    initialisation delay.

    Args:
        page: Playwright Page object (must have the init script injected).
        quiescence_s: Seconds of zero in-flight requests before returning.
        timeout_s: Maximum seconds to wait overall.
    """
    start = time.monotonic()
    last_active = start

    while time.monotonic() - start < timeout_s:
        try:
            pending = page.evaluate("window.__harCapturePendingRequests || 0")
        except Exception:
            return  # Page closed or JS context gone

        now = time.monotonic()
        if pending > 0:
            last_active = now
        elif now - last_active >= quiescence_s:
            _LOGGER.debug("Network quiescent for %.1fs — proceeding", quiescence_s)
            return

        page.wait_for_timeout(_DATA_WAIT_POLL_MS)

    _LOGGER.debug("Network quiescence timed out after %.1fs", timeout_s)


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
        sanitization_report: Report from sanitization (for interactive review)
    """

    har_path: Path | None = None
    compressed_path: Path | None = None
    sanitized_path: Path | None = None
    stats: dict[str, Any] | None = None
    sanitization_report: Any | None = None  # SanitizationReport when available
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
    metadata = har["log"].get("_har_capture", {})
    metadata.update(
        {
            "tool": tool_name,
            "version": __version__,
            "captured_at": datetime.now(tz=timezone.utc).isoformat(),
            "cache_disabled": True,
            "service_workers_blocked": True,
        }
    )
    har["log"]["_har_capture"] = metadata


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
    seen_requests: set[tuple[str, ...]] = set()
    filtered_entries = []

    for entry in har["log"]["entries"]:
        request = entry.get("request", {})
        method = request.get("method", "GET")
        url = request.get("url", "")

        # Skip bloat file types
        url_lower = url.lower().split("?")[0]  # Remove query params for extension check
        if any(url_lower.endswith(ext) for ext in bloat_extensions):
            continue

        # Skip duplicates (keep first occurrence of each unique request)
        # For POST/PUT/PATCH, include a body hash so requests to the same URL
        # with different bodies are preserved (e.g., devices that use a single
        # POST endpoint differentiated only by body parameters).
        # Identical retries still dedup correctly.
        if method in {"POST", "PUT", "PATCH"}:
            body_text = request.get("postData", {}).get("text", "")
            body_hash = hashlib.sha256(body_text.encode()).hexdigest()
            request_key: tuple[str, ...] = (method, url, body_hash)
        else:
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
    interactive: bool = True,
    probes: dict[str, Any] | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    wait_for_data: bool = True,
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
        interactive: If True, flag suspicious values for interactive review
        probes: Pre-capture diagnostic probe results to include in output
        custom_patterns: Domain pattern name, file path, or pre-loaded dict
            for domain-specific sanitization rules.
        wait_for_data: If True, wait for async data fetches (XHR/fetch) to
            complete before navigating away from each page.  Prevents losing
            SPA data (e.g. HNAP/SOAP responses) that loads after the initial
            HTML/JS.  Default True; pass False for legacy fast-navigation.

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

    # Check browser installed - auto-install if missing
    if not check_browser_installed(browser):
        _LOGGER.info("Browser %s not installed. Installing...", browser)
        if not install_browser(browser):
            return CaptureResult(
                har_path=Path(),
                success=False,
                error=f"Failed to install {browser}. Run: python -m playwright install {browser}",
            )
        _LOGGER.info("Browser %s installed successfully.", browser)

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

    # Create parent directories if they don't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

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

    # Create temp file for raw HAR (contains PII, never stored in user's directory)
    temp_fd, temp_path_str = tempfile.mkstemp(suffix=".har", prefix="har_capture_")
    temp_path = Path(temp_path_str)
    # Close the file descriptor - Playwright will write to it by path
    os.close(temp_fd)

    browser_cookies: list[Any] = []
    web_storage_local: list[dict[str, Any]] = []
    web_storage_session: dict[str, str] = {}

    def launch_browser_and_capture() -> bool:
        """Launch browser and capture HAR. Returns True on success."""
        nonlocal browser_cookies, web_storage_local, web_storage_session
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

            # Build context options - write raw HAR to temp file
            context_options: dict[str, Any] = {
                "record_har_path": str(temp_path),
                "record_har_content": "embed",  # Embed response bodies in HAR
                "ignore_https_errors": True,  # Devices often have self-signed certs
                "service_workers": "block",  # Disable service workers to prevent caching
            }

            # Add HTTP Basic Auth credentials if needed
            if http_credentials:
                context_options["http_credentials"] = http_credentials

            context = browser_instance.new_context(**context_options)

            # Create page and configure routing
            page = context.new_page()

            if wait_for_data:
                # Inject JS that monkey-patches XHR/fetch to track in-flight
                # requests.  Runs before any page script on every navigation.
                page.add_init_script(_WAIT_FOR_DATA_INIT_SCRIPT)

                # Track first navigation so we skip the wait (the initial
                # goto has its own explicit quiescence wait below).
                _is_first_nav = [True]

                def _on_frame_navigated(frame: Any) -> None:
                    """Wait for async data to load after each page navigation.

                    Called via page event, NOT from a route handler — calling
                    page.evaluate() from a sync route handler deadlocks
                    Playwright's dispatch loop.
                    """
                    if frame != page.main_frame:
                        return
                    if _is_first_nav[0]:
                        _is_first_nav[0] = False
                        return  # Initial goto — handled by explicit wait below
                    try:
                        page.wait_for_load_state("domcontentloaded")
                        _wait_for_network_quiescence(page)
                    except Exception:  # noqa: S110
                        pass  # Page closed or context gone

                page.on("framenavigated", _on_frame_navigated)

            # Route handler for cache control (disable HTTP cache)
            context.route("**/*", lambda route: route.continue_())

            page.goto(target_url, wait_until="networkidle")

            # Wait for async data fetches that fire after initial JS loads
            if wait_for_data:
                _wait_for_network_quiescence(page)

            # Capture browser cookie state after page load
            # Includes JS-set cookies (e.g. XSRF_TOKEN) with full properties
            try:
                browser_cookies = context.cookies()
            except Exception:
                browser_cookies = []

            # Web Storage snapshot — localStorage via storage_state(),
            # sessionStorage via JS evaluation in the page context
            try:
                storage_state = context.storage_state()
                web_storage_local = [
                    {"origin": o["origin"], "items": o["localStorage"]}
                    for o in storage_state.get("origins", [])
                    if o.get("localStorage")
                ]
            except Exception:
                web_storage_local = []

            try:
                web_storage_session = page.evaluate(
                    "() => Object.fromEntries(Object.entries(sessionStorage))"
                )
            except Exception:
                web_storage_session = {}

            if timeout is not None:
                if wait_for_data:
                    # Use Playwright's wait to keep the event loop (and
                    # framenavigated listeners) active during the wait period.
                    page.wait_for_timeout(timeout * 1000)
                    # Final quiescence wait for the last page's data
                    _wait_for_network_quiescence(page, timeout_s=10.0)
                else:
                    # Legacy: simple sleep
                    time.sleep(timeout)
            else:
                # Interactive mode: wait for user to close browser
                _LOGGER.info("Browser opened. Interact with your device, then close the browser.")
                try:
                    page.wait_for_event("close", timeout=0)
                except Exception as e:
                    _LOGGER.warning("Error waiting for page close: %s", e)
                    # Continue with cleanup anyway

            # Close context to save HAR
            try:
                context.close()
            except Exception as e:
                _LOGGER.warning("Failed to close browser context: %s", e)
                # Continue cleanup anyway

            try:
                browser_instance.close()
            except Exception as e:
                _LOGGER.warning("Failed to close browser instance: %s", e)
                # Continue cleanup anyway
        return True

    def _is_missing_browser_error(error_msg: str) -> bool:
        """Check if error indicates the browser executable is missing."""
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in _MISSING_BROWSER_PATTERNS)

    def _is_missing_deps_error(error_msg: str) -> bool:
        """Check if error indicates missing browser dependencies."""
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in _MISSING_DEPS_PATTERNS)

    def _cleanup_temp() -> None:
        """Clean up temp file."""
        try:
            temp_path.unlink()
        except Exception as e:
            _LOGGER.debug("Failed to clean up temp file %s: %s", temp_path, e)
            # Not critical, continue anyway

    def _try_fix_and_retry(fix_fn: Callable[[], bool], fix_fail_msg: str) -> CaptureResult | None:
        """Run a fix function and retry the capture. Returns CaptureResult on failure, None on success."""
        if fix_fn():
            _LOGGER.info("Fix applied. Retrying capture...")
            try:
                launch_browser_and_capture()
                return None  # success
            except Exception as e2:
                _cleanup_temp()
                return CaptureResult(
                    har_path=Path(),
                    success=False,
                    error=_sanitize_error_message(str(e2), http_credentials),
                )
        _cleanup_temp()
        return CaptureResult(har_path=Path(), success=False, error=fix_fail_msg)

    try:
        launch_browser_and_capture()
    except Exception as e:
        error_str = _sanitize_error_message(str(e), http_credentials)
        if _is_missing_browser_error(error_str):
            _LOGGER.warning("Browser executable missing. Reinstalling %s...", browser)
            fail = _try_fix_and_retry(
                lambda: install_browser(browser),
                f"Failed to install {browser}. Run: python -m playwright install {browser}",
            )
            if fail:
                return fail
        elif _is_missing_deps_error(error_str):
            _LOGGER.warning("Browser dependencies missing. Installing...")
            fail = _try_fix_and_retry(
                install_browser_deps,
                "Failed to install browser dependencies",
            )
            if fail:
                return fail
        else:
            _cleanup_temp()
            return CaptureResult(
                har_path=Path(),
                success=False,
                error=error_str,
            )

    # Inject probe data and browser cookies into the raw HAR before any
    # downstream processing.  This ensures they appear in all output paths
    # (sanitized, compressed, raw).
    if probes or browser_cookies or web_storage_local or web_storage_session:
        try:
            with open(temp_path, encoding="utf-8") as f:
                raw_har = json.load(f)
            if probes:
                raw_har["log"]["_probes"] = probes
            if browser_cookies:
                raw_har["log"].setdefault("_har_capture", {})
                raw_har["log"]["_har_capture"]["browser_cookies"] = browser_cookies
            if web_storage_local:
                raw_har["log"].setdefault("_har_capture", {})
                raw_har["log"]["_har_capture"]["local_storage"] = web_storage_local
            if web_storage_session:
                raw_har["log"].setdefault("_har_capture", {})
                raw_har["log"]["_har_capture"]["session_storage"] = [
                    {
                        "origin": target_url,
                        "items": [{"name": k, "value": v} for k, v in web_storage_session.items()],
                    }
                ]
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(raw_har, f)
        except Exception as e:
            _LOGGER.warning("Failed to inject metadata into HAR: %s", e)

    # Determine sanitized output path based on user's output_path
    if str(output_path).endswith(".har"):
        sanitized_output = output_path.parent / (output_path.stem + ".sanitized.har")
    else:
        sanitized_output = output_path.with_suffix(".sanitized.har")

    result = CaptureResult(har_path=None)

    # Sanitize from temp file to user's output location
    if sanitize:
        try:
            from har_capture.sanitization import sanitize_har_file

            _, sanitization_report = sanitize_har_file(
                str(temp_path),
                str(sanitized_output),
                heuristics=HeuristicMode.FLAG if interactive else HeuristicMode.DISABLED,
                custom_patterns=custom_patterns,
            )
            result.sanitized_path = sanitized_output
            result.sanitization_report = sanitization_report
        except Exception as e:
            _LOGGER.warning("Sanitization failed: %s", e)

    # Copy raw file to user's output location if:
    # - keep_raw is True, OR
    # - sanitize is False (user wants the raw file as output)
    if keep_raw or not sanitize:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(temp_path, output_path)
            result.har_path = output_path
        except Exception as e:
            result.success = False
            result.error = f"Failed to save HAR file: {e}"
            _LOGGER.error("Failed to copy raw HAR to %s: %s", output_path, e)

    # Always clean up temp file (raw PII should not persist)
    _cleanup_temp()

    # Compress the sanitized file (never compress unsanitized)
    if compress and result.sanitized_path and result.sanitized_path.exists():
        try:
            compressed_path, stats = filter_and_compress_har(result.sanitized_path, capture_options)
            result.compressed_path = compressed_path
            result.stats = stats

            # Delete uncompressed sanitized file unless keep_raw or interactive
            # Interactive mode needs the uncompressed file for user review
            if not keep_raw and not interactive:
                try:
                    result.sanitized_path.unlink()
                    result.sanitized_path = None
                except Exception as e:
                    _LOGGER.warning("Failed to delete uncompressed sanitized HAR: %s", e)
        except Exception as e:
            _LOGGER.warning("Compression failed: %s", e)

    return result
