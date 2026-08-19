"""Browser-based HAR capture using Playwright.

This module provides the core HAR capture functionality using Playwright.
Requires the 'capture' optional dependency: pip install har-capture[capture]
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
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
from har_capture.validation.completeness import (
    CaptureCompletenessReport,
    analyze_capture_completeness,
)

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
# Timeout (ms) for initial networkidle attempt before falling back to domcontentloaded.
# Normal devices resolve networkidle in <5s. 15s gives headroom for slow devices
# while catching persistent-connection devices without excessive wait.
_NETWORKIDLE_FALLBACK_TIMEOUT_MS = 15_000

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

_DIALOG_OBSERVER_INIT_SCRIPT = """\
(function () {
    // After the user resolves a native dialog, call straight back into Python
    // via the page-exposed binding. No window-scoped queue, no Python-side
    // polling — Playwright's expose_function is the first-class JS→Python
    // bridge for this kind of cross-context callback.

    var _alert = window.alert;
    window.alert = function (message) {
        _alert.call(window, message);
        window.__harCaptureDialogResolved({
            type: "alert",
            message: String(message),
            action: "accept"
        });
    };

    var _confirm = window.confirm;
    window.confirm = function (message) {
        var accepted = _confirm.call(window, message);
        window.__harCaptureDialogResolved({
            type: "confirm",
            message: String(message),
            action: accepted ? "accept" : "dismiss"
        });
        return accepted;
    };

    var _prompt = window.prompt;
    window.prompt = function (message, defaultValue) {
        var value = _prompt.call(window, message, defaultValue);
        window.__harCaptureDialogResolved({
            type: "prompt",
            message: String(message),
            action: value === null ? "dismiss" : "accept"
        });
        return value;
    };
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


def _apply_dialog_resolution(dialogs: list[dict[str, Any]], outcome: Any) -> dict[str, Any] | None:
    """Update the most-recent unresolved dialog matching ``outcome``.

    Pure function: walks ``dialogs`` in reverse, finds the first entry
    whose ``resolved_by`` is still ``"unknown"`` and whose ``type`` +
    ``message`` match ``outcome``, mutates that entry's ``action`` and
    ``resolved_by`` in place, and returns it.

    Extracted from the ``_on_dialog_resolved`` closure inside
    ``_run_browser_session`` so the matching logic — including the
    defensive ``isinstance`` guard and the no-match path — is
    fixture-driven unit-testable without going through Playwright
    mocks. The session closure is now a thin wrapper that handles
    logging.

    Args:
        dialogs: Mutable list of dialog records (``result.dialogs``
            shape) — each entry has ``type``, ``message``,
            ``default_value``, ``opened_at``, ``action``, ``resolved_by``.
        outcome: Resolution payload from the JS-side wrapper. Annotated
            ``Any`` because it crosses the ``page.expose_function``
            JS→Python bridge — runtime can be any JSON-compatible value.

    Returns:
        The updated dialog entry on match, or ``None`` if ``outcome``
        wasn't a dict or no unresolved matching entry was found.
    """
    if not isinstance(outcome, dict):
        return None
    dialog_type = outcome.get("type")
    message = outcome.get("message")
    for entry in reversed(dialogs):
        if entry["resolved_by"] == "unknown" and entry["type"] == dialog_type and entry["message"] == message:
            entry["action"] = outcome.get("action", "unknown")
            entry["resolved_by"] = "browser_ui"
            return entry
    return None


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
        completeness: What the capture contains and any gaps found in it
        downloads: Browser downloads saved during the session. Each record
            carries the suggested filename, the name it was saved under,
            the local path it was saved to, and an error message when
            saving failed. Saved files are raw device output — NOT
            sanitized.
    """

    har_path: Path | None = None
    compressed_path: Path | None = None
    sanitized_path: Path | None = None
    stats: dict[str, Any] | None = None
    sanitization_report: Any | None = None  # SanitizationReport when available
    completeness: CaptureCompletenessReport | None = None
    downloads: list[dict[str, Any]] = dataclasses.field(default_factory=list)
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


@dataclass
class CapturePathInfo:
    """Resolved paths for a capture operation.

    Attributes:
        output_path: User-facing HAR output path
        sanitized_output: Path for sanitized HAR (stem + .sanitized.har)
        temp_path: Temp file path for raw HAR (PII, always deleted)
        host: Extracted hostname from target
        target_url: Full URL for navigation (e.g., http://192.168.1.1/)
    """

    output_path: Path
    sanitized_output: Path
    temp_path: Path
    host: str
    target_url: str


@dataclass
class BrowserSessionResult:
    """Data captured during a Playwright browser session.

    Returned by _run_browser_session() — replaces the nonlocal variables
    that previously shuttled data out of launch_browser_and_capture().

    Attributes:
        pre_capture_cookies: Cookie jar state before any navigation
        browser_cookies: Cookies after page load (JS-set included)
        web_storage_local: localStorage entries per origin
        web_storage_session: sessionStorage key/value pairs
        captured_bodies: Eagerly captured response bodies keyed by
            ``"<method>|<url>|<status>"`` — used to patch HAR entries
            whose bodies were evicted before Playwright flushed the HAR.
        dialogs: Browser dialogs observed during interactive capture.
            For headed, user-driven runs, each entry records the dialog type,
            message, default value, inferred action (accept/dismiss), and that
            the dialog was resolved by the browser UI. Headless or timed
            captures keep Playwright's default auto-dismiss behavior.
        popups: One entry per page opened in the context after the initial
            page (i.e., popups via ``window.open`` / ``target="_blank"`` /
            ``context.new_page``). Each entry records the popup's initial
            URL and an opened-at timestamp. The popup's request/response
            traffic appears in the HAR via the context-level ``record_har_path``;
            this list exists so consumers can tell *that* a popup happened
            even if its traffic is otherwise indistinguishable from the
            main page's. Capture-everything: silent popups poison analysis.
        downloads: Files the user downloaded during the session, saved out
            of Playwright's ephemeral artifacts directory before context
            close deletes it (the CM2500 event-log export was lost this
            way). Each record carries the suggested filename, the name it
            was saved under, the local path, and an error message when
            saving failed. Saved files are raw device output — NOT
            sanitized.
        success: True if the session completed without error
        error: Error message if session failed
    """

    pre_capture_cookies: list[Any] = dataclasses.field(default_factory=list)
    browser_cookies: list[Any] = dataclasses.field(default_factory=list)
    web_storage_local: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    web_storage_session: dict[str, str] = dataclasses.field(default_factory=dict)
    captured_bodies: dict[str, bytes] = dataclasses.field(default_factory=dict)
    dialogs: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    popups: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    downloads: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    success: bool = True
    error: str | None = None


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


def strip_browser_internal_entries(har: dict[str, Any]) -> int:
    """Drop entries whose request URL is not http(s) from a HAR, in place.

    Browser-internal traffic (``chrome://``, ``chrome-extension://``,
    ``devtools://``, ``about:`` ...) is never target-device evidence, and
    some of it leaks local machine state — ``chrome://fileicon/?path=...``
    embeds the local filesystem path of every file on the downloads page
    (observed on the 2026-08-19 CM2500 captures: 11 chrome:// entries,
    including Playwright temp-dir paths).

    Args:
        har: Parsed HAR data (modified in place)

    Returns:
        Number of entries removed
    """
    entries = har.get("log", {}).get("entries")
    if not isinstance(entries, list):
        return 0

    def _keep_entry(entry: Any) -> bool:
        if not isinstance(entry, dict):
            return True  # malformed entries are not ours to judge — keep
        url = str(entry.get("request", {}).get("url", ""))
        return url.lower().startswith(("http://", "https://"))

    kept = [e for e in entries if _keep_entry(e)]
    removed = len(entries) - len(kept)
    if removed:
        har["log"]["entries"] = kept
    return removed


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


def _resolve_capture_paths(
    ip: str,
    output: str | Path | None,
    target_url: str | None,
) -> CapturePathInfo:
    """Resolve output paths, create temp file, and determine target URL.

    Pure filesystem + parsing logic — no network calls, no Playwright.

    Args:
        ip: Target URL, hostname, or IP address
        output: User-specified output path (None = auto-generate)
        target_url: Pre-computed target URL (None = needs connectivity check)

    Returns:
        CapturePathInfo with all resolved paths and the target URL
        (target_url may still be None if not pre-computed — caller must
        run connectivity check).
    """
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

    # Parse target to extract hostname
    host, _ = _parse_target(ip)

    # Determine sanitized output path
    if str(output_path).endswith(".har"):
        sanitized_output = output_path.parent / (output_path.stem + ".sanitized.har")
    else:
        sanitized_output = output_path.with_suffix(".sanitized.har")

    # Create temp file for raw HAR (contains PII, never stored in user's directory)
    temp_fd, temp_path_str = tempfile.mkstemp(suffix=".har", prefix="har_capture_")
    temp_path = Path(temp_path_str)
    os.close(temp_fd)

    return CapturePathInfo(
        output_path=output_path,
        sanitized_output=sanitized_output,
        temp_path=temp_path,
        host=host,
        target_url=target_url or "",
    )


def _run_browser_session(
    target_url: str,
    temp_path: Path,
    browser: str = "chromium",
    http_credentials: dict[str, str] | None = None,
    headless: bool = False,
    timeout: int | None = None,
    wait_for_data: bool = True,
    page_load_strategy: str = "networkidle",
    downloads_dir: Path | None = None,
) -> BrowserSessionResult:
    """Launch Playwright browser and capture HAR.

    Handles: browser launch, context configuration, navigation with
    networkidle/domcontentloaded fallback, wait-for-data, cookie/storage
    capture, download preservation, timeout vs interactive mode, browser
    cleanup.

    Args:
        target_url: Full URL to navigate to
        temp_path: Temp file path where Playwright writes the raw HAR
        browser: Browser engine name
        http_credentials: Optional HTTP Basic Auth credentials
        headless: Run browser without visible window
        timeout: Seconds to wait (None = interactive, wait for user close)
        wait_for_data: Enable async data fetch tracking
        page_load_strategy: Playwright wait_until value for page.goto()
        downloads_dir: Directory to save browser downloads into (created
            lazily on first download). ``None`` disables download saving.

    Returns:
        BrowserSessionResult with captured browser state
    """
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright

    result = BrowserSessionResult()

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
            "record_har_content": "embed",
            "ignore_https_errors": True,
            "service_workers": "block",
            "storage_state": {
                "cookies": [],
                "origins": [],
            },
        }

        if http_credentials:
            context_options["http_credentials"] = http_credentials

        context = browser_instance.new_context(**context_options)

        # Record cookie jar state before any navigation
        try:
            result.pre_capture_cookies = context.cookies()
            if result.pre_capture_cookies:
                _LOGGER.warning(
                    "Context inherited %d cookies despite clean storage_state; capture may be contaminated",
                    len(result.pre_capture_cookies),
                )
        except Exception as e:
            _LOGGER.warning("Could not audit pre-capture cookies: %s", e)
            result.pre_capture_cookies = []

        page = context.new_page()
        interactive_dialog_capture = not headless and timeout is None
        if interactive_dialog_capture:
            # Two-event model. (1) `page.on("dialog")` fires when the native
            # dialog OPENS — we create the record and log it. (2) The exposed
            # `__harCaptureDialogResolved` binding fires when the wrapped JS
            # confirm/alert/prompt RETURNS after the user clicks — we update
            # the open record with the outcome. No polling, no per-handler
            # deadlock surface (Playwright's first-class JS→Python bridge
            # delivers the resolution event directly).

            def _on_dialog_open(dialog: Any) -> None:
                dialog_info = {
                    "type": getattr(dialog, "type", None),
                    "message": getattr(dialog, "message", None),
                    "default_value": getattr(dialog, "default_value", None),
                    "opened_at": datetime.now().isoformat(timespec="seconds"),
                    "action": "unknown",
                    "resolved_by": "unknown",
                }
                result.dialogs.append(dialog_info)
                _LOGGER.info(
                    "Dialog opened: type=%s message=%r",
                    dialog_info["type"],
                    dialog_info["message"],
                )

            def _on_dialog_resolved(outcome: Any) -> None:
                # Match-and-update logic lives in the module-level pure
                # function ``_apply_dialog_resolution`` so it can be
                # fixture-driven unit-tested without Playwright mocks.
                # This closure stays thin: delegate, then log.
                updated = _apply_dialog_resolution(result.dialogs, outcome)
                if updated is not None:
                    _LOGGER.info(
                        "Dialog resolved by browser_ui: type=%s action=%s message=%r",
                        updated["type"],
                        updated["action"],
                        updated["message"],
                    )
                else:
                    _LOGGER.warning("Dialog resolution had no matching open record: %r", outcome)

            page.expose_function("__harCaptureDialogResolved", _on_dialog_resolved)
            page.add_init_script(_DIALOG_OBSERVER_INIT_SCRIPT)
            page.on("dialog", _on_dialog_open)

        _is_first_nav = [True]
        _quiescence_disabled = [not wait_for_data]

        if wait_for_data:
            page.add_init_script(_WAIT_FOR_DATA_INIT_SCRIPT)

            def _on_frame_navigated(frame: Any) -> None:
                if frame != page.main_frame:
                    return
                if _is_first_nav[0]:
                    _is_first_nav[0] = False
                    return
                if _quiescence_disabled[0]:
                    return
                try:
                    page.wait_for_load_state("domcontentloaded")
                    _wait_for_network_quiescence(page)
                except Exception:  # noqa: S110
                    pass

            page.on("framenavigated", _on_frame_navigated)

        # Eagerly capture response bodies for text content types.
        # Playwright's HAR recorder fetches bodies lazily at context.close()
        # via CDP Network.getResponseBody.  If a navigation evicts the
        # response from Chrome's buffer before the flush, the body is lost.
        # Capturing here while the response is still live lets us patch
        # missing bodies into the HAR afterward.
        def _on_response(response: Any) -> None:
            try:
                ct = response.headers.get("content-type", "")
                if not any(t in ct for t in ("text/", "application/json", "application/xml")):
                    return
                body = response.body()
                if body:
                    key = f"{response.request.method}|{response.url}|{response.status}"
                    result.captured_bodies[key] = body
            except Exception:  # noqa: S110 — response may be aborted/streaming
                pass

        page.on("response", _on_response)

        # Collect Download objects as they start; saving happens after the
        # interactive wait, in one place, before context.close() deletes
        # Playwright's ephemeral artifacts directory. The handler itself
        # makes no Playwright calls — blocking RPCs inside sync-API event
        # handlers can deadlock the dispatcher.
        pending_downloads: list[Any] = []

        def _on_download(download: Any) -> None:
            pending_downloads.append(download)
            _LOGGER.info("Download started (will be saved when the browser closes)")

        if downloads_dir is not None:
            page.on("download", _on_download)

        # Subscribe to popup / new-page events at the context level. Without
        # this, popups opened by the device (e.g., S33 reboot confirmation,
        # router config wizards) don't get their response bodies eagerly
        # captured, and the user has no signal that a popup happened — silent
        # capture loss. Context-level ``record_har_path`` already records the
        # popup's traffic in the HAR; this handler adds the same eager-body
        # safety net the main page has, plus a ``_solentlabs.popups`` audit
        # entry so consumers can see *that* a popup occurred even when its
        # entries are interleaved with the main page's.
        def _on_new_page(popup_page: Any) -> None:
            try:
                popup_page.on("response", _on_response)
                if downloads_dir is not None:
                    popup_page.on("download", _on_download)
                result.popups.append(
                    {
                        "url": popup_page.url,  # may be "about:blank" if not yet navigated
                        "opened_at": datetime.now().isoformat(timespec="seconds"),
                    }
                )
            except Exception as e:
                _LOGGER.warning("Failed to attach handlers to popup page: %s", e)

        context.on("page", _on_new_page)

        # Navigate with auto-fallback
        if page_load_strategy == "networkidle":
            try:
                page.goto(
                    target_url,
                    wait_until="networkidle",
                    timeout=_NETWORKIDLE_FALLBACK_TIMEOUT_MS,
                )
            except PlaywrightTimeout:
                _LOGGER.info(
                    "networkidle timed out — device has persistent connections, "
                    "falling back to domcontentloaded"
                )
                page.wait_for_load_state("domcontentloaded")
                _quiescence_disabled[0] = True
        else:
            page.goto(target_url, wait_until=page_load_strategy)  # type: ignore[arg-type]

        if wait_for_data and not _quiescence_disabled[0]:
            _wait_for_network_quiescence(page)

        # Capture browser cookie state after page load
        try:
            result.browser_cookies = context.cookies()
        except Exception:
            result.browser_cookies = []

        # Web Storage snapshot
        try:
            storage_state = context.storage_state()
            result.web_storage_local = [
                {"origin": o["origin"], "items": o["localStorage"]}
                for o in storage_state.get("origins", [])
                if o.get("localStorage")
            ]
        except Exception:
            result.web_storage_local = []

        try:
            result.web_storage_session = page.evaluate(
                "() => Object.fromEntries(Object.entries(sessionStorage))"
            )
        except Exception:
            result.web_storage_session = {}

        if timeout is not None:
            if wait_for_data:
                page.wait_for_timeout(timeout * 1000)
                _wait_for_network_quiescence(page, timeout_s=10.0)
            else:
                time.sleep(timeout)
        else:
            _LOGGER.info("Browser opened. Interact with your device, then close the browser.")
            try:
                page.wait_for_event("close", timeout=0)
            except Exception as e:
                _LOGGER.warning("Error waiting for page close: %s", e)

        # Save downloads BEFORE context.close() — closing the context
        # deletes Playwright's artifacts directory and the files with it.
        if pending_downloads and downloads_dir is not None:
            result.downloads = _save_pending_downloads(pending_downloads, downloads_dir)

        try:
            context.close()
        except Exception as e:
            _LOGGER.warning("Failed to close browser context: %s", e)

        try:
            browser_instance.close()
        except Exception as e:
            _LOGGER.warning("Failed to close browser instance: %s", e)

    return result


def _unique_download_name(suggested: str, taken: set[str]) -> str:
    """Pick a collision-free filename for a download.

    Uses only the basename of the suggestion (a hostile suggested
    filename must not escape the downloads directory) and appends a
    counter when the name is already taken: ``log.txt``, ``log_2.txt``.
    """
    base = Path(suggested or "download").name or "download"
    if base not in taken:
        return base
    stem, suffix = Path(base).stem, Path(base).suffix
    counter = 2
    while f"{stem}_{counter}{suffix}" in taken:
        counter += 1
    return f"{stem}_{counter}{suffix}"


def _save_pending_downloads(
    pending: list[Any],
    downloads_dir: Path,
) -> list[dict[str, Any]]:
    """Persist browser downloads out of Playwright's artifacts directory.

    Capture-everything over fail: each download is saved independently
    and a failure is recorded, never raised — losing one file must not
    lose the capture.

    Args:
        pending: Playwright Download objects collected during the session
        downloads_dir: Directory to save into (created on first use)

    Returns:
        One audit record per download: suggested filename, saved name and
        path on success, error message on failure.
    """
    records: list[dict[str, Any]] = []
    taken: set[str] = set()
    for download in pending:
        record: dict[str, Any] = {}
        try:
            record["suggested_filename"] = str(getattr(download, "suggested_filename", "") or "")
            downloads_dir.mkdir(parents=True, exist_ok=True)
            name = _unique_download_name(record["suggested_filename"], taken)
            dest = downloads_dir / name
            download.save_as(dest)
            taken.add(name)
            record["saved_as"] = name
            record["saved_path"] = str(dest)
            _LOGGER.info("Saved download: %s", dest)
        except Exception as e:
            record["error"] = str(e)
            _LOGGER.warning("Failed to save download %r: %s", record.get("suggested_filename"), e)
        records.append(record)
    return records


def _patch_missing_bodies(
    temp_path: Path,
    captured_bodies: dict[str, bytes],
) -> int:
    """Patch missing response bodies into the raw HAR.

    Playwright's HAR recorder fetches response bodies lazily at
    ``context.close()`` via CDP ``Network.getResponseBody``.  If a
    navigation evicts the response from Chrome's buffer before the
    flush, the body is lost — headers and sizes are correct but
    ``content.text`` is absent.

    This function fills the gap using bodies eagerly captured via
    ``page.on("response")`` during the live session.

    Args:
        temp_path: Path to the raw HAR temp file (modified in-place).
        captured_bodies: Map of ``"<method>|<url>|<status>"`` → raw
            response bytes captured during the browser session.

    Returns:
        Number of HAR entries whose bodies were patched.
    """
    if not captured_bodies:
        return 0

    try:
        with open(temp_path, encoding="utf-8") as f:
            har = json.load(f)
    except Exception:
        return 0

    patched = 0
    for entry in har.get("log", {}).get("entries", []):
        response = entry.get("response", {})
        content = response.get("content", {})

        # Skip entries that already have body content
        if content.get("text"):
            continue

        # Only patch if the response indicated there was content
        if response.get("bodySize", 0) <= 0 and response.get("_transferSize", 0) <= 0:
            continue

        method = entry.get("request", {}).get("method", "GET")
        url = entry.get("request", {}).get("url", "")
        status = response.get("status", 0)
        key = f"{method}|{url}|{status}"

        if key not in captured_bodies:
            continue

        body = captured_bodies[key]
        mime = content.get("mimeType", "")

        # Text content types are stored as plain text in the HAR
        if any(t in mime for t in ("text/", "application/json", "application/xml")):
            try:
                content["text"] = body.decode("utf-8")
            except UnicodeDecodeError:
                content["text"] = base64.b64encode(body).decode("ascii")
                content["encoding"] = "base64"
        else:
            content["text"] = base64.b64encode(body).decode("ascii")
            content["encoding"] = "base64"

        content["size"] = len(body)
        patched += 1

    if patched:
        _LOGGER.info("Patched %d HAR entries with eagerly captured response bodies", patched)
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(har, f)
        except Exception as e:
            _LOGGER.warning("Failed to write patched HAR: %s", e)
            return 0

    return patched


def _inject_har_metadata(
    temp_path: Path,
    target_url: str,
    probes: dict[str, Any] | None,
    session: BrowserSessionResult,
) -> None:
    """Inject probe data and browser state into the raw HAR.

    Reads the raw HAR from temp_path, injects _probes, _har_capture
    (cookies, storage), and _solentlabs (pre_capture_cookies), then
    writes back.

    Args:
        temp_path: Path to the raw HAR temp file
        target_url: Target URL used during capture (for sessionStorage origin)
        probes: Pre-capture probe results (None if no probes ran)
        session: Browser session result with captured state
    """
    try:
        with open(temp_path, encoding="utf-8") as f:
            raw_har = json.load(f)
        if probes:
            raw_har["log"]["_probes"] = probes
        if session.browser_cookies:
            raw_har["log"].setdefault("_har_capture", {})
            raw_har["log"]["_har_capture"]["browser_cookies"] = session.browser_cookies
        if session.web_storage_local:
            raw_har["log"].setdefault("_har_capture", {})
            raw_har["log"]["_har_capture"]["local_storage"] = session.web_storage_local
        if session.web_storage_session:
            raw_har["log"].setdefault("_har_capture", {})
            raw_har["log"]["_har_capture"]["session_storage"] = [
                {
                    "origin": target_url,
                    "items": [{"name": k, "value": v} for k, v in session.web_storage_session.items()],
                }
            ]
        raw_har["log"]["_solentlabs"] = {
            "pre_capture_cookies": session.pre_capture_cookies,
            "popups": session.popups,
            "dialogs": session.dialogs,
            # Filenames only — the local saved_path must not leak into an
            # artifact that gets shared.
            "downloads": [
                {k: v for k, v in record.items() if k != "saved_path"} for record in session.downloads
            ],
        }
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(raw_har, f)
    except Exception as e:
        _LOGGER.warning("Failed to inject metadata into HAR: %s", e)


def _run_post_capture_pipeline(
    temp_path: Path,
    output_path: Path,
    sanitized_output: Path,
    sanitize: bool,
    compress: bool,
    keep_raw: bool,
    interactive: bool,
    capture_options: CaptureOptions,
    custom_patterns: str | dict[str, Any] | None = None,
) -> CaptureResult:
    """Run sanitization, copy raw, compress, and cleanup.

    Args:
        temp_path: Path to raw HAR temp file (always deleted)
        output_path: User-facing output path for raw HAR
        sanitized_output: Path for sanitized HAR output
        sanitize: Whether to sanitize the HAR
        compress: Whether to compress after sanitization
        keep_raw: Whether to keep the raw (unsanitized) HAR
        interactive: Whether to flag suspicious values for review
        capture_options: Filtering options (fonts, images, media)
        custom_patterns: Domain pattern for sanitization

    Returns:
        CaptureResult with paths to generated files and a completeness report
    """
    result = CaptureResult(har_path=None)

    # Strip browser-internal entries (chrome:// etc.) before anything else
    # touches the HAR: they are never device evidence and can leak local
    # paths, so no downstream artifact — raw copy included — keeps them.
    try:
        with open(temp_path, encoding="utf-8") as f:
            raw_har = json.load(f)
        removed_internal = strip_browser_internal_entries(raw_har)
        if removed_internal:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(raw_har, f)
            _LOGGER.info("Removed %d browser-internal entries (chrome:// etc.)", removed_internal)
        # Runs on the raw HAR: bloat filtering can drop the true first entry.
        result.completeness = analyze_capture_completeness(raw_har)
    except Exception as e:
        _LOGGER.warning("Capture-completeness check failed: %s", e)

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

    # Copy raw file if keep_raw or no sanitization
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
    try:
        temp_path.unlink()
    except Exception as e:
        _LOGGER.debug("Failed to clean up temp file %s: %s", temp_path, e)

    # Compress the sanitized file (never compress unsanitized)
    if compress and result.sanitized_path and result.sanitized_path.exists():
        try:
            compressed_path, stats = filter_and_compress_har(result.sanitized_path, capture_options)
            result.compressed_path = compressed_path
            result.stats = stats

            if not keep_raw and not interactive:
                try:
                    result.sanitized_path.unlink()
                    result.sanitized_path = None
                except Exception as e:
                    _LOGGER.warning("Failed to delete uncompressed sanitized HAR: %s", e)
        except Exception as e:
            _LOGGER.warning("Compression failed: %s", e)

    return result


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
    target_url: str | None = None,
    page_load_strategy: str = "networkidle",
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
        target_url: Pre-computed target URL from the CLI workflow (e.g.,
            ``http://192.168.100.1/``).  When provided, the internal
            connectivity check is skipped — avoids a duplicate HTTP request.
        page_load_strategy: Playwright ``wait_until`` value for ``page.goto()``.
            Default ``"networkidle"``.  Use ``"domcontentloaded"`` for devices
            with persistent polling that prevent network idle.

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

    # Pre-flight checks
    if not check_playwright():
        return CaptureResult(
            har_path=Path(),
            success=False,
            error="Playwright not installed. Run: pip install har-capture[capture]",
        )

    if not check_browser_installed(browser):
        _LOGGER.info("Browser %s not installed. Installing...", browser)
        if not install_browser(browser):
            return CaptureResult(
                har_path=Path(),
                success=False,
                error=f"Failed to install {browser}. Run: python -m playwright install {browser}",
            )
        _LOGGER.info("Browser %s installed successfully.", browser)

    # 1. Resolve paths and create temp file
    paths = _resolve_capture_paths(ip, output, target_url)

    # Check connectivity if target_url was not pre-computed
    if not paths.target_url:
        reachable, scheme, error = check_device_connectivity(ip)
        if not reachable:
            with contextlib.suppress(Exception):
                paths.temp_path.unlink()
            return CaptureResult(
                har_path=paths.output_path,
                success=False,
                error=error or f"Cannot connect to {paths.host}",
            )
        paths = CapturePathInfo(
            output_path=paths.output_path,
            sanitized_output=paths.sanitized_output,
            temp_path=paths.temp_path,
            host=paths.host,
            target_url=f"{scheme}://{paths.host}/",
        )

    # 2. Run browser session (with error recovery)
    def _run_session() -> BrowserSessionResult:
        return _run_browser_session(
            target_url=paths.target_url,
            temp_path=paths.temp_path,
            browser=browser,
            http_credentials=http_credentials,
            headless=headless,
            timeout=timeout,
            wait_for_data=wait_for_data,
            page_load_strategy=page_load_strategy,
            downloads_dir=paths.output_path.parent / f"{paths.output_path.stem}_downloads",
        )

    def _cleanup_temp() -> None:
        try:
            paths.temp_path.unlink()
        except Exception as e:
            _LOGGER.debug("Failed to clean up temp file %s: %s", paths.temp_path, e)

    def _is_missing_browser_error(error_msg: str) -> bool:
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in _MISSING_BROWSER_PATTERNS)

    def _is_missing_deps_error(error_msg: str) -> bool:
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in _MISSING_DEPS_PATTERNS)

    def _try_fix_and_retry(fix_fn: Callable[[], bool], fix_fail_msg: str) -> CaptureResult | None:
        if fix_fn():
            _LOGGER.info("Fix applied. Retrying capture...")
            try:
                _run_session()
                return None
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
        session = _run_session()
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
            # Retry succeeded — create a default session result
            session = BrowserSessionResult()
        elif _is_missing_deps_error(error_str):
            _LOGGER.warning("Browser dependencies missing. Installing...")
            fail = _try_fix_and_retry(
                install_browser_deps,
                "Failed to install browser dependencies",
            )
            if fail:
                return fail
            session = BrowserSessionResult()
        else:
            _cleanup_temp()
            return CaptureResult(
                har_path=Path(),
                success=False,
                error=error_str,
            )

    # 3. Patch any response bodies that Playwright missed
    _patch_missing_bodies(paths.temp_path, session.captured_bodies)

    # 4. Inject metadata
    _inject_har_metadata(paths.temp_path, paths.target_url, probes, session)

    # 5. Post-capture pipeline
    result = _run_post_capture_pipeline(
        temp_path=paths.temp_path,
        output_path=paths.output_path,
        sanitized_output=paths.sanitized_output,
        sanitize=sanitize,
        compress=compress,
        keep_raw=keep_raw,
        interactive=interactive,
        capture_options=capture_options,
        custom_patterns=custom_patterns,
    )
    result.downloads = session.downloads
    return result
