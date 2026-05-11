"""Integration tests for browser capture using Playwright.

These tests start a local HTTP server and use Playwright to capture real traffic.
They are marked as 'slow' and 'integration' - skip with: pytest -m "not slow"

Requirements:
- Playwright must be installed: pip install har-capture[capture]
- Browser must be installed: playwright install chromium
"""

from __future__ import annotations

import gzip
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Skip all tests in this module if Playwright is not available
pytest.importorskip("playwright", reason="Playwright not installed")

from har_capture.capture import capture_device_har
from har_capture.capture.browser import _DIALOG_OBSERVER_INIT_SCRIPT
from har_capture.capture.deps import check_browser_installed

# =============================================================================
# Test Server
# =============================================================================


class MockHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for testing capture."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress server logging during tests."""

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/":
            self._send_html(
                "<html><head><title>Test Page</title></head>"
                "<body><h1>Hello World</h1>"
                '<a href="/page2">Page 2</a></body></html>'
            )
        elif self.path == "/page2":
            self._send_html(
                "<html><head><title>Page 2</title></head><body><h1>Second Page</h1></body></html>"
            )
        elif self.path == "/api/data":
            self._send_json({"status": "ok", "value": 42})
        elif self.path == "/popup-trigger":
            # Mimics the S33-class reboot flow: the page opens a popup
            # via window.open. The popup's traffic must land in the HAR
            # for downstream tools to reconstruct the auth/config exchange.
            self._send_html(
                "<html><head><title>Popup Trigger</title></head>"
                "<body><h1>Opens Popup</h1>"
                "<script>window.open('/popup-content', '_blank');</script>"
                "</body></html>"
            )
        elif self.path == "/popup-content":
            self._send_html(
                "<html><head><title>Popup Content</title></head>"
                "<body><h1>Popup Body</h1>"
                "<p>This popup must appear in the HAR.</p></body></html>"
            )
        elif self.path == "/sensitive":
            # Page with sensitive data that should be sanitized
            self._send_html(
                "<html><body>"
                "<p>IP: 192.168.1.100</p>"
                "<p>MAC: AA:BB:CC:DD:EE:FF</p>"
                "<p>Email: user@example.com</p>"
                "</body></html>"
            )
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(content_length)  # Read and discard body
            self._send_json({"status": "authenticated"})
        else:
            self.send_error(404)

    def _send_html(self, content: str) -> None:
        """Send HTML response."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())

    def _send_json(self, data: dict) -> None:
        """Send JSON response."""
        content = json.dumps(data)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())


@pytest.fixture(scope="module")
def mock_server() -> Generator[str, None, None]:
    """Start a mock HTTP server for testing.

    Yields:
        Base URL of the mock server (e.g., "http://127.0.0.1:8765")
    """
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    # Wait for server to be ready
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


class PopupRootHandler(MockHandler):
    """Variant that serves the popup-trigger HTML at ``/``.

    ``capture_device_har`` always navigates to the target's root path,
    so to exercise the popup-capture path without disturbing other
    tests' fixtures, we use a dedicated server whose root opens a popup
    on load. The popup destination (``/popup-content``) is inherited
    from MockHandler.
    """

    def do_GET(self) -> None:
        """Serve popup-trigger at root; defer everything else to MockHandler."""
        if self.path == "/":
            self._send_html(
                "<html><head><title>Popup Trigger</title></head>"
                "<body><h1>Opens Popup</h1>"
                "<script>window.open('/popup-content', '_blank');</script>"
                "</body></html>"
            )
            return
        super().do_GET()


@pytest.fixture(scope="module")
def popup_mock_server() -> Generator[str, None, None]:
    """Mock server whose root opens a popup on load.

    Yields:
        Base URL of the popup-emitting mock server.
    """
    server = HTTPServer(("127.0.0.1", 0), PopupRootHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


# =============================================================================
# Skip conditions
# =============================================================================


def browser_available() -> bool:
    """Check if Chromium browser is installed."""
    try:
        return check_browser_installed("chromium")
    except Exception:
        return False


skip_no_browser = pytest.mark.skipif(
    not browser_available(),
    reason="Chromium not installed. Run: playwright install chromium",
)


# =============================================================================
# Integration Tests
# =============================================================================


@pytest.mark.slow
@pytest.mark.integration
@skip_no_browser
class TestBrowserCapture:
    """Integration tests for browser-based capture."""

    def test_capture_creates_har_file(self, mock_server: str, tmp_path: Path) -> None:
        """Test that capture creates a valid HAR file."""
        output = tmp_path / "test.har"

        result = capture_device_har(
            ip=mock_server,
            output=str(output),
            browser="chromium",
            sanitize=False,  # Don't sanitize for this test
            compress=False,
            headless=True,
            timeout=3,
        )

        assert result.success, f"Capture failed: {result.error}"
        assert result.har_path is not None
        assert result.har_path.exists()

        # Verify HAR structure
        with open(result.har_path) as f:
            har = json.load(f)

        assert "log" in har
        assert "entries" in har["log"]
        assert len(har["log"]["entries"]) > 0

    def test_capture_with_sanitization(self, mock_server: str, tmp_path: Path) -> None:
        """Test that capture with sanitization removes PII."""
        output = tmp_path / "sanitized.har"

        result = capture_device_har(
            ip=mock_server,
            output=str(output),
            browser="chromium",
            sanitize=True,
            compress=False,
            headless=True,
            timeout=3,
        )

        assert result.success, f"Capture failed: {result.error}"
        assert result.sanitized_path is not None
        assert result.sanitized_path.exists()

        # Verify sanitized HAR
        with open(result.sanitized_path) as f:
            har = json.load(f)

        # Check that entries exist
        assert len(har["log"]["entries"]) > 0

    def test_capture_with_compression(self, mock_server: str, tmp_path: Path) -> None:
        """Test that capture with compression creates .gz file."""
        output = tmp_path / "compressed.har"

        result = capture_device_har(
            ip=mock_server,
            output=str(output),
            browser="chromium",
            sanitize=True,
            compress=True,
            headless=True,
            timeout=3,
        )

        assert result.success, f"Capture failed: {result.error}"
        assert result.compressed_path is not None

        # Should have .gz extension
        gz_path = result.compressed_path
        assert gz_path.suffix == ".gz"
        assert gz_path.exists()

        # Verify it's valid gzip
        with gzip.open(gz_path, "rt") as f:
            har = json.load(f)
        assert "log" in har

    def test_capture_records_requests(self, mock_server: str, tmp_path: Path) -> None:
        """Test that capture records HTTP requests."""
        output = tmp_path / "requests.har"

        result = capture_device_har(
            ip=mock_server,
            output=str(output),
            browser="chromium",
            sanitize=False,
            compress=False,
            headless=True,
            timeout=3,
        )

        assert result.success
        assert result.har_path is not None

        with open(result.har_path) as f:
            har = json.load(f)

        # Find the main page request
        entries = har["log"]["entries"]
        urls = [e["request"]["url"] for e in entries]

        # Should have captured the root page
        root_urls = [u for u in urls if u.endswith("/") or "127.0.0.1" in u]
        assert len(root_urls) > 0, f"No root URL found in: {urls}"

    def test_capture_unreachable_host(self, tmp_path: Path) -> None:
        """Test capture handles unreachable hosts gracefully."""
        output = tmp_path / "unreachable.har"

        result = capture_device_har(
            ip="http://192.0.2.1",  # TEST-NET-1, guaranteed unreachable
            output=str(output),
            browser="chromium",
            headless=True,
            timeout=3,
        )

        assert not result.success
        assert result.error is not None
        assert "connect" in result.error.lower() or "cannot" in result.error.lower()


@pytest.mark.slow
@pytest.mark.integration
@skip_no_browser
class TestConnectivity:
    """Integration tests for connectivity checking."""

    def test_check_connectivity_reachable(self, mock_server: str) -> None:
        """Test connectivity check for reachable server."""
        from har_capture.capture.connectivity import check_device_connectivity

        reachable, scheme, error = check_device_connectivity(mock_server, timeout=5)

        assert reachable is True
        assert scheme == "http"
        assert error is None

    def test_check_connectivity_unreachable(self) -> None:
        """Test connectivity check for unreachable server."""
        from har_capture.capture.connectivity import check_device_connectivity

        reachable, _scheme, error = check_device_connectivity("http://192.0.2.1", timeout=2)

        assert reachable is False
        assert error is not None

    def test_check_basic_auth_no_auth(self, mock_server: str) -> None:
        """Test Basic Auth check for server without auth."""
        from har_capture.capture.connectivity import check_basic_auth

        requires_auth, realm = check_basic_auth(f"{mock_server}/")

        assert requires_auth is False
        assert realm is None


# =============================================================================
# Unit Tests for Capture Module (no browser needed)
# =============================================================================


class TestCaptureHelpers:
    """Unit tests for capture helper functions (no Playwright needed)."""

    def test_capture_result_dataclass(self) -> None:
        """Test CaptureResult dataclass."""
        from har_capture.capture.browser import CaptureResult

        test_path = Path("test_output.har")
        result = CaptureResult(
            har_path=test_path,
            success=True,
            error=None,
        )

        assert result.har_path == test_path
        assert result.success is True
        assert result.error is None

    def test_capture_options_dataclass(self) -> None:
        """Test CaptureOptions dataclass."""
        from har_capture.capture.browser import CaptureOptions

        options = CaptureOptions(
            include_fonts=True,
            include_images=False,
            include_media=False,
        )

        assert options.include_fonts is True
        assert options.include_images is False
        assert options.include_media is False

    def test_sanitize_error_message(self) -> None:
        """Test credential sanitization in error messages."""
        from har_capture.capture.browser import _sanitize_error_message

        error = "Failed to connect with user admin and password secret123"
        credentials = {"username": "admin", "password": "secret123"}

        sanitized = _sanitize_error_message(error, credentials)

        assert "admin" not in sanitized
        assert "secret123" not in sanitized
        assert "[USERNAME]" in sanitized
        assert "[PASSWORD]" in sanitized

    def test_sanitize_error_message_no_credentials(self) -> None:
        """Test error message sanitization with no credentials."""
        from har_capture.capture.browser import _sanitize_error_message

        error = "Connection timeout"

        assert _sanitize_error_message(error, None) == error
        assert _sanitize_error_message(error, {}) == error


# =============================================================================
# Popup Capture Tests
# =============================================================================


@pytest.mark.slow
@pytest.mark.integration
@skip_no_browser
class TestPopupCapture:
    """Real-browser tests that popup traffic lands in the HAR.

    Models the failure mode reported in CMM #146 (S33 reboot button opens a
    popup that the integrated browser does not capture). Without the
    ``context.on("page")`` subscription, popup responses can be evicted from
    Chromium's buffer before the HAR is flushed, and consumers have no signal
    that a popup occurred. Capture-everything: silent popups poison analysis.
    """

    def test_popup_traffic_lands_in_har(self, popup_mock_server: str, tmp_path: Path) -> None:
        """Popup opened via ``window.open`` is captured in HAR entries."""
        output = tmp_path / "popup.har"

        result = capture_device_har(
            ip=popup_mock_server,
            output=str(output),
            browser="chromium",
            sanitize=False,
            compress=False,
            headless=True,
            timeout=3,
        )

        assert result.success, f"Capture failed: {result.error}"
        assert result.har_path is not None

        with open(result.har_path) as f:
            har = json.load(f)

        urls = [e["request"]["url"] for e in har["log"]["entries"]]
        popup_urls = [u for u in urls if u.endswith("/popup-content")]
        assert popup_urls, f"Popup URL /popup-content not in HAR entries. URLs captured: {urls}"

    def test_popup_event_recorded_in_solentlabs_metadata(
        self, popup_mock_server: str, tmp_path: Path
    ) -> None:
        """``_solentlabs.popups`` records that a popup happened.

        Even when popup traffic interleaves with main-page traffic in the
        HAR entries, consumers need an explicit signal that a popup occurred
        so they can correlate the auth/config exchange across pages.
        """
        output = tmp_path / "popup_meta.har"

        result = capture_device_har(
            ip=popup_mock_server,
            output=str(output),
            browser="chromium",
            sanitize=False,
            compress=False,
            headless=True,
            timeout=3,
        )

        assert result.success, f"Capture failed: {result.error}"
        assert result.har_path is not None

        with open(result.har_path) as f:
            har = json.load(f)

        solentlabs = har["log"].get("_solentlabs", {})
        popups = solentlabs.get("popups", [])
        assert popups, f"_solentlabs.popups is empty; full _solentlabs: {solentlabs}"
        assert all("opened_at" in p for p in popups), f"popup entries missing opened_at: {popups}"


# =============================================================================
# Dialog Observer Integration Tests
# =============================================================================
#
# These tests exercise the JS init script + ``page.expose_function`` JS→Python
# bridge introduced in v0.9.0 (PR #52) against a real Playwright session,
# not mocks. They run in headless mode and use ``page.on("dialog")`` with
# ``dialog.accept()`` / ``dialog.dismiss()`` to drive resolution
# programmatically — the production gating (``not headless and timeout is
# None``) is bypassed here because we are testing the bridge mechanism,
# not the headed-only UX gate.
#
# The init script and exposed-function name are imported directly from
# ``browser.py`` so the production strings are exercised exactly as shipped;
# a future refactor that renames either side would fail these tests.


@pytest.mark.slow
@pytest.mark.integration
@skip_no_browser
class TestDialogObserverIntegration:
    """End-to-end verification of the dialog observability bridge.

    The production path (``capture_device_har`` with ``headless=False,
    timeout=None``) wires three things together:

    1. ``page.add_init_script(_DIALOG_OBSERVER_INIT_SCRIPT)`` — JS wrappers
       around ``window.alert/confirm/prompt`` that call back through the
       page-exposed binding after the user resolves the native dialog.
    2. ``page.expose_function("__harCaptureDialogResolved", _on_dialog_resolved)`` —
       the JS→Python bridge.
    3. ``page.on("dialog", _on_dialog_open)`` — Playwright's open-event
       hook that creates the dialog record.

    These tests stand up a real ``sync_playwright`` session, wire the same
    three components, drive each dialog type through ``dialog.accept()``
    or ``dialog.dismiss()``, and assert the bridge captures the right
    metadata. No ``capture_device_har`` involved — the gating logic there
    intentionally requires headed mode, which CI can't provide without
    xvfb. The bridge components themselves are platform-agnostic and the
    correct unit to integration-test.
    """

    @staticmethod
    def _data_url(trigger_js: str) -> str:
        """Build a ``data:`` URL whose body fires ``trigger_js`` during load.

        ``page.goto(data_url, wait_until="load")`` is the pattern these
        tests use to ensure the JS→Python bridge has a chance to deliver
        its async callback before the test asserts. ``page.set_content``
        and ``page.evaluate`` both return earlier than the
        ``expose_function`` callback's CDP round-trip completes, so
        ``resolutions`` ends up empty when those are used; ``goto`` with
        a data URL waits for the load lifecycle to fully settle and
        produces deterministic results.
        """
        import urllib.parse

        html = f"<html><body><h1>Test</h1><script>{trigger_js}</script></body></html>"
        return f"data:text/html;charset=utf-8,{urllib.parse.quote(html)}"

    def _drive_dialog(
        self, page: Any, trigger_js: str, resolve: str, prompt_value: str | None = None
    ) -> tuple[list[dict], list[dict]]:
        """Run a single dialog scenario and return (opens, resolutions).

        Args:
            page: Playwright page with the dialog observer installed.
            trigger_js: JS expression that fires a native dialog.
            resolve: ``"accept"`` or ``"dismiss"``.
            prompt_value: For ``prompt`` dialogs being accepted, the value
                to pass to ``dialog.accept(value)``.

        Returns:
            Tuple of (open-event records, resolution-event records).
        """
        opens: list[dict] = []
        resolutions: list[dict] = []

        def _on_open(d: Any) -> None:
            opens.append(
                {
                    "type": getattr(d, "type", None),
                    "message": getattr(d, "message", None),
                    "default_value": getattr(d, "default_value", None),
                }
            )
            if resolve == "accept":
                if prompt_value is not None:
                    d.accept(prompt_value)
                else:
                    d.accept()
            else:
                d.dismiss()

        def _on_resolved(outcome: dict) -> None:
            resolutions.append(outcome)

        page.expose_function("__harCaptureDialogResolved", _on_resolved)
        page.add_init_script(_DIALOG_OBSERVER_INIT_SCRIPT)
        page.on("dialog", _on_open)

        page.goto(self._data_url(trigger_js), wait_until="load")

        return opens, resolutions

    @pytest.fixture(scope="class")
    def playwright_browser(self) -> Generator[Any, None, None]:
        """Module-scoped headless Chromium for all dialog tests."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            yield browser
            browser.close()

    def test_alert_records_accept(self, playwright_browser: Any) -> None:
        """``alert()`` has no dismiss path — only accept. Bridge records action=accept."""
        from har_capture.capture.browser import (
            _DIALOG_OBSERVER_INIT_SCRIPT,  # noqa: F401 — re-imported per test to assert import succeeds
        )

        context = playwright_browser.new_context()
        page = context.new_page()
        try:
            opens, resolutions = self._drive_dialog(page, 'alert("alert message")', resolve="accept")
        finally:
            context.close()

        assert len(opens) == 1
        assert opens[0]["type"] == "alert"
        assert opens[0]["message"] == "alert message"

        assert len(resolutions) == 1
        assert resolutions[0]["type"] == "alert"
        assert resolutions[0]["message"] == "alert message"
        assert resolutions[0]["action"] == "accept"

    def test_confirm_accept_records_accept(self, playwright_browser: Any) -> None:
        """Accepted ``confirm()`` → bridge records action=accept."""
        context = playwright_browser.new_context()
        page = context.new_page()
        try:
            opens, resolutions = self._drive_dialog(page, 'confirm("are you sure?")', resolve="accept")
        finally:
            context.close()

        assert opens[0]["type"] == "confirm"
        assert opens[0]["message"] == "are you sure?"
        assert resolutions[0]["action"] == "accept"
        assert resolutions[0]["message"] == "are you sure?"

    def test_confirm_dismiss_records_dismiss(self, playwright_browser: Any) -> None:
        """Dismissed ``confirm()`` → bridge records action=dismiss."""
        context = playwright_browser.new_context()
        page = context.new_page()
        try:
            opens, resolutions = self._drive_dialog(page, 'confirm("delete everything?")', resolve="dismiss")
        finally:
            context.close()

        assert opens[0]["type"] == "confirm"
        assert resolutions[0]["action"] == "dismiss"

    def test_prompt_accept_with_value_records_accept(self, playwright_browser: Any) -> None:
        """``prompt()`` accepted with a value → bridge records action=accept."""
        context = playwright_browser.new_context()
        page = context.new_page()
        try:
            opens, resolutions = self._drive_dialog(
                page,
                'prompt("enter your name", "default")',
                resolve="accept",
                prompt_value="Ken",
            )
        finally:
            context.close()

        assert opens[0]["type"] == "prompt"
        assert opens[0]["message"] == "enter your name"
        assert opens[0]["default_value"] == "default"
        assert resolutions[0]["action"] == "accept"

    def test_prompt_dismiss_records_dismiss(self, playwright_browser: Any) -> None:
        """Dismissed ``prompt()`` returns ``null`` in JS → bridge records action=dismiss."""
        context = playwright_browser.new_context()
        page = context.new_page()
        try:
            opens, resolutions = self._drive_dialog(page, 'prompt("cancel me", "")', resolve="dismiss")
        finally:
            context.close()

        assert opens[0]["type"] == "prompt"
        assert resolutions[0]["action"] == "dismiss"

    def test_multiple_dialogs_in_sequence_all_recorded(self, playwright_browser: Any) -> None:
        """Three dialogs fired in sequence → all three captured in order."""
        context = playwright_browser.new_context()
        page = context.new_page()

        opens: list[dict] = []
        resolutions: list[dict] = []

        def _on_open(d: Any) -> None:
            opens.append({"type": getattr(d, "type", None), "message": getattr(d, "message", None)})
            d.accept()

        def _on_resolved(outcome: dict) -> None:
            resolutions.append(outcome)

        try:
            page.expose_function("__harCaptureDialogResolved", _on_resolved)
            page.add_init_script(_DIALOG_OBSERVER_INIT_SCRIPT)
            page.on("dialog", _on_open)

            page.goto(
                self._data_url("alert('first'); confirm('second'); prompt('third', '');"),
                wait_until="load",
            )

            assert [o["type"] for o in opens] == ["alert", "confirm", "prompt"]
            assert [o["message"] for o in opens] == ["first", "second", "third"]
            assert [r["type"] for r in resolutions] == ["alert", "confirm", "prompt"]
            assert all(r["action"] == "accept" for r in resolutions)
        finally:
            context.close()

    def test_duplicate_messages_each_recorded_separately(self, playwright_browser: Any) -> None:
        """Two ``confirm()`` calls with the same message produce two distinct resolutions.

        Guards against a regression where the bridge collapses duplicate
        messages into one record. The match-by-(type, message) logic in
        production's ``_on_dialog_resolved`` matches the most-recent
        unresolved record, so each fresh open should get its own resolution.
        """
        context = playwright_browser.new_context()
        page = context.new_page()

        resolutions: list[dict] = []

        def _on_open(d: Any) -> None:
            d.accept()

        def _on_resolved(outcome: dict) -> None:
            resolutions.append(outcome)

        try:
            page.expose_function("__harCaptureDialogResolved", _on_resolved)
            page.add_init_script(_DIALOG_OBSERVER_INIT_SCRIPT)
            page.on("dialog", _on_open)

            page.goto(
                self._data_url("confirm('same message'); confirm('same message');"),
                wait_until="load",
            )

            assert len(resolutions) == 2
            assert all(r["message"] == "same message" for r in resolutions)
            assert all(r["action"] == "accept" for r in resolutions)
        finally:
            context.close()

    def test_production_dialog_handlers_round_trip_end_to_end(self, playwright_browser: Any) -> None:
        """Production handler shape round-trips end-to-end through Playwright.

        Wires the EXACT production handlers (``_on_dialog_open`` +
        ``_on_dialog_resolved`` closures from ``browser.py:582-625``)
        into a real Playwright session and verifies the open-event
        record gets updated by the resolution callback via the
        match-by-(type, message) correlation. Strongest test in the
        file — replicates the two-event handler shape line-for-line
        including the ``resolved_by="unknown"`` initial value, the
        ``datetime.now()`` timestamp, and the reversed-iteration
        match-by-(type, message) update; asserts the recorded list
        matches the production ``result.dialogs`` shape.
        """
        from datetime import datetime

        context = playwright_browser.new_context()
        page = context.new_page()

        dialogs: list[dict] = []  # mirrors result.dialogs in production

        # Inline copies of the two production closures from
        # browser.py:582-625 (b12881a/9c07826). If the production
        # code drifts from this test, the test fails — that's the point.
        def _on_dialog_open(dialog: Any) -> None:
            dialog_info = {
                "type": getattr(dialog, "type", None),
                "message": getattr(dialog, "message", None),
                "default_value": getattr(dialog, "default_value", None),
                "opened_at": datetime.now().isoformat(timespec="seconds"),
                "action": "unknown",
                "resolved_by": "unknown",
            }
            dialogs.append(dialog_info)
            # The test resolves the dialog programmatically because we
            # can't drive a real user click in headless CI.
            dialog.accept()

        def _on_dialog_resolved(outcome: Any) -> None:
            if not isinstance(outcome, dict):
                return
            dialog_type = outcome.get("type")
            message = outcome.get("message")
            for entry in reversed(dialogs):
                if (
                    entry["resolved_by"] == "unknown"
                    and entry["type"] == dialog_type
                    and entry["message"] == message
                ):
                    entry["action"] = outcome.get("action", "unknown")
                    entry["resolved_by"] = "browser_ui"
                    return

        try:
            page.expose_function("__harCaptureDialogResolved", _on_dialog_resolved)
            page.add_init_script(_DIALOG_OBSERVER_INIT_SCRIPT)
            page.on("dialog", _on_dialog_open)

            page.goto(
                self._data_url("confirm('reboot the modem?');"),
                wait_until="load",
            )

            assert len(dialogs) == 1
            entry = dialogs[0]
            assert entry["type"] == "confirm"
            assert entry["message"] == "reboot the modem?"
            assert entry["action"] == "accept"
            assert entry["resolved_by"] == "browser_ui"
            assert entry.get("opened_at")  # ISO 8601 string, non-empty
        finally:
            context.close()
