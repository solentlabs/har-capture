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
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Skip all tests in this module if Playwright is not available
pytest.importorskip("playwright", reason="Playwright not installed")

from har_capture.capture import capture_device_har
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
                "<html><head><title>Page 2</title></head>"
                "<body><h1>Second Page</h1></body></html>"
            )
        elif self.path == "/api/data":
            self._send_json({"status": "ok", "value": 42})
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
        Base URL of the mock server (e.g., "127.0.0.1:8765")
    """
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    # Wait for server to be ready
    time.sleep(0.1)

    yield f"127.0.0.1:{port}"

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
            ip="192.0.2.1",  # TEST-NET-1, guaranteed unreachable
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

        reachable, _scheme, error = check_device_connectivity("192.0.2.1", timeout=2)

        assert reachable is False
        assert error is not None

    def test_check_basic_auth_no_auth(self, mock_server: str) -> None:
        """Test Basic Auth check for server without auth."""
        from har_capture.capture.connectivity import check_basic_auth

        requires_auth, realm = check_basic_auth(f"http://{mock_server}/")

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
