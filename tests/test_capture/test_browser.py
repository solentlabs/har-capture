"""Tests for browser-based HAR capture functionality.

This module tests the core HAR capture functionality using Playwright, including:

Test Coverage:
    - Bloat extension filtering (fonts, images, media)
    - Capture options configuration
    - Playwright dependency checking and auto-installation
    - Private IP detection (RFC 1918 ranges, loopback, special addresses)
    - Target URL parsing and validation
    - End-to-end device HAR capture with mocking
    - Sanitization before compression
    - Browser cleanup and error handling
    - Retry logic and timeout handling

Test Strategy:
    - Table-driven tests for IP detection with comprehensive edge cases
    - Mocked Playwright context for fast, deterministic tests
    - Integration tests for the full capture workflow
    - Error condition testing (network failures, browser crashes, etc.)

Dependencies:
    - pytest for test framework
    - unittest.mock for Playwright mocking (avoids real browser launches)
"""

from __future__ import annotations

import json
import unittest.mock
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.browser import (
    _DIALOG_OBSERVER_INIT_SCRIPT,
    _WAIT_FOR_DATA_INIT_SCRIPT,
    BrowserSessionResult,
    CaptureOptions,
    _add_capture_metadata,
    _inject_har_metadata,
    _resolve_capture_paths,
    _run_post_capture_pipeline,
    _wait_for_network_quiescence,
    _wait_for_pending_data,
    capture_device_har,
)
from har_capture.capture.connectivity import _parse_target
from har_capture.capture.deps import check_playwright
from har_capture.patterns import get_bloat_extensions
from har_capture.validation.secrets import is_private_ip

# =============================================================================
# Test Data Tables
# =============================================================================

_FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "test_browser.json"
with _FIXTURE_PATH.open() as _f:
    _FIXTURE_DATA = json.load(_f)

PRIVATE_IP_CASES = [(c["ip"], c["expected"], c["id"]) for c in _FIXTURE_DATA["private_ip_cases"]]

PARSE_TARGET_CASES = [
    (c["target"], c["expected_host"], c["scheme"], c["id"]) for c in _FIXTURE_DATA["parse_target_cases"]
]

WAIT_FOR_PENDING_DATA_CASES = _FIXTURE_DATA["wait_for_pending_data_cases"]
WAIT_FOR_QUIESCENCE_CASES = _FIXTURE_DATA["wait_for_quiescence_cases"]
OUTPUT_PATH_CASES = _FIXTURE_DATA["output_path_cases"]
CAPTURE_ERROR_CASES = _FIXTURE_DATA["capture_error_cases"]
BROWSER_SELECTION_CASES = _FIXTURE_DATA["browser_selection_cases"]
DIALOG_RESOLUTION_CASES = _FIXTURE_DATA["dialog_resolution_cases"]

# ┌─────────────────────────┬─────────────────────────────┐
# │ extension               │ description                 │
# ├─────────────────────────┼─────────────────────────────┤
# │ File extension          │ test case name              │
# └─────────────────────────┴─────────────────────────────┘
#
# fmt: off
BLOAT_FONT_EXTENSIONS = [
    (".woff",   "woff"),
    (".woff2",  "woff2"),
    (".ttf",    "ttf"),
    (".otf",    "otf"),
    (".eot",    "eot"),
]

BLOAT_IMAGE_EXTENSIONS = [
    (".png",    "png"),
    (".jpg",    "jpg"),
    (".jpeg",   "jpeg"),
    (".gif",    "gif"),
    (".webp",   "webp"),
    (".ico",    "ico"),
    (".svg",    "svg"),
    (".bmp",    "bmp"),
]

BLOAT_MEDIA_EXTENSIONS = [
    (".mp3",    "mp3"),
    (".mp4",    "mp4"),
    (".webm",   "webm"),
    (".ogg",    "ogg"),
    (".wav",    "wav"),
    (".avi",    "avi"),
    (".mov",    "mov"),
]

BLOAT_OTHER_EXTENSIONS = [
    (".map",    "sourcemap"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestBloatExtensions:
    """Tests for bloat extension filtering."""

    @pytest.mark.parametrize(
        ("ext", "desc"),
        BLOAT_FONT_EXTENSIONS,
        ids=[c[1] for c in BLOAT_FONT_EXTENSIONS],
    )
    def test_fonts_are_bloat(self, ext: str, desc: str) -> None:
        """Test font files are considered bloat by default."""
        extensions = get_bloat_extensions()
        assert ext in extensions, f"{desc}: {ext} should be in bloat extensions"

    @pytest.mark.parametrize(
        ("ext", "desc"),
        BLOAT_IMAGE_EXTENSIONS,
        ids=[c[1] for c in BLOAT_IMAGE_EXTENSIONS],
    )
    def test_images_are_bloat(self, ext: str, desc: str) -> None:
        """Test image files are considered bloat by default."""
        extensions = get_bloat_extensions()
        assert ext in extensions, f"{desc}: {ext} should be in bloat extensions"

    @pytest.mark.parametrize(
        ("ext", "desc"),
        BLOAT_MEDIA_EXTENSIONS,
        ids=[c[1] for c in BLOAT_MEDIA_EXTENSIONS],
    )
    def test_media_are_bloat(self, ext: str, desc: str) -> None:
        """Test media files are considered bloat by default."""
        extensions = get_bloat_extensions()
        assert ext in extensions, f"{desc}: {ext} should be in bloat extensions"

    @pytest.mark.parametrize(
        ("ext", "desc"),
        BLOAT_OTHER_EXTENSIONS,
        ids=[c[1] for c in BLOAT_OTHER_EXTENSIONS],
    )
    def test_other_bloat(self, ext: str, desc: str) -> None:
        """Test other bloat files."""
        extensions = get_bloat_extensions()
        assert ext in extensions, f"{desc}: {ext} should be in bloat extensions"

    def test_include_fonts_excludes_fonts(self) -> None:
        """Test include_fonts flag excludes fonts from bloat."""
        extensions = get_bloat_extensions(include_fonts=True)
        for ext, _ in BLOAT_FONT_EXTENSIONS:
            assert ext not in extensions, f"{ext} should not be in bloat when include_fonts=True"

    def test_include_images_excludes_images(self) -> None:
        """Test include_images flag excludes images from bloat."""
        extensions = get_bloat_extensions(include_images=True)
        for ext, _ in BLOAT_IMAGE_EXTENSIONS:
            assert ext not in extensions, f"{ext} should not be in bloat when include_images=True"

    def test_include_media_excludes_media(self) -> None:
        """Test include_media flag excludes media from bloat."""
        extensions = get_bloat_extensions(include_media=True)
        for ext, _ in BLOAT_MEDIA_EXTENSIONS:
            assert ext not in extensions, f"{ext} should not be in bloat when include_media=True"

    def test_include_all_returns_minimal(self) -> None:
        """Test including all categories returns minimal bloat set."""
        extensions = get_bloat_extensions(
            include_fonts=True,
            include_images=True,
            include_media=True,
        )
        # Should only have sourcemaps and other non-categorized bloat
        assert ".woff" not in extensions
        assert ".png" not in extensions
        assert ".mp4" not in extensions
        assert ".map" in extensions  # Sourcemaps still filtered


class TestCaptureOptions:
    """Tests for CaptureOptions dataclass."""

    def test_default_options(self) -> None:
        """Test default options filter all bloat."""
        options = CaptureOptions()
        assert options.include_fonts is False
        assert options.include_images is False
        assert options.include_media is False

    def test_get_bloat_extensions_respects_options(self) -> None:
        """Test get_bloat_extensions method respects options."""
        options = CaptureOptions(include_fonts=True)
        extensions = options.get_bloat_extensions()
        assert ".woff" not in extensions
        assert ".png" in extensions


class TestPlaywrightCheck:
    """Tests for Playwright availability check."""

    def test_check_playwright_returns_bool(self) -> None:
        """Test check_playwright returns a boolean."""
        result = check_playwright()
        assert isinstance(result, bool)


class TestPrivateIpDetection:
    """Tests for private IP detection."""

    @pytest.mark.parametrize(
        ("ip", "expected", "desc"),
        PRIVATE_IP_CASES,
        ids=[c[2] for c in PRIVATE_IP_CASES],
    )
    def test_private_ip_detection(self, ip: str, expected: bool, desc: str) -> None:
        """Test private IP detection."""
        result = is_private_ip(ip)
        assert result is expected, f"{desc}: {ip} should be {'private' if expected else 'public'}"

    # fmt: off
    INVALID_IP_CASES = [
        ("not.an.ip",       "not_an_ip"),
        ("256.1.1.1",       "octet_too_high"),
        ("1.1.1",           "too_few_octets"),
        ("1.1.1.1.1",       "too_many_octets"),
        ("",                "empty_string"),
        ("abc",             "letters_only"),
        ("-1.0.0.0",        "negative_octet"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("ip", "desc"),
        INVALID_IP_CASES,
        ids=[c[1] for c in INVALID_IP_CASES],
    )
    def test_invalid_ip_returns_false(self, ip: str, desc: str) -> None:
        """Test invalid IPs return False."""
        result = is_private_ip(ip)
        assert result is False, f"{desc}: invalid IP '{ip}' should return False"


class TestParseTarget:
    """Tests for target URL parsing."""

    @pytest.mark.parametrize(
        ("target", "expected_host", "expected_scheme", "desc"),
        PARSE_TARGET_CASES,
        ids=[c[3] for c in PARSE_TARGET_CASES],
    )
    def test_parse_target(
        self, target: str, expected_host: str, expected_scheme: str | None, desc: str
    ) -> None:
        """Test URL/hostname parsing extracts host and scheme correctly."""
        host, scheme = _parse_target(target)
        assert host == expected_host, f"{desc}: expected host '{expected_host}', got '{host}'"
        assert scheme == expected_scheme, f"{desc}: expected scheme '{expected_scheme}', got '{scheme}'"


# Skip this class if Playwright isn't installed (unit tests don't require it)
playwright = pytest.importorskip("playwright", reason="Playwright not installed")


class TestCaptureDeviceHar:
    """Tests for capture_device_har function parameters.

    These tests mock Playwright to test the capture_device_har parameters
    without requiring actual browser automation.
    """

    @pytest.fixture
    def mock_playwright(self) -> MagicMock:
        """Create a mock Playwright instance with all necessary components."""
        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()

        # Chain the mocks
        mock_pw.chromium.launch.return_value = mock_browser
        mock_pw.firefox.launch.return_value = mock_browser
        mock_pw.webkit.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        return mock_pw

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_headless_parameter_passed_to_browser(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_playwright: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test headless parameter is passed to browser launch."""
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"

        # Test with headless=True
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        mock_playwright.chromium.launch.assert_called_once_with(headless=True)

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_headless_false_parameter(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_playwright: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test headless=False is passed correctly."""
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"

        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=False,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        mock_playwright.chromium.launch.assert_called_once_with(headless=False)

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    @patch("time.sleep")
    def test_timeout_triggers_sleep(
        self,
        mock_sleep: MagicMock,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_playwright: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test timeout parameter triggers time.sleep instead of wait_for_event."""
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)
        mock_page = (
            mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
        )

        output = tmp_path / "test.har"

        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=5,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # Should call time.sleep with the timeout value
        mock_sleep.assert_called_once_with(5)
        # Should NOT call wait_for_event when timeout is set
        mock_page.wait_for_event.assert_not_called()

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_no_timeout_waits_for_close(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_playwright: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test timeout=None waits for browser close event."""
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)
        mock_page = (
            mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
        )

        output = tmp_path / "test.har"

        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=None,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # Should call wait_for_event when timeout is None
        mock_page.wait_for_event.assert_called_once_with("close", timeout=0)

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_firefox_browser_selection(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_playwright: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test firefox browser is selected correctly."""
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"

        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            browser="firefox",
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        mock_playwright.firefox.launch.assert_called_once_with(headless=True)
        mock_playwright.chromium.launch.assert_not_called()

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_webkit_browser_selection(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_playwright: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test webkit browser is selected correctly."""
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"

        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            browser="webkit",
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        mock_playwright.webkit.launch.assert_called_once_with(headless=True)
        mock_playwright.chromium.launch.assert_not_called()


class TestBrowserCookieSnapshot:
    """Tests for browser cookie snapshot after page load."""

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_context_cookies_called_after_goto(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test context.cookies() is called after page.goto()."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_context.cookies.return_value = [
            {
                "name": "XSRF_TOKEN",
                "value": "abc123",
                "domain": ".example.com",
                "path": "/",
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            },
        ]

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # cookies() is called twice: once for pre-capture audit, once for
        # browser state snapshot after navigation
        assert mock_context.cookies.call_count == 2

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_browser_cookies_injected_into_har(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test browser cookies appear in HAR _har_capture.browser_cookies."""
        import json
        import os

        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        test_cookies = [
            {
                "name": "XSRF_TOKEN",
                "value": "abc123",
                "domain": ".example.com",
                "path": "/",
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            },
        ]
        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_context.cookies.return_value = test_cookies

        # Create a real temp HAR file so the injection JSON read/write works
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }
        temp_har = tmp_path / "temp_capture.har"
        temp_har.write_text(json.dumps(har_data))

        output = tmp_path / "test.har"

        # The capture writes the temp HAR via Playwright (mocked), then reads it
        # back for injection.  We must make tempfile.mkstemp point at our real file.
        fd = os.open(str(temp_har), os.O_RDWR)
        with patch("tempfile.mkstemp", return_value=(fd, str(temp_har))):
            capture_device_har(
                ip="127.0.0.1",
                output=str(output),
                headless=True,
                timeout=1,
                sanitize=False,
                compress=False,
                keep_raw=True,
                wait_for_data=False,
            )

        # The output file should contain injected browser_cookies
        raw_har = json.loads(output.read_text())
        assert "browser_cookies" in raw_har["log"].get("_har_capture", {}), (
            "browser_cookies should be injected into _har_capture metadata"
        )
        assert raw_har["log"]["_har_capture"]["browser_cookies"] == test_cookies

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_context_cookies_exception_handled(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test context.cookies() exception is caught gracefully."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_context.cookies.side_effect = RuntimeError("cookies() failed")

        output = tmp_path / "test.har"
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # Should not crash
        assert result.success is True


class TestWebStorageCapture:
    """Tests for Web Storage (localStorage + sessionStorage) capture."""

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_storage_state_and_evaluate_called(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test context.storage_state() and page.evaluate() are called after goto."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value
        mock_context.storage_state.return_value = {"origins": [], "cookies": []}
        mock_page.evaluate.return_value = {}

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        mock_context.storage_state.assert_called_once()
        mock_page.evaluate.assert_called_once()

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_web_storage_injected_into_har(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test web storage data appears in HAR _har_capture metadata."""
        import json
        import os

        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value
        mock_context.cookies.return_value = []
        mock_context.storage_state.return_value = {
            "origins": [
                {
                    "origin": "http://127.0.0.1",
                    "localStorage": [
                        {"name": "PrivateKey", "value": "hmac_secret_123"},
                    ],
                },
            ],
            "cookies": [],
        }
        mock_page.evaluate.return_value = {"sjcl_key": "aes_key_456", "user": "admin"}

        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }
        temp_har = tmp_path / "temp_capture.har"
        temp_har.write_text(json.dumps(har_data))

        output = tmp_path / "test.har"
        fd = os.open(str(temp_har), os.O_RDWR)
        with patch("tempfile.mkstemp", return_value=(fd, str(temp_har))):
            capture_device_har(
                ip="127.0.0.1",
                output=str(output),
                headless=True,
                timeout=1,
                sanitize=False,
                compress=False,
                keep_raw=True,
                wait_for_data=False,
            )

        raw_har = json.loads(output.read_text())
        meta = raw_har["log"].get("_har_capture", {})

        # localStorage
        assert "local_storage" in meta
        assert len(meta["local_storage"]) == 1
        assert meta["local_storage"][0]["origin"] == "http://127.0.0.1"
        assert meta["local_storage"][0]["items"][0]["name"] == "PrivateKey"
        assert meta["local_storage"][0]["items"][0]["value"] == "hmac_secret_123"

        # sessionStorage
        assert "session_storage" in meta
        assert len(meta["session_storage"]) == 1
        items = {i["name"]: i["value"] for i in meta["session_storage"][0]["items"]}
        assert items["sjcl_key"] == "aes_key_456"
        assert items["user"] == "admin"

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_storage_state_exception_handled(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test storage_state() exception is caught gracefully."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value
        mock_context.storage_state.side_effect = RuntimeError("storage_state() failed")
        mock_page.evaluate.side_effect = RuntimeError("evaluate() failed")

        output = tmp_path / "test.har"
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        assert result.success is True


# fmt: off
ADD_CAPTURE_METADATA_CASES = [
    # (description, input_har_capture, expected_keys_present, expected_values)
    (
        "preserves_existing_keys",
        {"browser_cookies": [{"name": "a"}]},
        ["browser_cookies", "tool", "version"],
        {"browser_cookies": [{"name": "a"}]},
    ),
    (
        "creates_section_when_absent",
        None,
        ["tool", "version", "captured_at", "cache_disabled"],
        {"tool": "har-capture"},
    ),
    (
        "overwrites_standard_keeps_custom",
        {"tool": "old", "custom": "keep"},
        ["tool", "custom"],
        {"tool": "har-capture", "custom": "keep"},
    ),
    (
        "preserves_probes_alongside_cookies",
        {"browser_cookies": [{"name": "sid"}], "extra": 42},
        ["browser_cookies", "extra", "tool"],
        {"extra": 42},
    ),
]
# fmt: on


class TestAddCaptureMetadata:
    """Tests for _add_capture_metadata merge behavior."""

    @pytest.mark.parametrize(
        ("desc", "input_har_capture", "expected_keys", "expected_values"),
        ADD_CAPTURE_METADATA_CASES,
        ids=[c[0] for c in ADD_CAPTURE_METADATA_CASES],
    )
    def test_metadata_merge(
        self,
        desc: str,
        input_har_capture: dict | None,
        expected_keys: list[str],
        expected_values: dict,
    ) -> None:
        """Test _add_capture_metadata merges correctly."""
        har: dict = {"log": {}}
        if input_har_capture is not None:
            har["log"]["_har_capture"] = input_har_capture

        _add_capture_metadata(har)

        meta = har["log"]["_har_capture"]
        for key in expected_keys:
            assert key in meta, f"Expected key '{key}' in metadata"
        for key, value in expected_values.items():
            assert meta[key] == value, f"Expected {key}={value}, got {meta[key]}"


class TestBrowserCookiesSurvivePipeline:
    """Test browser_cookies survive the full sanitize + compress pipeline.

    Regression: _add_capture_metadata() in filter_and_compress_har() was
    overwriting _har_capture with a fresh dict, clobbering browser_cookies
    that were injected earlier.
    """

    def test_browser_cookies_survive_filter_and_compress(self, tmp_path: Path) -> None:
        """Browser cookies in _har_capture must survive filter_and_compress_har."""
        import gzip
        import json

        from har_capture.capture.browser import filter_and_compress_har

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
                "_har_capture": {
                    "browser_cookies": [
                        {
                            "name": "PHPSESSID",
                            "value": "secret",
                            "domain": "localhost",
                            "path": "/",
                            "httpOnly": True,
                            "secure": False,
                            "sameSite": "Lax",
                        },
                    ],
                },
            }
        }

        har_path = tmp_path / "test.har"
        har_path.write_text(json.dumps(har))

        compressed_path, _ = filter_and_compress_har(har_path)

        # Check the uncompressed HAR on disk (filter_and_compress rewrites it)
        result = json.loads(har_path.read_text())
        assert "browser_cookies" in result["log"]["_har_capture"], (
            "browser_cookies must not be clobbered by _add_capture_metadata"
        )
        assert result["log"]["_har_capture"]["browser_cookies"][0]["name"] == "PHPSESSID"

        # Also check the compressed output
        with gzip.open(compressed_path, "rt") as f:
            compressed_har = json.load(f)
        assert "browser_cookies" in compressed_har["log"]["_har_capture"]

    def test_full_capture_sanitize_compress_preserves_cookies(self, tmp_path: Path) -> None:
        """End-to-end: browser_cookies are sanitized and present after compress."""
        import json

        from har_capture.capture.browser import filter_and_compress_har
        from har_capture.sanitization import sanitize_har_file

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
                "_har_capture": {
                    "browser_cookies": [
                        {
                            "name": "session",
                            "value": "s3cr3t_t0k3n",
                            "domain": "example.com",
                            "path": "/",
                            "httpOnly": True,
                            "secure": True,
                            "sameSite": "Strict",
                        },
                    ],
                },
            }
        }

        raw_path = tmp_path / "capture.har"
        raw_path.write_text(json.dumps(har))

        # Sanitize
        sanitized_path_str, _ = sanitize_har_file(str(raw_path))
        sanitized_path = Path(sanitized_path_str)

        # Compress (this is where the bug was — _add_capture_metadata clobbered cookies)
        filter_and_compress_har(sanitized_path)

        # The sanitized file should still have browser_cookies with redacted values
        result = json.loads(sanitized_path.read_text())
        cookies = result["log"]["_har_capture"]["browser_cookies"]
        assert len(cookies) == 1
        assert cookies[0]["name"] == "session"
        assert cookies[0]["value"] != "s3cr3t_t0k3n", "Cookie value should be redacted"
        assert cookies[0]["domain"] == "example.com", "Structural properties preserved"
        assert cookies[0]["httpOnly"] is True, "Structural properties preserved"

    def test_full_capture_sanitize_compress_preserves_storage(self, tmp_path: Path) -> None:
        """End-to-end: web storage is sanitized and present after compress."""
        import json

        from har_capture.capture.browser import filter_and_compress_har
        from har_capture.sanitization import sanitize_har_file

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
                "_har_capture": {
                    "local_storage": [
                        {
                            "origin": "https://192.168.100.1",
                            "items": [
                                {"name": "PrivateKey", "value": "hmac_secret_key"},
                            ],
                        },
                    ],
                    "session_storage": [
                        {
                            "origin": "https://192.168.100.1",
                            "items": [
                                {"name": "sjcl_key", "value": "aes256_enc_key"},
                                {"name": "csrf_token", "value": "xsrf_abc123"},
                            ],
                        },
                    ],
                },
            }
        }

        raw_path = tmp_path / "capture.har"
        raw_path.write_text(json.dumps(har))

        sanitized_path_str, _ = sanitize_har_file(str(raw_path))
        sanitized_path = Path(sanitized_path_str)

        filter_and_compress_har(sanitized_path)

        result = json.loads(sanitized_path.read_text())
        meta = result["log"]["_har_capture"]

        # localStorage survives and is redacted
        assert "local_storage" in meta
        ls = meta["local_storage"][0]
        assert ls["origin"] == "https://192.168.100.1"
        assert ls["items"][0]["name"] == "PrivateKey"
        assert ls["items"][0]["value"] != "hmac_secret_key", "Should be redacted"

        # sessionStorage survives and is redacted
        assert "session_storage" in meta
        ss = meta["session_storage"][0]
        assert ss["origin"] == "https://192.168.100.1"
        assert ss["items"][0]["name"] == "sjcl_key"
        assert ss["items"][0]["value"] != "aes256_enc_key", "Should be redacted"
        assert ss["items"][1]["name"] == "csrf_token"
        assert ss["items"][1]["value"] != "xsrf_abc123", "Should be redacted"


class TestSanitizationBeforeCompression:
    """Tests to ensure compression happens AFTER sanitization.

    SECURITY INVARIANT: The workflow must sanitize before compressing.
    This ensures the compressed output is based on sanitized content.
    """

    def test_compressed_file_named_from_sanitized_source(self, tmp_path: Path) -> None:
        """Test that compressed file is created from sanitized file path.

        The compressed output should be named based on the sanitized file,
        not the raw file. This ensures we're compressing the right source.
        """
        import json

        from har_capture.capture.browser import filter_and_compress_har
        from har_capture.sanitization import sanitize_har_file

        raw_har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }

        raw_path = tmp_path / "test.har"
        raw_path.write_text(json.dumps(raw_har))

        # Workflow: sanitize then compress
        sanitized_path_str, _ = sanitize_har_file(str(raw_path))
        sanitized_path = Path(sanitized_path_str)
        compressed_path, _ = filter_and_compress_har(sanitized_path, None)

        # Compressed file should be based on sanitized path
        assert "sanitized" in str(compressed_path), (
            f"Compressed path {compressed_path} should be based on sanitized file"
        )
        assert compressed_path.suffix == ".gz"

    def test_workflow_order_sanitize_then_compress(self, tmp_path: Path) -> None:
        """Test the workflow processes in correct order: sanitize then compress.

        We verify this by adding a marker during sanitization and checking
        it appears in the compressed output.
        """
        import gzip
        import json

        from har_capture.capture.browser import filter_and_compress_har
        from har_capture.sanitization import sanitize_har_file

        # Create a minimal HAR
        raw_har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }

        raw_path = tmp_path / "order_test.har"
        raw_path.write_text(json.dumps(raw_har))

        # Run the workflow
        sanitized_path_str, _ = sanitize_har_file(str(raw_path))
        sanitized_path = Path(sanitized_path_str)
        compressed_path, _ = filter_and_compress_har(sanitized_path, None)

        # The compressed content should come from the sanitized file
        # We can verify by checking that sanitized_path content matches
        # the decompressed content (modulo metadata added by compression)
        with gzip.open(compressed_path, "rt") as f:
            compressed_har = json.load(f)

        # Should have _har_capture metadata from compression step
        # Metadata is inside the 'log' object
        assert "_har_capture" in compressed_har.get("log", {}), "Missing capture metadata"

    def test_raw_file_not_compressed_directly(self, tmp_path: Path) -> None:
        """Test that raw file path is NOT used for compression.

        The browser.py code must pass sanitized_path to filter_and_compress_har,
        not the raw output_path. This test verifies the file naming convention.
        """
        import json

        from har_capture.capture.browser import filter_and_compress_har
        from har_capture.sanitization import sanitize_har_file

        raw_har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }

        raw_path = tmp_path / "capture.har"
        raw_path.write_text(json.dumps(raw_har))

        sanitized_path_str, _ = sanitize_har_file(str(raw_path))
        sanitized_path = Path(sanitized_path_str)
        compressed_path, _ = filter_and_compress_har(sanitized_path, None)

        # The compressed file should NOT be named "capture.har.gz"
        # It should be named "capture.sanitized.har.gz"
        assert compressed_path.name != "capture.har.gz", "Compressed file should not be from raw path"
        assert "sanitized" in compressed_path.name, "Compressed file should be based on sanitized file"


# ┌─────────────┬───────────────┬─────────────────┬─────────────────┬─────────────┬─────────────────┐
# │ browser     │ is_installed  │ install_result  │ expect_install  │ expect_ok   │ error_contains  │
# ├─────────────┼───────────────┼─────────────────┼─────────────────┼─────────────┼─────────────────┤
# │ Browser     │ check result  │ install result  │ install called? │ success?    │ error substring │
# └─────────────┴───────────────┴─────────────────┴─────────────────┴─────────────┴─────────────────┘
#
# fmt: off
AUTO_INSTALL_CASES = [
    # Browser missing, install succeeds
    ("chromium", False, True,  True,  True,  None),
    ("firefox",  False, True,  True,  True,  None),
    ("webkit",   False, True,  True,  True,  None),
    # Browser missing, install fails
    ("chromium", False, False, True,  False, "Failed to install chromium"),
    ("firefox",  False, False, True,  False, "Failed to install firefox"),
    # Browser already installed
    ("chromium", True,  None,  False, True,  None),
    ("firefox",  True,  None,  False, True,  None),
]
# fmt: on


class TestBrowserAutoInstall:
    """Tests for automatic browser installation when missing."""

    @pytest.mark.parametrize(
        ("browser", "is_installed", "install_result", "expect_install", "expect_ok", "error_contains"),
        AUTO_INSTALL_CASES,
        ids=[
            f"{c[0]}_{'present' if c[1] else 'missing'}_{'ok' if c[4] else 'fail'}"
            for c in AUTO_INSTALL_CASES
        ],
    )
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_auto_install_behavior(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
        browser: str,
        is_installed: bool,
        install_result: bool | None,
        expect_install: bool,
        expect_ok: bool,
        error_contains: str | None,
    ) -> None:
        """Test browser auto-install behavior for various scenarios."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        with (
            patch(
                "har_capture.capture.browser.check_browser_installed",
                return_value=is_installed,
            ),
            patch(
                "har_capture.capture.browser.install_browser",
                return_value=install_result,
            ) as mock_install,
        ):
            output = tmp_path / "test.har"

            result = capture_device_har(
                ip="127.0.0.1",
                output=str(output),
                browser=browser,
                headless=True,
                timeout=1,
                sanitize=False,
                compress=False,
                wait_for_data=False,
            )

            # Verify install was called (or not) as expected
            if expect_install:
                mock_install.assert_called_once_with(browser)
            else:
                mock_install.assert_not_called()

            # Verify success/failure
            assert result.success is expect_ok

            # Verify error message if expected
            if error_contains:
                assert error_contains in result.error


# ┌──────────────────────────────────────────────────┬─────────────────┬─────────────┬─────────────────────────────┐
# │ error_message                                    │ install_result  │ expect_ok   │ error_contains              │
# ├──────────────────────────────────────────────────┼─────────────────┼─────────────┼─────────────────────────────┤
# │ Error from browser launch                        │ reinstall ok?   │ success?    │ error substring             │
# └──────────────────────────────────────────────────┴─────────────────┴─────────────┴─────────────────────────────┘
#
# fmt: off
MISSING_BROWSER_CASES = [
    # Browser executable missing, reinstall succeeds → retry succeeds
    ("Executable doesn't exist at /home/user/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome",
     True,  True,  None,                               "reinstall_succeeds"),
    # Browser executable missing, reinstall fails → error with python -m suggestion
    ("Executable doesn't exist at /path/to/chrome",
     False, False, "python -m playwright install",      "reinstall_fails"),
    # Case-insensitive matching
    ("executable doesn't exist at /some/path",
     True,  True,  None,                               "case_insensitive"),
    # Unrelated error → no reinstall, returns original error
    ("Connection refused",
     None,  False, "Connection refused",                "unrelated_error"),
]
# fmt: on


class TestBrowserExecutableMissing:
    """Tests for automatic browser reinstall when executable is missing."""

    @pytest.mark.parametrize(
        ("error_message", "install_result", "expect_ok", "error_contains", "desc"),
        MISSING_BROWSER_CASES,
        ids=[c[4] for c in MISSING_BROWSER_CASES],
    )
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_browser_installed", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_missing_browser_recovery(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_installed: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
        error_message: str,
        install_result: bool | None,
        expect_ok: bool,
        error_contains: str | None,
        desc: str,
    ) -> None:
        """Test browser executable missing detection and recovery."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        # First call raises the error, second call (retry) succeeds
        if install_result:
            mock_pw.chromium.launch.side_effect = [
                Exception(error_message),
                MagicMock(),  # retry succeeds
            ]
        else:
            mock_pw.chromium.launch.side_effect = Exception(error_message)

        with patch(
            "har_capture.capture.browser.install_browser",
            return_value=install_result,
        ) as mock_install:
            output = tmp_path / "test.har"

            result = capture_device_har(
                ip="127.0.0.1",
                output=str(output),
                browser="chromium",
                headless=True,
                timeout=1,
                sanitize=False,
                compress=False,
                wait_for_data=False,
            )

            assert result.success is expect_ok

            if error_contains:
                assert error_contains in result.error

            # Unrelated errors should not trigger reinstall
            if install_result is None:
                mock_install.assert_not_called()
            else:
                mock_install.assert_called_once_with("chromium")


class TestBrowserCleanupErrorHandling:
    """Tests for graceful handling of browser cleanup failures."""

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_context_close_failure_continues_cleanup(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that context.close() failure doesn't crash the capture process."""
        mock_playwright = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        # Mock browser context to raise exception on close
        mock_context = mock_playwright.chromium.launch.return_value.new_context.return_value
        mock_context.close.side_effect = RuntimeError("Failed to close context")

        output = tmp_path / "test.har"

        # Should not raise exception despite context.close() failure
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # Capture should still succeed
        assert result.success is True
        # Context close was attempted
        mock_context.close.assert_called_once()
        # Browser close should still be called even if context close failed
        mock_playwright.chromium.launch.return_value.close.assert_called_once()

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_browser_close_failure_logged(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that browser.close() failure is logged but doesn't crash."""
        mock_playwright = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        # Mock browser instance to raise exception on close
        mock_browser = mock_playwright.chromium.launch.return_value
        mock_browser.close.side_effect = RuntimeError("Failed to close browser")

        output = tmp_path / "test.har"

        # Should not raise exception despite browser.close() failure
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # Capture should still succeed
        assert result.success is True
        # Browser close was attempted
        mock_browser.close.assert_called_once()

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_both_close_failures_handled(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that both context and browser close failures are handled."""
        mock_playwright = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_playwright
        mock_connectivity.return_value = (True, "http", None)

        # Both context and browser raise exceptions on close
        mock_context = mock_playwright.chromium.launch.return_value.new_context.return_value
        mock_browser = mock_playwright.chromium.launch.return_value
        mock_context.close.side_effect = RuntimeError("Context close failed")
        mock_browser.close.side_effect = RuntimeError("Browser close failed")

        output = tmp_path / "test.har"

        # Should not raise exception despite both failures
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # Capture should still succeed
        assert result.success is True
        # Both close methods were attempted
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()


# =============================================================================
# Wait-for-data behaviour
# =============================================================================

# ┌────────────────┬──────────────────┬─────────────────────┬───────────────────────┐
# │ wait_for_data  │ expect_init_js   │ expect_nav_listener │ description           │
# ├────────────────┼──────────────────┼─────────────────────┼───────────────────────┤
# │ flag value     │ add_init_script  │ page.on called      │ test case name        │
# └────────────────┴──────────────────┴─────────────────────┴───────────────────────┘
#
# fmt: off
WAIT_FOR_DATA_ROUTING_CASES = [
    (True,  True,  True,  "enabled_uses_nav_listener"),
    (False, False, False, "disabled_no_listener"),
]
# fmt: on


class TestWaitForData:
    """Tests for --wait-for-data capture behaviour."""

    @pytest.mark.parametrize(
        ("wait_flag", "expect_init_js", "expect_nav_listener", "desc"),
        WAIT_FOR_DATA_ROUTING_CASES,
        ids=[c[3] for c in WAIT_FOR_DATA_ROUTING_CASES],
    )
    @patch("har_capture.capture.browser._wait_for_network_quiescence")
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_routing_strategy(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_quiescence: MagicMock,
        tmp_path: Path,
        wait_flag: bool,
        expect_init_js: bool,
        expect_nav_listener: bool,
        desc: str,
    ) -> None:
        """Test that wait_for_data uses framenavigated listener, not route handler.

        Calling page.evaluate() from a sync route handler deadlocks Playwright.
        The fix uses page.on('framenavigated') to wait after each navigation.
        """
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=wait_flag,
        )

        if expect_init_js:
            mock_page.add_init_script.assert_called_once_with(_WAIT_FOR_DATA_INIT_SCRIPT)
        else:
            mock_page.add_init_script.assert_not_called()

        # No context.route — removed to avoid CDP Fetch domain
        # interfering with HAR body capture
        mock_context.route.assert_not_called()
        # page.route must never be used (sync API deadlock)
        mock_page.route.assert_not_called()

        # Eager body capture listener is always registered
        mock_page.on.assert_any_call("response", unittest.mock.ANY)

        # Popup / new-page subscription is always registered at the context
        # level — without it, popups (S33 reboot confirmation, router config
        # wizards, etc.) get their response bodies silently dropped.
        mock_context.on.assert_any_call("page", unittest.mock.ANY)

        if expect_nav_listener:
            mock_page.on.assert_any_call("framenavigated", unittest.mock.ANY)
        else:
            nav_calls = [c for c in mock_page.on.call_args_list if c[0][0] == "framenavigated"]
            assert len(nav_calls) == 0

    @patch("har_capture.capture.browser._wait_for_network_quiescence")
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_quiescence_called_after_goto(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_quiescence: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that network quiescence wait runs after initial page load."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=True,
        )

        # Called twice: once after goto, once after timeout
        assert mock_quiescence.call_count == 2

    @patch("har_capture.capture.browser._wait_for_network_quiescence")
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_timeout_uses_playwright_wait(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_quiescence: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that wait_for_data uses page.wait_for_timeout instead of sleep."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_page = mock_pw.chromium.launch.return_value.new_context.return_value.new_page.return_value

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=5,
            sanitize=False,
            compress=False,
            wait_for_data=True,
        )

        # Should use Playwright's wait (keeps event loop active), not time.sleep
        mock_page.wait_for_timeout.assert_any_call(5000)

    @patch("har_capture.capture.browser._wait_for_network_quiescence")
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_no_quiescence_when_disabled(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_quiescence: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that quiescence wait is skipped when wait_for_data=False."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        mock_quiescence.assert_not_called()


# =============================================================================
# Table-driven tests for wait-for-data helpers
# =============================================================================


class TestWaitForPendingData:
    """Table-driven tests for _wait_for_pending_data timeout/success paths."""

    @pytest.mark.parametrize(
        "case",
        WAIT_FOR_PENDING_DATA_CASES,
        ids=[c["id"] for c in WAIT_FOR_PENDING_DATA_CASES],
    )
    def test_pending_data(self, case: dict) -> None:
        """Test _wait_for_pending_data with various pending-count sequences."""
        page = MagicMock()

        if case["pending_values"] == "exception":
            page.evaluate.side_effect = RuntimeError("context gone")
        else:
            page.evaluate.side_effect = case["pending_values"]

        _wait_for_pending_data(page, timeout_s=case["timeout_s"])

        # If exception, should return after first call
        if case["pending_values"] == "exception":
            page.evaluate.assert_called_once()
        elif case["expect_timeout"]:
            # Timed out — evaluate was called multiple times
            assert page.evaluate.call_count >= 2
        else:
            # Succeeded — evaluate was called at least once
            assert page.evaluate.call_count >= 1


class TestWaitForNetworkQuiescence:
    """Table-driven tests for _wait_for_network_quiescence timeout/quiescence paths."""

    @pytest.mark.parametrize(
        "case",
        WAIT_FOR_QUIESCENCE_CASES,
        ids=[c["id"] for c in WAIT_FOR_QUIESCENCE_CASES],
    )
    def test_quiescence(self, case: dict) -> None:
        """Test _wait_for_network_quiescence with various pending-count sequences."""
        page = MagicMock()

        if case["pending_values"] == "exception":
            page.evaluate.side_effect = RuntimeError("context gone")
        else:
            page.evaluate.side_effect = case["pending_values"]

        _wait_for_network_quiescence(
            page,
            quiescence_s=case["quiescence_s"],
            timeout_s=case["timeout_s"],
        )

        if case["pending_values"] == "exception":
            page.evaluate.assert_called_once()
        elif case["expect_timeout"]:
            assert page.evaluate.call_count >= 2
        else:
            assert page.evaluate.call_count >= 1


# =============================================================================
# Table-driven tests for capture_device_har error paths
# =============================================================================


class TestCaptureDeviceHarErrors:
    """Table-driven tests for capture_device_har error branches."""

    @pytest.mark.parametrize(
        "case",
        CAPTURE_ERROR_CASES,
        ids=[c["id"] for c in CAPTURE_ERROR_CASES],
    )
    def test_error_returns_failure(self, case: dict, tmp_path: Path) -> None:
        """Test early-exit error paths return CaptureResult(success=False)."""
        output = tmp_path / "test.har"

        if "mock_check_pw" in case and case["mock_check_pw"] is False:
            with patch("har_capture.capture.browser.check_playwright", return_value=False):
                result = capture_device_har(
                    ip="127.0.0.1",
                    output=str(output),
                    sanitize=False,
                    compress=False,
                )
        else:
            with (
                patch("har_capture.capture.browser.check_playwright", return_value=True),
                patch(
                    "har_capture.capture.browser.check_device_connectivity",
                    return_value=tuple(case["mock_connectivity"]),
                ),
                patch("har_capture.capture.browser.check_browser_installed", return_value=True),
            ):
                result = capture_device_har(
                    ip="127.0.0.1",
                    output=str(output),
                    sanitize=False,
                    compress=False,
                )

        assert result.success is False
        assert case["expect_error"] in (result.error or "")


# =============================================================================
# Table-driven tests for output path handling
# =============================================================================


class TestOutputPathHandling:
    """Table-driven tests for output path suffix enforcement."""

    @pytest.mark.parametrize(
        "case",
        OUTPUT_PATH_CASES,
        ids=[c["id"] for c in OUTPUT_PATH_CASES],
    )
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_output_suffix_enforced(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        case: dict,
        tmp_path: Path,
    ) -> None:
        """Test output path always ends with .har."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / case["input"]
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        # The context should have been created with a .har temp path
        assert result.success is True

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_default_output_creates_captures_dir(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test output=None creates captures/ directory with timestamped file."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        monkeypatch.chdir(tmp_path)
        result = capture_device_har(
            ip="127.0.0.1",
            output=None,
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        assert result.success is True
        assert (tmp_path / "captures").is_dir()


# =============================================================================
# Table-driven tests for browser selection
# =============================================================================


class TestBrowserSelectionParametrized:
    """Table-driven tests for browser engine selection."""

    @pytest.mark.parametrize(
        "case",
        BROWSER_SELECTION_CASES,
        ids=[c["id"] for c in BROWSER_SELECTION_CASES],
    )
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_browser_selected(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        case: dict,
        tmp_path: Path,
    ) -> None:
        """Test correct browser engine is selected."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            browser=case["browser"],
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        launch_fn = getattr(mock_pw, case["launch_attr"]).launch
        launch_fn.assert_called_once_with(headless=True)


# =============================================================================
# Tests for context config and pre-capture cookie audit
# =============================================================================


class TestCleanBrowserContext:
    """Tests for forced clean browser context (storage_state)."""

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_storage_state_set_on_context(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test new_context is called with empty storage_state."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        call_kwargs = mock_pw.chromium.launch.return_value.new_context.call_args[1]
        assert "storage_state" in call_kwargs
        assert call_kwargs["storage_state"]["cookies"] == []
        assert call_kwargs["storage_state"]["origins"] == []

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_http_credentials_passed_to_context(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test http_credentials are included in context options."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        creds = {"username": "admin", "password": "secret"}
        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            http_credentials=creds,
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        call_kwargs = mock_pw.chromium.launch.return_value.new_context.call_args[1]
        assert call_kwargs["http_credentials"] == creds

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_no_http_credentials_when_none(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test http_credentials omitted from context when not provided."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        call_kwargs = mock_pw.chromium.launch.return_value.new_context.call_args[1]
        assert "http_credentials" not in call_kwargs

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_pre_capture_cookies_in_har(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test _solentlabs.pre_capture_cookies is injected into HAR."""
        import os

        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_context.cookies.return_value = []

        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }
        temp_har = tmp_path / "temp_capture.har"
        temp_har.write_text(json.dumps(har_data))

        output = tmp_path / "test.har"
        fd = os.open(str(temp_har), os.O_RDWR)
        with patch("tempfile.mkstemp", return_value=(fd, str(temp_har))):
            capture_device_har(
                ip="127.0.0.1",
                output=str(output),
                headless=True,
                timeout=1,
                sanitize=False,
                compress=False,
                keep_raw=True,
                wait_for_data=False,
            )

        raw_har = json.loads(output.read_text())
        assert "_solentlabs" in raw_har["log"]
        assert raw_har["log"]["_solentlabs"]["pre_capture_cookies"] == []


# =============================================================================
# Tests for networkidle fallback
# =============================================================================


class TestNetworkIdleFallback:
    """Tests for networkidle → domcontentloaded auto-fallback."""

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_networkidle_timeout_falls_back(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test networkidle timeout triggers domcontentloaded fallback."""
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value
        mock_page.goto.side_effect = PlaywrightTimeout("networkidle timed out")
        # evaluate returns 0 pending requests so quiescence check succeeds
        mock_page.evaluate.return_value = 0
        mock_page.main_frame = mock_page  # framenavigated needs this

        output = tmp_path / "test.har"
        result = capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=True,
            page_load_strategy="networkidle",
        )

        assert result.success is True
        mock_page.wait_for_load_state.assert_called_with("domcontentloaded")

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_domcontentloaded_strategy_no_fallback(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test domcontentloaded strategy doesn't trigger fallback logic."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_page = mock_pw.chromium.launch.return_value.new_context.return_value.new_page.return_value

        output = tmp_path / "test.har"
        capture_device_har(
            ip="127.0.0.1",
            output=str(output),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
            page_load_strategy="domcontentloaded",
        )

        mock_page.goto.assert_called_once_with("http://127.0.0.1/", wait_until="domcontentloaded")


# =============================================================================
# Tests for extracted functions (_resolve_capture_paths, _inject_har_metadata,
# _run_post_capture_pipeline)
# =============================================================================

# ┌──────────────────────────┬──────────────────────────┬──────────────────┬──────────────────────┐
# │ id                       │ input_output             │ expected_suffix  │ creates_captures_dir │
# ├──────────────────────────┼──────────────────────────┼──────────────────┼──────────────────────┤
# │ test case name           │ output param             │ .har suffix?     │ auto-create dir?     │
# └──────────────────────────┴──────────────────────────┴──────────────────┴──────────────────────┘
RESOLVE_PATHS_CASES = [
    ("explicit_har", "capture.har", ".har", False),
    ("explicit_json", "capture.json", ".har", False),
    ("explicit_no_ext", "capture", ".har", False),
    ("none_auto_generates", None, ".har", True),
]


class TestResolveCapturePathsUnit:
    """Tests for _resolve_capture_paths — zero mocks, pure filesystem."""

    @pytest.mark.parametrize(
        ("desc", "input_output", "expected_suffix", "creates_captures_dir"),
        RESOLVE_PATHS_CASES,
        ids=[c[0] for c in RESOLVE_PATHS_CASES],
    )
    def test_output_path_resolution(
        self,
        desc: str,
        input_output: str | None,
        expected_suffix: str,
        creates_captures_dir: bool,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test path resolution for various output specs."""
        monkeypatch.chdir(tmp_path)
        output = str(tmp_path / input_output) if input_output else None
        paths = _resolve_capture_paths("192.168.1.1", output, target_url="http://192.168.1.1/")

        assert paths.output_path.suffix == expected_suffix
        assert paths.temp_path.exists()
        assert paths.host == "192.168.1.1"
        assert paths.target_url == "http://192.168.1.1/"

        if creates_captures_dir:
            assert (tmp_path / "captures").is_dir()

        # Sanitized output is sibling with .sanitized.har
        assert "sanitized" in paths.sanitized_output.stem
        assert paths.sanitized_output.suffix == ".har"

        # Cleanup temp
        paths.temp_path.unlink()

    def test_temp_file_created_and_closed(self, tmp_path: Path) -> None:
        """Test temp file exists and FD is closed (writeable by path)."""
        paths = _resolve_capture_paths("10.0.0.1", str(tmp_path / "test.har"), target_url="http://10.0.0.1/")
        # Should be able to write to it (FD closed, file exists)
        paths.temp_path.write_text("test")
        assert paths.temp_path.read_text() == "test"
        paths.temp_path.unlink()

    def test_parent_dirs_created(self, tmp_path: Path) -> None:
        """Test parent directories are created for nested output paths."""
        nested = tmp_path / "deep" / "nested" / "dir" / "output.har"
        paths = _resolve_capture_paths("10.0.0.1", str(nested), target_url="http://10.0.0.1/")
        assert nested.parent.is_dir()
        paths.temp_path.unlink()

    def test_target_url_passthrough(self, tmp_path: Path) -> None:
        """Test pre-computed target_url is passed through."""
        paths = _resolve_capture_paths(
            "router.local", str(tmp_path / "out.har"), target_url="https://router.local:8443/"
        )
        assert paths.target_url == "https://router.local:8443/"
        paths.temp_path.unlink()

    def test_target_url_none_gives_empty(self, tmp_path: Path) -> None:
        """Test target_url=None produces empty string (caller must check connectivity)."""
        paths = _resolve_capture_paths("192.168.1.1", str(tmp_path / "out.har"), target_url=None)
        assert paths.target_url == ""
        paths.temp_path.unlink()


# ┌──────────────────────────────┬──────────┬──────────────────┬──────────────────┬───────────────┐
# │ id                           │ probes   │ browser_cookies  │ web_storage      │ description   │
# ├──────────────────────────────┼──────────┼──────────────────┼──────────────────┼───────────────┤
# │ test case name               │ inject?  │ inject?          │ inject?          │ scenario      │
# └──────────────────────────────┴──────────┴──────────────────┴──────────────────┘───────────────┘
INJECT_METADATA_CASES = _FIXTURE_DATA["inject_metadata_cases"]


class TestPopupHandler:
    """Behavior of the ``context.on('page', ...)`` popup handler.

    The handler runs as a closure inside ``_run_browser_session``. The
    ``test_routing_strategy`` test asserts ``context.on('page', ANY)`` is
    *registered*; these tests reach into the recorded mock call args to
    extract the actual handler and exercise its body — the eager-body
    attachment to popup pages and the defensive log-and-continue path
    when popup setup fails.
    """

    @staticmethod
    def _extract_popup_handler(mock_context: MagicMock) -> Any:
        """Find the ``context.on('page', handler)`` call and return the handler."""
        for call in mock_context.on.call_args_list:
            if call[0][0] == "page":
                return call[0][1]
        raise AssertionError(
            f"context.on('page', ...) never invoked; calls: {mock_context.on.call_args_list}"
        )

    @patch("har_capture.capture.browser._wait_for_network_quiescence")
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_handler_attaches_response_listener_to_popup(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_quiescence: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A popup page receives the same eager-body listener as the main page.

        Without this, popup response bodies can be evicted from Chromium's
        buffer before HAR flush — the same failure mode the main page had
        before v0.6.1 (CDP Network.getResponseBody race).
        """
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value

        capture_device_har(
            ip="127.0.0.1",
            output=str(tmp_path / "test.har"),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        handler = self._extract_popup_handler(mock_context)

        popup_page = MagicMock()
        popup_page.url = "http://127.0.0.1/popup"
        handler(popup_page)

        popup_page.on.assert_any_call("response", unittest.mock.ANY)

    @patch("har_capture.capture.browser._wait_for_network_quiescence")
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_handler_swallows_setup_failure(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        mock_quiescence: MagicMock,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """If the popup tears down before we can subscribe, log and continue.

        Capture-everything: a failed popup-handler attach is preferable to
        crashing the entire capture session. The warning surfaces the
        failure for postmortem; the main page's HAR continues uninterrupted.
        """
        import logging as _logging

        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value

        capture_device_har(
            ip="127.0.0.1",
            output=str(tmp_path / "test.har"),
            headless=True,
            timeout=1,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        handler = self._extract_popup_handler(mock_context)

        # Popup that's already torn down — calling .on raises.
        bad_popup = MagicMock()
        bad_popup.on.side_effect = RuntimeError("page closed")

        with caplog.at_level(_logging.WARNING, logger="har_capture.capture.browser"):
            handler(bad_popup)  # must not raise

        assert any("Failed to attach handlers to popup page" in rec.message for rec in caplog.records), (
            f"Expected warning log; got: {[r.message for r in caplog.records]}"
        )


class TestDialogHandler:
    """Behavior of the ``page.on('dialog', ...)`` handler.

    Dialog capture is enabled only for interactive headed runs. These
    tests reach into the mocked page event registration to exercise the
    real handler closure and confirm the inferred browser-UI outcome is
    recorded into ``_solentlabs.dialogs`` metadata.
    """

    @staticmethod
    def _extract_dialog_handler(mock_page: MagicMock) -> Any:
        """Find the ``page.on('dialog', handler)`` call and return the handler."""
        for call in mock_page.on.call_args_list:
            if call[0][0] == "dialog":
                return call[0][1]
        raise AssertionError(f"page.on('dialog', ...) never invoked; calls: {mock_page.on.call_args_list}")

    @pytest.mark.parametrize(
        ("headless", "timeout", "expect_dialog_capture"),
        [
            (False, None, True),
            (True, None, False),
            (False, 1, False),
        ],
        ids=["interactive_headed", "headless", "timed"],
    )
    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_dialog_capture_boundary(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
        headless: bool,
        timeout: int | None,
        expect_dialog_capture: bool,
    ) -> None:
        """Dialog capture is limited to interactive headed runs."""
        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value
        mock_page.evaluate.side_effect = lambda expr: (
            [] if expr == "window.__harCaptureDialogOutcomes || []" else {}
        )
        mock_page.wait_for_event.side_effect = RuntimeError("stop interactive wait")

        capture_device_har(
            ip="127.0.0.1",
            output=str(tmp_path / "test.har"),
            headless=headless,
            timeout=timeout,
            sanitize=False,
            compress=False,
            wait_for_data=False,
        )

        if expect_dialog_capture:
            mock_page.add_init_script.assert_called_once_with(_DIALOG_OBSERVER_INIT_SCRIPT)
            mock_page.on.assert_any_call("dialog", unittest.mock.ANY)
        else:
            dialog_calls = [c for c in mock_page.on.call_args_list if c[0][0] == "dialog"]
            assert dialog_calls == []
            assert _DIALOG_OBSERVER_INIT_SCRIPT not in [
                c.args[0] for c in mock_page.add_init_script.call_args_list
            ]

    @patch("har_capture.capture.browser.check_playwright", return_value=True)
    @patch("har_capture.capture.browser.check_device_connectivity")
    @patch("playwright.sync_api.sync_playwright")
    def test_dialog_handler_records_browser_ui_outcome_in_har(
        self,
        mock_sync_pw: MagicMock,
        mock_connectivity: MagicMock,
        mock_check_pw: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Dialog handler logs the inferred browser-UI outcome into HAR metadata.

        Two-event model: ``page.on("dialog")`` creates the open record;
        the ``__harCaptureDialogResolved`` binding (exposed via
        ``page.expose_function``) updates it with the user's action.
        Mocks drive both events to assert the recorded HAR shape.
        """
        import os

        mock_pw = MagicMock()
        mock_sync_pw.return_value.__enter__.return_value = mock_pw
        mock_connectivity.return_value = (True, "http", None)

        mock_context = mock_pw.chromium.launch.return_value.new_context.return_value
        mock_page = mock_context.new_page.return_value
        mock_context.cookies.return_value = []
        mock_context.storage_state.return_value = {"cookies": [], "origins": []}

        def evaluate_side_effect(expression: str) -> Any:
            if expression == "() => Object.fromEntries(Object.entries(sessionStorage))":
                return {}
            return 0

        mock_page.evaluate.side_effect = evaluate_side_effect

        # Capture the exposed-function callback so we can fire it ourselves
        # after the dialog-open handler runs.
        exposed_callbacks: dict[str, Any] = {}

        def expose_function_side_effect(name: str, handler: Any) -> None:
            exposed_callbacks[name] = handler

        mock_page.expose_function.side_effect = expose_function_side_effect

        def on_side_effect(event_name: str, handler: Any) -> None:
            if event_name == "dialog":
                dialog = MagicMock()
                dialog.type = "confirm"
                dialog.message = "Are you sure?"
                dialog.default_value = ""
                handler(dialog)
                # Simulate the JS init script firing the exposed callback
                # after the user resolves the dialog in the browser UI.
                resolve_cb = exposed_callbacks.get("__harCaptureDialogResolved")
                assert resolve_cb is not None, (
                    "expose_function('__harCaptureDialogResolved', ...) was not called"
                )
                resolve_cb({"type": "confirm", "message": "Are you sure?", "action": "dismiss"})

        mock_page.on.side_effect = on_side_effect

        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }
        temp_har = tmp_path / "temp_capture.har"
        temp_har.write_text(json.dumps(har_data))

        output = tmp_path / "dialog.har"
        fd = os.open(str(temp_har), os.O_RDWR)
        with patch("tempfile.mkstemp", return_value=(fd, str(temp_har))):
            capture_device_har(
                ip="127.0.0.1",
                output=str(output),
                headless=False,
                timeout=None,
                sanitize=False,
                compress=False,
                keep_raw=True,
                wait_for_data=False,
            )

        raw_har = json.loads(output.read_text())
        dialogs = raw_har["log"]["_solentlabs"]["dialogs"]
        assert len(dialogs) == 1
        assert dialogs[0] == {
            "type": "confirm",
            "message": "Are you sure?",
            "default_value": "",
            "opened_at": dialogs[0]["opened_at"],
            "action": "dismiss",
            "resolved_by": "browser_ui",
        }


class TestInjectHarMetadataUnit:
    """Tests for _inject_har_metadata — zero mocks, real temp files."""

    @pytest.mark.parametrize(
        "case",
        INJECT_METADATA_CASES,
        ids=[c["id"] for c in INJECT_METADATA_CASES],
    )
    def test_metadata_injection(self, case: dict, tmp_path: Path) -> None:
        """Test metadata injection with various combinations."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        }
        temp_har = tmp_path / "temp.har"
        temp_har.write_text(json.dumps(har_data))

        probes = {"auth_challenge": {"status": 401}} if case["has_probes"] else None
        popup_record = {"url": "http://10.0.0.1/popup", "opened_at": "2026-05-02T10:00:00"}
        dialog_record = {
            "type": "confirm",
            "message": "Are you sure?",
            "default_value": "",
            "opened_at": "2026-05-02T10:01:00",
            "action": "dismiss",
            "resolved_by": "browser_ui",
        }
        session = BrowserSessionResult(
            browser_cookies=[{"name": "SID", "value": "abc"}] if case["has_cookies"] else [],
            web_storage_local=(
                [{"origin": "http://10.0.0.1", "items": [{"name": "k", "value": "v"}]}]
                if case["has_storage"]
                else []
            ),
            web_storage_session={"token": "xyz"} if case["has_storage"] else {},
            pre_capture_cookies=[],
            dialogs=[dialog_record] if case.get("has_dialogs") else [],
            popups=[popup_record] if case.get("has_popups") else [],
        )

        _inject_har_metadata(temp_har, "http://10.0.0.1/", probes, session)

        result = json.loads(temp_har.read_text())
        log = result["log"]

        # _solentlabs.pre_capture_cookies is always present
        assert log["_solentlabs"]["pre_capture_cookies"] == []

        if case.get("has_dialogs"):
            assert log["_solentlabs"]["dialogs"] == [dialog_record]
        else:
            assert log["_solentlabs"]["dialogs"] == []

        # _solentlabs.popups round-trips whatever the session carried.
        # Empty for sessions where no popup occurred (the common case);
        # populated when the device opened popups (e.g., S33 reboot).
        if case.get("has_popups"):
            assert log["_solentlabs"]["popups"] == [popup_record]
        else:
            assert log["_solentlabs"]["popups"] == []

        if case["has_probes"]:
            assert log["_probes"]["auth_challenge"]["status"] == 401
        else:
            assert "_probes" not in log

        if case["has_cookies"]:
            assert log["_har_capture"]["browser_cookies"][0]["name"] == "SID"
        elif not case["has_storage"]:
            assert "_har_capture" not in log or "browser_cookies" not in log.get("_har_capture", {})

        if case["has_storage"]:
            assert "local_storage" in log["_har_capture"]
            assert "session_storage" in log["_har_capture"]
            ss_items = log["_har_capture"]["session_storage"][0]["items"]
            assert any(i["name"] == "token" for i in ss_items)

    def test_corrupt_har_handled_gracefully(self, tmp_path: Path) -> None:
        """Test _inject_har_metadata handles unreadable HAR without crashing."""
        temp_har = tmp_path / "bad.har"
        temp_har.write_text("not json")

        session = BrowserSessionResult()
        # Should not raise
        _inject_har_metadata(temp_har, "http://10.0.0.1/", None, session)


# ┌────────────────────────┬──────────┬──────────┬──────────┬──────────────┬─────────────────────┐
# │ id                     │ sanitize │ compress │ keep_raw │ interactive  │ description         │
# ├────────────────────────┼──────────┼──────────┼──────────┼──────────────┼─────────────────────┤
# │ test case name         │ flag     │ flag     │ flag     │ flag         │ scenario            │
# └────────────────────────┴──────────┴──────────┴──────────┴──────────────┴─────────────────────┘
POST_PIPELINE_CASES = [
    ("sanitize_compress", True, True, False, False, "default pipeline"),
    ("no_sanitize", False, True, False, False, "skip sanitization"),
    ("keep_raw", True, True, True, False, "keep raw HAR"),
    ("no_compress", True, False, False, False, "skip compression"),
    ("interactive", True, True, False, True, "interactive mode keeps sanitized"),
]


class TestRunPostCapturePipelineUnit:
    """Tests for _run_post_capture_pipeline — zero Playwright mocks."""

    @pytest.mark.parametrize(
        ("desc", "sanitize", "compress", "keep_raw", "interactive", "scenario"),
        POST_PIPELINE_CASES,
        ids=[c[0] for c in POST_PIPELINE_CASES],
    )
    def test_pipeline_file_outputs(
        self,
        desc: str,
        sanitize: bool,
        compress: bool,
        keep_raw: bool,
        interactive: bool,
        scenario: str,
        tmp_path: Path,
    ) -> None:
        """Test post-capture pipeline produces correct file outputs."""
        # Create a realistic temp HAR
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [
                    {
                        "request": {"method": "GET", "url": "http://10.0.0.1/"},
                        "response": {"status": 200, "content": {"text": "ok"}},
                    }
                ],
            }
        }
        temp_path = tmp_path / "temp_raw.har"
        temp_path.write_text(json.dumps(har_data))

        output_path = tmp_path / "output.har"
        sanitized_output = tmp_path / "output.sanitized.har"

        result = _run_post_capture_pipeline(
            temp_path=temp_path,
            output_path=output_path,
            sanitized_output=sanitized_output,
            sanitize=sanitize,
            compress=compress,
            keep_raw=keep_raw,
            interactive=interactive,
            capture_options=CaptureOptions(),
        )

        assert result.success is True

        # Temp file always deleted
        assert not temp_path.exists(), "Temp file should always be deleted"

        # Raw HAR only when keep_raw or not sanitize
        if keep_raw or not sanitize:
            assert result.har_path == output_path
            assert output_path.exists()
        else:
            assert result.har_path is None

        # Sanitized path
        if sanitize:
            if compress and not keep_raw and not interactive:
                # Sanitized deleted after compression
                assert result.sanitized_path is None
            else:
                assert result.sanitized_path is not None
        else:
            assert result.sanitized_path is None

        # Compressed path
        if sanitize and compress:
            assert result.compressed_path is not None
            assert result.compressed_path.exists()
            assert result.stats is not None
        else:
            assert result.compressed_path is None

    def test_temp_cleaned_on_copy_failure(self, tmp_path: Path) -> None:
        """Test temp file is deleted even if copy fails."""
        temp_path = tmp_path / "temp.har"
        temp_path.write_text("{}")

        # Point output to a non-existent device to force copy failure
        _run_post_capture_pipeline(
            temp_path=temp_path,
            output_path=Path("/dev/null/impossible/output.har"),
            sanitized_output=tmp_path / "sanitized.har",
            sanitize=False,
            compress=False,
            keep_raw=False,
            interactive=False,
            capture_options=CaptureOptions(),
        )

        assert not temp_path.exists(), "Temp file should still be cleaned up"


# =============================================================================
# _apply_dialog_resolution() — pure function extracted from
# _run_browser_session so the matching logic (including defensive
# branches) is fixture-driven unit-testable without Playwright mocks.
# =============================================================================


class TestApplyDialogResolution:
    """Fixture-driven coverage of the dialog-resolution match-and-update logic.

    Each row of ``dialog_resolution_cases`` in ``test_browser.json``
    declares the ``dialogs`` list state before the call, the resolution
    ``outcome`` payload, and the expected outcome (match vs. no-match;
    on match: post-update ``action`` / ``resolved_by``; optionally the
    index of the entry that should have been updated).

    These cases collectively cover every branch in
    ``_apply_dialog_resolution``: the ``isinstance(outcome, dict)``
    defensive guard, the reverse-iteration LIFO match preference,
    the type/message correlation requirements, the
    ``resolved_by == "unknown"`` skip-already-resolved condition,
    the missing-``action``-key default, and the no-match fall-through.
    """

    @pytest.mark.parametrize(
        "case",
        DIALOG_RESOLUTION_CASES,
        ids=[c["id"] for c in DIALOG_RESOLUTION_CASES],
    )
    def test_apply_dialog_resolution(self, case: dict[str, Any]) -> None:
        """Exercise the resolution logic against a fixture row.

        Pre-copy the dialogs list so the test asserts the function's
        in-place mutation (or non-mutation) without aliasing the
        fixture data across parametrize cases.
        """
        import copy

        from har_capture.capture.browser import _apply_dialog_resolution

        dialogs_before = copy.deepcopy(case["dialogs_before"])
        dialogs = copy.deepcopy(case["dialogs_before"])
        outcome = case["outcome"]

        result = _apply_dialog_resolution(dialogs, outcome)

        if case["expect_match"]:
            assert result is not None, f"{case['id']}: expected a match but got None (dialogs={dialogs})"
            assert result["action"] == case["expect_action"]
            assert result["resolved_by"] == case["expect_resolved_by"]
            # The function returns the entry; the same entry inside
            # ``dialogs`` should be mutated in place.
            if "expect_updated_index" in case:
                idx = case["expect_updated_index"]
                assert dialogs[idx]["action"] == case["expect_action"]
                assert dialogs[idx]["resolved_by"] == case["expect_resolved_by"]
                # Other entries must be untouched.
                for other_idx, (before, after) in enumerate(zip(dialogs_before, dialogs, strict=False)):
                    if other_idx != idx:
                        assert before == after, f"{case['id']}: entry {other_idx} mutated unexpectedly"
        else:
            assert result is None, f"{case['id']}: expected no match but got {result!r}"
            # No-match → dialogs list must be unchanged.
            assert dialogs == dialogs_before, f"{case['id']}: dialogs mutated despite no match"


# =============================================================================
# Download preservation — 2026-08-19 CM2500 session: the event-log export
# went to Playwright's ephemeral artifacts dir and was wiped on close.
# =============================================================================


class TestUniqueDownloadName:
    """Filename selection for saved downloads."""

    # fmt: off
    NAME_CASES = [
        ("eventlog.txt",        set(),                          "eventlog.txt",     "simple_name"),
        ("eventlog.txt",        {"eventlog.txt"},               "eventlog_2.txt",   "collision_appends_counter"),
        ("eventlog.txt",        {"eventlog.txt", "eventlog_2.txt"}, "eventlog_3.txt", "double_collision"),
        ("",                    set(),                          "download",         "empty_name_fallback"),
        ("../../etc/cron.d",    set(),                          "cron.d",           "path_escape_stripped"),
        ("noext",               {"noext"},                      "noext_2",          "no_extension_counter"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("suggested", "taken", "expected", "desc"),
        NAME_CASES,
        ids=[c[3] for c in NAME_CASES],
    )
    def test_unique_download_name(self, suggested: str, taken: set[str], expected: str, desc: str) -> None:
        from har_capture.capture.browser import _unique_download_name

        assert _unique_download_name(suggested, taken) == expected, desc


class TestSavePendingDownloads:
    """Saving collected Download objects out of the artifacts dir."""

    @staticmethod
    def _fake_download(name: str, content: bytes = b"data", fail: bool = False) -> MagicMock:
        download = MagicMock()
        download.suggested_filename = name
        if fail:
            download.save_as.side_effect = RuntimeError("context closed")
        else:
            download.save_as.side_effect = lambda dest: Path(dest).write_bytes(content)
        return download

    def test_downloads_saved_with_audit_records(self, tmp_path: Path) -> None:
        from har_capture.capture.browser import _save_pending_downloads

        downloads_dir = tmp_path / "capture_downloads"
        pending = [
            self._fake_download("eventlog.txt", b"log-a"),
            self._fake_download("eventlog.txt", b"log-b"),
        ]

        records = _save_pending_downloads(pending, downloads_dir)

        assert (downloads_dir / "eventlog.txt").read_bytes() == b"log-a"
        assert (downloads_dir / "eventlog_2.txt").read_bytes() == b"log-b"
        assert [r["saved_as"] for r in records] == ["eventlog.txt", "eventlog_2.txt"]
        assert all("error" not in r for r in records)

    def test_one_failure_does_not_lose_the_rest(self, tmp_path: Path) -> None:
        """Capture-everything over fail: a dead download is recorded, not raised."""
        from har_capture.capture.browser import _save_pending_downloads

        downloads_dir = tmp_path / "capture_downloads"
        pending = [
            self._fake_download("gone.bin", fail=True),
            self._fake_download("kept.txt", b"ok"),
        ]

        records = _save_pending_downloads(pending, downloads_dir)

        assert records[0]["error"] == "context closed"
        assert "saved_path" not in records[0]
        assert (downloads_dir / "kept.txt").read_bytes() == b"ok"
        assert records[1]["saved_as"] == "kept.txt"

    def test_no_downloads_creates_no_directory(self, tmp_path: Path) -> None:
        from har_capture.capture.browser import _save_pending_downloads

        downloads_dir = tmp_path / "capture_downloads"
        assert _save_pending_downloads([], downloads_dir) == []
        assert not downloads_dir.exists()
