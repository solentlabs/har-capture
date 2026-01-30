"""Tests for browser capture module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.browser import CaptureOptions, capture_device_har
from har_capture.capture.connectivity import _parse_target
from har_capture.capture.deps import check_playwright
from har_capture.patterns import get_bloat_extensions
from har_capture.validation.secrets import is_private_ip

# =============================================================================
# Test Data Tables
# =============================================================================

# ┌─────────────────────────┬─────────────┬─────────────────────────────┐
# │ ip_address              │ is_private  │ description                 │
# ├─────────────────────────┼─────────────┼─────────────────────────────┤
# │ IP address to test      │ True/False  │ test case name              │
# └─────────────────────────┴─────────────┴─────────────────────────────┘
#
# fmt: off
PRIVATE_IP_CASES = [
    # 10.x.x.x range (Class A private)
    ("10.0.0.1",            True,   "10_network_start"),
    ("10.0.0.0",            True,   "10_network_zero"),
    ("10.255.255.255",      True,   "10_network_end"),
    ("10.100.50.25",        True,   "10_network_middle"),
    # 172.16-31.x.x range (Class B private)
    ("172.16.0.1",          True,   "172_16_start"),
    ("172.31.255.255",      True,   "172_31_end"),
    ("172.20.100.50",       True,   "172_20_middle"),
    ("172.15.0.1",          False,  "172_15_not_private"),
    ("172.32.0.1",          False,  "172_32_not_private"),
    # 192.168.x.x range (Class C private)
    ("192.168.0.1",         True,   "192_168_0_1"),
    ("192.168.1.1",         True,   "192_168_1_1"),
    ("192.168.100.1",       True,   "192_168_100_1"),
    ("192.168.255.255",     True,   "192_168_end"),
    # Loopback
    ("127.0.0.1",           True,   "localhost"),
    ("127.0.0.0",           True,   "loopback_start"),
    ("127.255.255.255",     True,   "loopback_end"),
    # Special addresses
    ("0.0.0.0",             True,   "all_zeros_redacted"),
    # Public IPs (should NOT be private)
    ("8.8.8.8",             False,  "google_dns"),
    ("8.8.4.4",             False,  "google_dns_secondary"),
    ("1.1.1.1",             False,  "cloudflare_dns"),
    ("208.67.222.222",      False,  "opendns"),
    ("9.9.9.9",             False,  "quad9"),
    ("192.0.2.1",           False,  "test_net_1"),
    ("203.0.113.1",         False,  "test_net_3"),
    ("198.51.100.1",        False,  "test_net_2"),
    # Edge cases
    ("192.167.1.1",         False,  "192_167_not_private"),
    ("192.169.1.1",         False,  "192_169_not_private"),
    ("11.0.0.1",            False,  "11_not_private"),
]
# fmt: on

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

# ┌───────────────────────────────┬─────────────────────┬─────────┬──────────────────────┐
# │ target_input                  │ expected_host       │ scheme  │ description          │
# ├───────────────────────────────┼─────────────────────┼─────────┼──────────────────────┤
# │ URL or hostname to parse      │ extracted hostname  │ scheme  │ test case name       │
# └───────────────────────────────┴─────────────────────┴─────────┴──────────────────────┘
#
# fmt: off
PARSE_TARGET_CASES = [
    # Full URLs with scheme
    ("https://example.com",             "example.com",       "https",  "https_url"),
    ("http://example.com",              "example.com",       "http",   "http_url"),
    ("https://example.com/",            "example.com",       "https",  "https_trailing_slash"),
    ("https://example.com/path/page",   "example.com",       "https",  "https_with_path"),
    ("http://example.com:8080",         "example.com:8080",  "http",   "http_with_port"),
    ("https://192.168.1.1:8443",        "192.168.1.1:8443",  "https",  "https_ip_with_port"),
    # Hostnames without scheme
    ("example.com",                     "example.com",       None,     "hostname_only"),
    ("sub.example.com",                 "sub.example.com",   None,     "subdomain"),
    ("router.local",                    "router.local",      None,     "local_hostname"),
    # IP addresses without scheme
    ("192.168.1.1",                     "192.168.1.1",       None,     "ipv4_address"),
    ("192.168.1.1:8080",                "192.168.1.1:8080",  None,     "ipv4_with_port"),
    ("10.0.0.1",                        "10.0.0.1",          None,     "private_ip"),
    # Edge cases
    ("HTTPS://EXAMPLE.COM",             "EXAMPLE.COM",       "https",  "uppercase_scheme"),
    ("http://localhost",                "localhost",         "http",   "localhost"),
    ("http://127.0.0.1",                "127.0.0.1",         "http",   "loopback_ip"),
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
        )

        mock_playwright.webkit.launch.assert_called_once_with(headless=True)
        mock_playwright.chromium.launch.assert_not_called()
