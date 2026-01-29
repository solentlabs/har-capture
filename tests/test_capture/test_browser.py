"""Tests for browser capture module."""

from __future__ import annotations

import pytest

from har_capture.capture.browser import CaptureOptions
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
