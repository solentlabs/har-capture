"""Tests for HAR processing functions (filter, compress, metadata)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from har_capture.capture.browser import (
    CaptureOptions,
    _add_capture_metadata,
    filter_and_compress_har,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def basic_har(tmp_path: Path) -> Path:
    """Create a basic HAR file for testing."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://example.com/page",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"text": "Hello", "mimeType": "text/html"},
                    },
                },
            ],
        }
    }
    har_file = tmp_path / "test.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


@pytest.fixture
def har_with_bloat(tmp_path: Path) -> Path:
    """Create a HAR file with bloat entries (fonts, images, etc.)."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                # Main page
                {
                    "request": {"method": "GET", "url": "http://example.com/", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # Font (bloat)
                {
                    "request": {"method": "GET", "url": "http://example.com/font.woff2", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # Image (bloat)
                {
                    "request": {"method": "GET", "url": "http://example.com/logo.png", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # CSS (not bloat)
                {
                    "request": {"method": "GET", "url": "http://example.com/style.css", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # JS (not bloat)
                {
                    "request": {"method": "GET", "url": "http://example.com/app.js", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # Sourcemap (bloat)
                {
                    "request": {"method": "GET", "url": "http://example.com/app.js.map", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # Media (bloat)
                {
                    "request": {"method": "GET", "url": "http://example.com/video.mp4", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
            ],
        }
    }
    har_file = tmp_path / "bloat.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


@pytest.fixture
def har_with_duplicates(tmp_path: Path) -> Path:
    """Create a HAR file with duplicate requests."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [
                # First request
                {
                    "request": {"method": "GET", "url": "http://example.com/api", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # Duplicate GET
                {
                    "request": {"method": "GET", "url": "http://example.com/api", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                # POST to same URL (not a duplicate - different method)
                {
                    "request": {"method": "POST", "url": "http://example.com/api", "headers": []},
                    "response": {"status": 201, "headers": [], "content": {}},
                },
                # Another duplicate GET
                {
                    "request": {"method": "GET", "url": "http://example.com/api", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
            ],
        }
    }
    har_file = tmp_path / "duplicates.har"
    har_file.write_text(json.dumps(har_data))
    return har_file


# =============================================================================
# Test Classes
# =============================================================================


class TestAddCaptureMetadata:
    """Tests for _add_capture_metadata function."""

    def test_adds_metadata_section(self) -> None:
        """Test metadata section is added to HAR."""
        har = {"log": {"entries": []}}

        _add_capture_metadata(har)

        assert "_har_capture" in har["log"]
        metadata = har["log"]["_har_capture"]
        assert "tool" in metadata
        assert "captured_at" in metadata
        assert "cache_disabled" in metadata
        assert "service_workers_blocked" in metadata

    def test_default_tool_name(self) -> None:
        """Test default tool name is har-capture."""
        har = {"log": {"entries": []}}

        _add_capture_metadata(har)

        assert har["log"]["_har_capture"]["tool"] == "har-capture"

    def test_custom_tool_name(self) -> None:
        """Test custom tool name can be set."""
        har = {"log": {"entries": []}}

        _add_capture_metadata(har, tool_name="custom-tool")

        assert har["log"]["_har_capture"]["tool"] == "custom-tool"

    def test_captured_at_is_iso_format(self) -> None:
        """Test captured_at is in ISO format."""
        har = {"log": {"entries": []}}

        _add_capture_metadata(har)

        captured_at = har["log"]["_har_capture"]["captured_at"]
        # ISO format should have T separator and be parseable
        assert "T" in captured_at
        # Should not raise
        from datetime import datetime

        datetime.fromisoformat(captured_at)

    def test_cache_disabled_is_true(self) -> None:
        """Test cache_disabled is set to True."""
        har = {"log": {"entries": []}}

        _add_capture_metadata(har)

        assert har["log"]["_har_capture"]["cache_disabled"] is True

    def test_service_workers_blocked_is_true(self) -> None:
        """Test service_workers_blocked is set to True."""
        har = {"log": {"entries": []}}

        _add_capture_metadata(har)

        assert har["log"]["_har_capture"]["service_workers_blocked"] is True


class TestFilterAndCompressHar:
    """Tests for filter_and_compress_har function."""

    def test_creates_compressed_file(self, basic_har: Path) -> None:
        """Test compressed .har.gz file is created."""
        compressed_path, _stats = filter_and_compress_har(basic_har)

        assert compressed_path.exists()
        assert compressed_path.suffix == ".gz"
        assert str(compressed_path).endswith(".har.gz")

    def test_compressed_file_is_valid_gzip(self, basic_har: Path) -> None:
        """Test compressed file is valid gzip."""
        compressed_path, _stats = filter_and_compress_har(basic_har)

        # Should be able to read as gzip
        with gzip.open(compressed_path, "rt") as f:
            har = json.load(f)

        assert "log" in har
        assert "entries" in har["log"]

    def test_adds_metadata_to_har(self, basic_har: Path) -> None:
        """Test metadata is added to the HAR."""
        compressed_path, _stats = filter_and_compress_har(basic_har)

        with gzip.open(compressed_path, "rt") as f:
            har = json.load(f)

        assert "_har_capture" in har["log"]

    def test_returns_stats(self, basic_har: Path) -> None:
        """Test stats dict is returned."""
        _compressed_path, stats = filter_and_compress_har(basic_har)

        assert "original_entries" in stats
        assert "filtered_entries" in stats
        assert "removed_entries" in stats
        assert "original_size" in stats
        assert "filtered_size" in stats
        assert "compressed_size" in stats

    def test_filters_bloat_by_default(self, har_with_bloat: Path) -> None:
        """Test bloat files are filtered by default."""
        _compressed_path, stats = filter_and_compress_har(har_with_bloat)

        # Original: 7 entries (1 page + 1 font + 1 image + 1 css + 1 js + 1 map + 1 video)
        # After filter: 3 entries (page, css, js) - bloat removed
        assert stats["original_entries"] == 7
        assert stats["filtered_entries"] == 3
        assert stats["removed_entries"] == 4

    def test_include_fonts_option(self, har_with_bloat: Path) -> None:
        """Test include_fonts option keeps fonts."""
        options = CaptureOptions(include_fonts=True)
        _compressed_path, stats = filter_and_compress_har(har_with_bloat, options)

        # Should keep font, but still filter images/media/maps
        assert stats["filtered_entries"] == 4  # page, font, css, js

    def test_include_images_option(self, har_with_bloat: Path) -> None:
        """Test include_images option keeps images."""
        options = CaptureOptions(include_images=True)
        _compressed_path, stats = filter_and_compress_har(har_with_bloat, options)

        # Should keep image, but still filter fonts/media/maps
        assert stats["filtered_entries"] == 4  # page, image, css, js

    def test_include_media_option(self, har_with_bloat: Path) -> None:
        """Test include_media option keeps media files."""
        options = CaptureOptions(include_media=True)
        _compressed_path, stats = filter_and_compress_har(har_with_bloat, options)

        # Should keep video, but still filter fonts/images/maps
        assert stats["filtered_entries"] == 4  # page, video, css, js

    def test_include_all_options(self, har_with_bloat: Path) -> None:
        """Test including all options keeps most files."""
        options = CaptureOptions(include_fonts=True, include_images=True, include_media=True)
        _compressed_path, stats = filter_and_compress_har(har_with_bloat, options)

        # Should only filter sourcemaps
        assert stats["filtered_entries"] == 6  # all except .map

    def test_removes_duplicates(self, har_with_duplicates: Path) -> None:
        """Test duplicate requests are removed."""
        _compressed_path, stats = filter_and_compress_har(har_with_duplicates)

        # Original: 4 entries (3 GET, 1 POST)
        # After dedup: 2 entries (1 GET, 1 POST) - duplicates removed
        assert stats["original_entries"] == 4
        assert stats["filtered_entries"] == 2

    def test_preserves_different_methods(self, har_with_duplicates: Path) -> None:
        """Test different HTTP methods to same URL are preserved."""
        compressed_path, _stats = filter_and_compress_har(har_with_duplicates)

        with gzip.open(compressed_path, "rt") as f:
            har = json.load(f)

        methods = [e["request"]["method"] for e in har["log"]["entries"]]
        assert "GET" in methods
        assert "POST" in methods

    def test_compressed_size_smaller_for_large_file(self, tmp_path: Path) -> None:
        """Test compressed size is smaller than original for sufficiently large files."""
        # Create a larger HAR file where compression is effective
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [
                    {
                        "request": {"method": "GET", "url": f"http://example.com/page{i}", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": "x" * 1000, "mimeType": "text/html"},
                        },
                    }
                    for i in range(20)
                ],
            }
        }
        har_file = tmp_path / "large.har"
        har_file.write_text(json.dumps(har_data))

        _compressed_path, stats = filter_and_compress_har(har_file)

        assert stats["compressed_size"] < stats["filtered_size"]

    def test_url_query_params_ignored_for_bloat_check(self, tmp_path: Path) -> None:
        """Test query params don't affect bloat extension detection."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/image.png?v=123",
                            "headers": [],
                        },
                        "response": {"status": 200, "headers": [], "content": {}},
                    },
                ],
            }
        }
        har_file = tmp_path / "query.har"
        har_file.write_text(json.dumps(har_data))

        _compressed_path, stats = filter_and_compress_har(har_file)

        # Image should be filtered even with query params
        assert stats["filtered_entries"] == 0

    def test_case_insensitive_extension_check(self, tmp_path: Path) -> None:
        """Test bloat extension check is case-insensitive."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [
                    {
                        "request": {"method": "GET", "url": "http://example.com/IMAGE.PNG", "headers": []},
                        "response": {"status": 200, "headers": [], "content": {}},
                    },
                    {
                        "request": {"method": "GET", "url": "http://example.com/Font.WOFF2", "headers": []},
                        "response": {"status": 200, "headers": [], "content": {}},
                    },
                ],
            }
        }
        har_file = tmp_path / "uppercase.har"
        har_file.write_text(json.dumps(har_data))

        _compressed_path, stats = filter_and_compress_har(har_file)

        # Both should be filtered (case-insensitive)
        assert stats["filtered_entries"] == 0

    def test_default_options_when_none(self, basic_har: Path) -> None:
        """Test default options are used when None is passed."""
        # Should not raise
        compressed_path, _stats = filter_and_compress_har(basic_har, options=None)

        assert compressed_path.exists()
