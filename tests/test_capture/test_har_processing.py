"""Tests for HAR processing functions (filter, compress, metadata, body patching)."""

from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest

from har_capture.capture.browser import (
    CaptureOptions,
    _add_capture_metadata,
    _patch_missing_bodies,
    filter_and_compress_har,
    strip_browser_internal_entries,
)

# =============================================================================
# Fixture data
# =============================================================================

FIXTURES_PATH = Path(__file__).parent.parent / "fixtures" / "test_har_processing.json"
FIXTURES = json.loads(FIXTURES_PATH.read_text())


def _write_har(tmp_path: Path, key: str, filename: str) -> Path:
    """Write a fixture HAR to a temp file and return the path."""
    har_file = tmp_path / filename
    har_file.write_text(json.dumps(copy.deepcopy(FIXTURES[key])))
    return har_file


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def basic_har(tmp_path: Path) -> Path:
    """Create a basic HAR file for testing."""
    return _write_har(tmp_path, "basic_har", "test.har")


@pytest.fixture
def har_with_bloat(tmp_path: Path) -> Path:
    """Create a HAR file with bloat entries (fonts, images, etc.)."""
    return _write_har(tmp_path, "har_with_bloat", "bloat.har")


@pytest.fixture
def har_with_duplicates(tmp_path: Path) -> Path:
    """Create a HAR file with duplicate requests."""
    return _write_har(tmp_path, "har_with_duplicates", "duplicates.har")


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
        assert "version" in metadata
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

    def test_version_matches_package(self) -> None:
        """Test version matches the package version."""
        from har_capture import __version__

        har = {"log": {"entries": []}}

        _add_capture_metadata(har)

        assert har["log"]["_har_capture"]["version"] == __version__


class TestStripBrowserInternalEntries:
    """Tests for strip_browser_internal_entries.

    Reproduces the 2026-08-19 CM2500 finding: 11 chrome:// entries in the
    happy-path capture, including chrome://fileicon URLs embedding local
    Playwright temp-dir paths.
    """

    def test_non_http_entries_removed_http_kept(self) -> None:
        har = copy.deepcopy(FIXTURES["har_with_internal_entries"])
        removed = strip_browser_internal_entries(har)

        assert removed == 6
        urls = [e["request"]["url"] for e in har["log"]["entries"]]
        assert all(u.lower().startswith(("http://", "https://")) for u in urls)
        # Scheme matching is case-insensitive; the POST survives too.
        assert "HTTP://192.168.100.1/RouterStatus.htm" in urls
        assert any("goform/Login" in u for u in urls)
        # The local-path leak is gone.
        assert "playwright-artifacts" not in json.dumps(har)

    def test_clean_har_untouched(self) -> None:
        har = copy.deepcopy(FIXTURES["basic_har"])
        before = copy.deepcopy(har)

        assert strip_browser_internal_entries(har) == 0
        assert har == before

    @pytest.mark.parametrize(
        "har",
        [{}, {"log": {}}, {"log": {"entries": "not-a-list"}}],
        ids=["empty_dict", "no_entries", "entries_not_list"],
    )
    def test_malformed_har_returns_zero(self, har: dict) -> None:
        assert strip_browser_internal_entries(har) == 0

    def test_malformed_entry_is_kept(self) -> None:
        """Non-dict entries are not ours to judge — capture-everything."""
        har = {"log": {"entries": ["weird", {"request": {"url": "chrome://x"}}]}}
        removed = strip_browser_internal_entries(har)
        assert removed == 1
        assert har["log"]["entries"] == ["weird"]


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

    def test_post_different_bodies_preserved(self, tmp_path: Path) -> None:
        """Test POSTs to the same URL with different bodies are kept."""
        har_file = _write_har(tmp_path, "post_different_bodies", "post_bodies.har")

        compressed_path, stats = filter_and_compress_har(har_file)

        assert stats["original_entries"] == 3
        assert stats["filtered_entries"] == 3

        with gzip.open(compressed_path, "rt") as f:
            har = json.load(f)

        bodies = [e["request"]["postData"]["text"] for e in har["log"]["entries"]]
        assert bodies == ["action=1", "action=2", "action=3"]

    def test_post_identical_bodies_deduped(self, tmp_path: Path) -> None:
        """Test POSTs to the same URL with identical bodies are deduped."""
        har_file = _write_har(tmp_path, "post_identical_bodies", "post_retry.har")

        _compressed_path, stats = filter_and_compress_har(har_file)

        assert stats["original_entries"] == 2
        assert stats["filtered_entries"] == 1

    def test_compressed_size_smaller_for_large_file(self, tmp_path: Path) -> None:
        """Test compressed size is smaller than original for sufficiently large files."""
        har_file = _write_har(tmp_path, "large_har", "large.har")

        _compressed_path, stats = filter_and_compress_har(har_file)

        assert stats["compressed_size"] < stats["filtered_size"]

    def test_url_query_params_ignored_for_bloat_check(self, tmp_path: Path) -> None:
        """Test query params don't affect bloat extension detection."""
        har_file = _write_har(tmp_path, "query_params_bloat", "query.har")

        _compressed_path, stats = filter_and_compress_har(har_file)

        # Image should be filtered even with query params
        assert stats["filtered_entries"] == 0

    def test_case_insensitive_extension_check(self, tmp_path: Path) -> None:
        """Test bloat extension check is case-insensitive."""
        har_file = _write_har(tmp_path, "uppercase_extensions", "uppercase.har")

        _compressed_path, stats = filter_and_compress_har(har_file)

        # Both should be filtered (case-insensitive)
        assert stats["filtered_entries"] == 0

    def test_default_options_when_none(self, basic_har: Path) -> None:
        """Test default options are used when None is passed."""
        # Should not raise
        compressed_path, _stats = filter_and_compress_har(basic_har, options=None)

        assert compressed_path.exists()

    def test_probes_preserved_through_filter_compress(self, tmp_path: Path) -> None:
        """Test _probes key in HAR survives filter+compress round-trip."""
        har_file = _write_har(tmp_path, "har_with_probes", "probes.har")

        compressed_path, _stats = filter_and_compress_har(har_file)

        with gzip.open(compressed_path, "rt") as f:
            har = json.load(f)

        assert "_probes" in har["log"]
        assert har["log"]["_probes"]["target_url"] == "http://192.168.1.1/"
        assert har["log"]["_probes"]["auth_challenge"]["status_code"] == 401

    def test_no_probes_key_when_absent(self, basic_har: Path) -> None:
        """Test no _probes key when HAR doesn't contain probes."""
        compressed_path, _stats = filter_and_compress_har(basic_har)

        with gzip.open(compressed_path, "rt") as f:
            har = json.load(f)

        assert "_probes" not in har["log"]


# =============================================================================
# Body patching
# =============================================================================

# ┌─────────────────────────┬───────────────────────┬──────────────┬──────────┐
# │ fixture_key             │ captured_bodies       │ expect_patch │ id       │
# ├─────────────────────────┼───────────────────────┼──────────────┼──────────┤
PATCH_BODIES_CASES = [
    (
        "har_missing_body",
        {"GET|http://192.168.100.1/|200": b"<html><input type='hidden' name='csrf'/></html>"},
        True,
        "missing_body_patched_from_cache",
    ),
    (
        "har_body_present",
        {"GET|http://192.168.100.1/|200": b"<html>SHOULD NOT REPLACE</html>"},
        False,
        "existing_body_not_overwritten",
    ),
    (
        "har_missing_body",
        {},
        False,
        "empty_cache_no_patch",
    ),
    (
        "har_missing_body",
        {"GET|http://192.168.100.1/WRONG|200": b"wrong url"},
        False,
        "cache_miss_no_patch",
    ),
    (
        "har_missing_body_no_size",
        {"GET|http://192.168.100.1/empty|204": b""},
        False,
        "zero_bodysize_not_patched",
    ),
]
# └─────────────────────────┴───────────────────────┴──────────────┴──────────┘


class TestPatchMissingBodies:
    """Tests for _patch_missing_bodies function."""

    @pytest.mark.parametrize(
        ("fixture_key", "captured_bodies", "expect_patch", "desc"),
        PATCH_BODIES_CASES,
        ids=[c[3] for c in PATCH_BODIES_CASES],
    )
    def test_patch_decision(
        self,
        tmp_path: Path,
        fixture_key: str,
        captured_bodies: dict[str, bytes],
        expect_patch: bool,
        desc: str,
    ) -> None:
        """Table-driven: verify when bodies are/aren't patched."""
        har_file = _write_har(tmp_path, fixture_key, "test.har")

        patched_count = _patch_missing_bodies(har_file, captured_bodies)

        assert (patched_count > 0) == expect_patch

        if expect_patch:
            with open(har_file) as f:
                har = json.load(f)
            entry = har["log"]["entries"][0]
            assert entry["response"]["content"]["text"]
            assert entry["response"]["content"]["size"] > 0

    def test_patches_correct_body_text(self, tmp_path: Path) -> None:
        """Verify the patched body matches the eagerly captured content."""
        har_file = _write_har(tmp_path, "har_missing_body", "test.har")
        html = "<html><input type='hidden' name='csrf' value='abc'/></html>"
        bodies = {"GET|http://192.168.100.1/|200": html.encode("utf-8")}

        _patch_missing_bodies(har_file, bodies)

        with open(har_file) as f:
            har = json.load(f)
        content = har["log"]["entries"][0]["response"]["content"]
        assert content["text"] == html
        assert content["size"] == len(html.encode("utf-8"))
        assert "encoding" not in content  # UTF-8 text, no base64

    def test_mixed_entries_only_missing_patched(self, tmp_path: Path) -> None:
        """In a HAR with mixed entries, only missing bodies get patched."""
        har_file = _write_har(tmp_path, "har_mixed_bodies", "test.har")
        bodies = {
            "GET|http://192.168.100.1/|200": b"<html>login</html>",
            "GET|http://192.168.100.1/api/status|200": b'{"status":"ok"}',
        }

        patched_count = _patch_missing_bodies(har_file, bodies)

        assert patched_count == 2

        with open(har_file) as f:
            har = json.load(f)

        entries = har["log"]["entries"]
        # Entry 0: was missing, now patched
        assert entries[0]["response"]["content"]["text"] == "<html>login</html>"
        # Entry 1: already had body, unchanged
        assert entries[1]["response"]["content"]["text"] == "<html>dashboard</html>"
        # Entry 2: was missing, now patched
        assert entries[2]["response"]["content"]["text"] == '{"status":"ok"}'

    def test_non_utf8_body_uses_base64(self, tmp_path: Path) -> None:
        """Non-UTF-8 text body falls back to base64 encoding."""
        har_file = _write_har(tmp_path, "har_missing_body", "test.har")
        body = b"\xff\xfe<html>latin1</html>"
        bodies = {"GET|http://192.168.100.1/|200": body}

        _patch_missing_bodies(har_file, bodies)

        with open(har_file) as f:
            har = json.load(f)
        content = har["log"]["entries"][0]["response"]["content"]
        assert content["encoding"] == "base64"
        import base64

        assert base64.b64decode(content["text"]) == body

    def test_corrupt_har_returns_zero(self, tmp_path: Path) -> None:
        """Corrupt HAR file returns 0 patched without crashing."""
        har_file = tmp_path / "bad.har"
        har_file.write_text("not json")

        result = _patch_missing_bodies(har_file, {"GET|http://x/|200": b"body"})

        assert result == 0


class TestCaptureWriterLineEndings:
    r"""Every capture-side HAR rewrite is LF-only on every platform.

    The .har handed to the operator is evidence: downstream repos commit it
    and enforce LF, so a CRLF artifact gets rewritten by their hooks. Each
    writer in the post-capture pipeline pins ``newline="\n"`` rather than
    letting text mode pick ``os.linesep``. The ``windows_text_mode`` fixture
    makes an unpinned write emit CRLF on any platform, so a dropped pin fails
    here on Linux CI too.

    Only the pretty-printed writers are asserted on. ``_patch_missing_bodies``
    and ``_inject_har_metadata`` dump compact JSON — no newline ever reaches
    the stream, so no assertion on their bytes can fail. They pin the newline
    anyway, for the day one of them grows an ``indent=``.
    """

    def test_filter_and_compress_writes_lf(self, basic_har: Path, windows_text_mode: None) -> None:
        """filter_and_compress_har rewrites the HAR with LF endings."""
        filter_and_compress_har(basic_har)

        assert b"\r" not in basic_har.read_bytes()

    def test_compressed_copy_is_lf(self, tmp_path: Path, windows_text_mode: None) -> None:
        """The .har.gz sibling carries the same LF bytes as the .har."""
        har_file = _write_har(tmp_path, "basic_har", "test.har")

        compressed_path, _stats = filter_and_compress_har(har_file)

        assert b"\r" not in har_file.read_bytes()
        with gzip.open(compressed_path, "rb") as f:
            assert b"\r" not in f.read()

    def test_filtered_har_still_parses(self, basic_har: Path, windows_text_mode: None) -> None:
        """Pinning the newline does not disturb the JSON payload."""
        filter_and_compress_har(basic_har)

        assert json.loads(basic_har.read_text())["log"]["entries"]
