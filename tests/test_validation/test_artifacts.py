"""Tests for .har/.har.gz artifact-consistency checks.

The stale-gz case reproduces the 2026-08-19 CM2500 finding: an
interactive review rewrote the .sanitized.har while the pre-review
.har.gz — the upload artifact — kept the scrubbed serial and IPv6.

Test Strategy:
    - Table-driven pair resolution
    - tmp_path fixtures for fresh/stale/corrupt pairs
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from har_capture.validation.artifacts import (
    compressed_sibling_pair,
    stale_compressed_sibling,
)


def _write_pair(tmp_path: Path, har_bytes: bytes, gz_of: bytes | None = None) -> Path:
    """Write device.sanitized.har plus a .gz of ``gz_of`` (default: matching)."""
    har = tmp_path / "device.sanitized.har"
    har.write_bytes(har_bytes)
    with gzip.open(tmp_path / "device.sanitized.har.gz", "wb") as f:
        f.write(har_bytes if gz_of is None else gz_of)
    return har


class TestCompressedSiblingPair:
    """Pair resolution from either member."""

    def test_resolves_from_har(self, tmp_path: Path) -> None:
        har = _write_pair(tmp_path, b"{}")
        pair = compressed_sibling_pair(har)
        assert pair == (har, tmp_path / "device.sanitized.har.gz")

    def test_resolves_from_gz(self, tmp_path: Path) -> None:
        har = _write_pair(tmp_path, b"{}")
        pair = compressed_sibling_pair(tmp_path / "device.sanitized.har.gz")
        assert pair == (har, tmp_path / "device.sanitized.har.gz")

    @pytest.mark.parametrize(
        ("present", "checked"),
        [
            ("har_only", "device.sanitized.har"),
            ("gz_only", "device.sanitized.har.gz"),
        ],
        ids=["har_without_gz", "gz_without_har"],
    )
    def test_incomplete_pair_is_none(self, tmp_path: Path, present: str, checked: str) -> None:
        """A lone member has nothing to diverge from."""
        if present == "har_only":
            (tmp_path / "device.sanitized.har").write_bytes(b"{}")
        else:
            with gzip.open(tmp_path / "device.sanitized.har.gz", "wb") as f:
                f.write(b"{}")
        assert compressed_sibling_pair(tmp_path / checked) is None

    def test_non_har_path_is_none(self, tmp_path: Path) -> None:
        other = tmp_path / "notes.txt"
        other.write_text("x")
        assert compressed_sibling_pair(other) is None


class TestStaleCompressedSibling:
    """Content divergence detection."""

    def test_fresh_pair_is_clean(self, tmp_path: Path) -> None:
        har = _write_pair(tmp_path, b'{"log": {"entries": []}}')
        assert stale_compressed_sibling(har) is None

    def test_stale_gz_is_reported_from_either_member(self, tmp_path: Path) -> None:
        """The reproduction: gz holds pre-review content the review scrubbed."""
        har = _write_pair(
            tmp_path,
            b'{"content": "Serial: SERIAL_deadbeef"}',
            gz_of=b'{"content": "Serial: 7S0245KL9BAAA"}',
        )
        for member in (har, tmp_path / "device.sanitized.har.gz"):
            message = stale_compressed_sibling(member)
            assert message is not None, f"stale pair must be reported when checking {member.name}"
            assert "stale" in message

    def test_corrupt_gz_is_reported(self, tmp_path: Path) -> None:
        har = tmp_path / "device.sanitized.har"
        har.write_bytes(b"{}")
        (tmp_path / "device.sanitized.har.gz").write_bytes(b"not gzip data")
        message = stale_compressed_sibling(har)
        assert message is not None
        assert "Cannot read" in message

    def test_lone_har_is_clean(self, tmp_path: Path) -> None:
        har = tmp_path / "device.sanitized.har"
        har.write_bytes(b"{}")
        assert stale_compressed_sibling(har) is None
