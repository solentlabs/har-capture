"""Artifact-consistency checks for HAR file pairs.

A ``.har`` and its ``.har.gz`` sibling are the same evidence in two
encodings — every har-capture flow writes the ``.gz`` as a byte-for-byte
gzip of the final ``.har``. When they diverge, one of them predates the
other's last edit; the known failure mode is a compressed artifact
written before an interactive review scrubbed PII from the ``.har``
(observed on all three reviewed CM2500 captures, 2026-08-19), and the
``.gz`` is exactly the file contributors upload.
"""

from __future__ import annotations

import gzip
from pathlib import Path


def compressed_sibling_pair(path: Path) -> tuple[Path, Path] | None:
    """Resolve a ``(har, gz)`` pair from either member.

    Returns ``None`` when the other member of the pair does not exist.
    """
    path = Path(path)
    if path.name.endswith(".har.gz"):
        har_path = path.with_name(path.name.removesuffix(".gz"))
        gz_path = path
    elif path.name.endswith(".har"):
        har_path = path
        gz_path = path.with_name(path.name + ".gz")
    else:
        return None
    if not (har_path.exists() and gz_path.exists()):
        return None
    return har_path, gz_path


def stale_compressed_sibling(path: Path) -> str | None:
    """Check a ``.har``/``.har.gz`` pair for divergent content.

    Args:
        path: Either member of the pair.

    Returns:
        A human-readable problem description when the pair's contents
        differ (or the ``.gz`` is unreadable), else ``None`` — including
        when there is no complete pair to compare.
    """
    pair = compressed_sibling_pair(path)
    if pair is None:
        return None
    har_path, gz_path = pair

    try:
        with gzip.open(gz_path, "rb") as f:
            gz_content = f.read()
    except (OSError, gzip.BadGzipFile) as e:
        return f"Cannot read {gz_path}: {e}"

    try:
        har_content = har_path.read_bytes()
    except OSError as e:
        return f"Cannot read {har_path}: {e}"

    if gz_content != har_content:
        return (
            f"{gz_path.name} does not match {har_path.name} — the compressed "
            "copy is stale and may still contain values scrubbed from the "
            f".har. Regenerate it (gzip -kf -9 {har_path.name}) before sharing."
        )
    return None
