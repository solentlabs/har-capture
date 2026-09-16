"""Recording the interactive review's outcome in a sanitized HAR file.

Pass 2 (``apply_user_redactions``) works on parsed HAR data; this module is
the file side of it: apply the review's decisions to the sanitized HAR on
disk, record how the review ended, and keep the compressed copy — the file
contributors upload — identical to the reviewed one.
"""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from har_capture.sanitization.har import HarValidationError, apply_user_redactions

if TYPE_CHECKING:
    from har_capture.sanitization.report import ReviewOutcome, SanitizationReport


class StaleCompressedError(OSError):
    """The reviewed HAR was written, but its compressed copy could not be.

    The compressed file still holds its pre-review content — every value the
    review scrubbed — so it must not be shared.

    Attributes:
        compressed_path: The stale compressed file
    """

    def __init__(self, compressed_path: Path, cause: OSError) -> None:
        super().__init__(f"Failed to regenerate compressed file {compressed_path}: {cause}")
        self.compressed_path = compressed_path


def write_compressed_copy(source: Path, compressed_path: Path, compresslevel: int = 9) -> None:
    """Write ``compressed_path`` as a gzip of ``source``, byte for byte.

    Args:
        source: File to compress
        compressed_path: Compressed file to (re)write
        compresslevel: Gzip level, 1-9

    Raises:
        OSError: If either file cannot be read or written
    """
    with open(source, "rb") as f_in, gzip.open(compressed_path, "wb", compresslevel=compresslevel) as f_out:
        f_out.write(f_in.read())


def record_review(
    har_path: Path | str,
    report: SanitizationReport,
    outcome: ReviewOutcome,
    compressed_path: Path | str | None = None,
) -> Path | None:
    """Apply a review's decisions to a sanitized HAR file and record how it ended.

    Writes ``log._har_capture.sanitization.review`` (the outcome) and the
    ``user_redacted`` / ``user_skipped`` counts, applies every value the user
    chose to redact (``apply_user_redactions``), and replaces the file
    atomically. Then the compressed copy is rewritten from it: the one named,
    or an existing ``<har_path>.gz``. A ``.gz`` compressed before the review
    would otherwise keep every value the review scrubbed, in exactly the
    artifact contributors upload.

    Args:
        har_path: The sanitized HAR file
        report: The Pass 1 report, carrying the user's decisions
        outcome: How the review ended
        compressed_path: Compressed copy to rewrite; ``None`` rewrites an
            existing ``<har_path>.gz`` sibling

    Returns:
        The compressed file rewritten, or None when there was none

    Raises:
        OSError: If the file cannot be read or written; the original is kept
        ValueError: If the file is not JSON, or not a HAR
        StaleCompressedError: If the HAR was written but its compressed copy
            could not be
    """
    har_path = Path(har_path)
    with open(har_path, encoding="utf-8") as f:
        data = json.load(f)

    data = apply_user_redactions(data, report)
    if not isinstance(data["log"], dict):
        raise HarValidationError("'log' must be an object", "log")
    meta = data["log"].setdefault("_har_capture", {}).setdefault("sanitization", {})
    meta["review"] = outcome.value
    meta["user_redacted"] = report.total_user_redacted
    meta["user_skipped"] = report.total_user_skipped

    # LF on every platform, as sanitize_har_file writes it.
    tmp_file = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed by the with below
        mode="w", encoding="utf-8", newline="\n", dir=har_path.parent, delete=False, suffix=".har.tmp"
    )
    tmp_path = Path(tmp_file.name)
    try:
        with tmp_file:
            json.dump(data, tmp_file, indent=2)
        tmp_path.replace(har_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    if compressed_path is None:
        sibling = Path(str(har_path) + ".gz")
        compressed_path = sibling if sibling.exists() else None
    if compressed_path is None:
        return None
    compressed_path = Path(compressed_path)
    try:
        write_compressed_copy(har_path, compressed_path)
    except OSError as e:
        raise StaleCompressedError(compressed_path, e) from e
    return compressed_path
