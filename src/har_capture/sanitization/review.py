"""Recording the review's outcome in a sanitized HAR file.

Pass 2 (``apply_user_redactions``) works on parsed HAR data; this module is
the file side of it: apply the review's decisions to the sanitized HAR on
disk, record how the review ended, and keep the compressed copy — the file
contributors upload — identical to the reviewed one.

The decisions come from the interactive prompt or, where there is no terminal
to prompt in, from a review report whose items someone decided
(``read_review_decisions``, ``apply_review_decisions``). The report need not
be a file: the CLI passes it through its standard streams, so the flagged
values it holds are never written to disk.
"""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from har_capture.sanitization.har import HarValidationError, apply_user_redactions
from har_capture.sanitization.report import RedactionStatus

if TYPE_CHECKING:
    from har_capture.sanitization.report import ReviewOutcome, SanitizationReport

# The statuses that decide a flagged value in a review report: redact it, or
# keep it. ``flagged`` is an item nobody has decided.
_DECIDED = {status.value: status for status in (RedactionStatus.USER_REDACTED, RedactionStatus.USER_SKIPPED)}


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


def read_review_decisions(data: Any) -> dict[str, RedactionStatus]:
    """Read the decisions in a parsed review report: each decided value mapped to its status.

    The report is the JSON ``sanitize`` writes (``SanitizationReport.to_dict``)
    with an item's ``status`` set to ``"user"`` (redact it) or ``"skipped"``
    (keep it). An item left ``"flagged"`` is undecided and is not returned.

    Args:
        data: The parsed report

    Returns:
        ``{value: status}`` for every decided item

    Raises:
        ValueError: If it is not a review report, or holds a status that is
            none of ``user``, ``skipped`` and ``flagged``
    """
    items = data.get("flagged") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("not a review report: no 'flagged' list")
    decisions: dict[str, RedactionStatus] = {}
    for index, item in enumerate(items):
        value = item.get("value") if isinstance(item, dict) else None
        status = item.get("status") if isinstance(item, dict) else None
        if not isinstance(value, str) or not isinstance(status, str):
            raise ValueError(f"flagged item {index} needs a string 'value' and 'status'")
        if status in _DECIDED:
            decisions[value] = _DECIDED[status]
        elif status != RedactionStatus.FLAGGED.value:
            raise ValueError(
                f"flagged item {index} has status {status!r}: use 'user' to redact the value, "
                "'skipped' to keep it, or leave 'flagged' if it is undecided"
            )
    return decisions


def load_review_decisions(path: Path | str) -> dict[str, RedactionStatus]:
    """Read the decisions in a review report file (``read_review_decisions``).

    Args:
        path: The review report

    Returns:
        ``{value: status}`` for every decided item

    Raises:
        OSError: If the file cannot be read
        ValueError: If it is not JSON, or not a review report
    """
    with open(path, encoding="utf-8") as f:
        return read_review_decisions(json.load(f))


def apply_review_decisions(report: SanitizationReport, decisions: dict[str, RedactionStatus]) -> int:
    """Set each flagged value's status from ``decisions`` and return how many are left undecided.

    Decisions are matched on the flagged value itself, so a report made by one
    run decides the same values in another run of the same capture. A decision
    for a value this run did not flag is ignored.

    Args:
        report: The Pass 1 report of the run being reviewed
        decisions: ``load_review_decisions()`` of the decided report

    Returns:
        The number of flagged values with no decision
    """
    undecided = 0
    for flagged in report.flagged:
        status = decisions.get(flagged.original_value)
        if status is None:
            undecided += 1
        else:
            flagged.status = status
    return undecided
