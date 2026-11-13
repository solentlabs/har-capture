"""Checks on what a sanitized HAR records about its own sanitization.

Every sanitized HAR records the har-capture version that produced it in
``log._har_capture.sanitization.version``. A capture sanitized by a release
older than ``MIN_SANITIZER_VERSION`` carries output a later release corrected,
and only a re-run from the raw capture repairs it.

It also records how the review of its flagged values ended (``review``) and
how many were flagged (``flagged_total``). A review nobody finished leaves
every flagged value in the file as captured.
"""

from __future__ import annotations

import re
from typing import Any

# The oldest release whose sanitized output is current. A release that changes
# what the sanitizer writes sets this to its own version in the release commit.
MIN_SANITIZER_VERSION = "0.19.0"

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.match(text)
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def stale_sanitizer_version(log: dict[str, Any]) -> str | None:
    """Return the recorded sanitizer version if it predates ``MIN_SANITIZER_VERSION``.

    ``None`` when the version is current, or when the file records none: an
    unsanitized capture, or one with no readable version, has nothing to compare.
    """
    metadata = log.get("_har_capture")
    sanitization = metadata.get("sanitization") if isinstance(metadata, dict) else None
    recorded = sanitization.get("version") if isinstance(sanitization, dict) else None
    if not isinstance(recorded, str):
        return None
    parsed = _parse_version(recorded)
    minimum = _parse_version(MIN_SANITIZER_VERSION)
    if parsed is None or minimum is None or parsed >= minimum:
        return None
    return recorded


# The review outcomes that mean nobody decided the flagged values: there was no
# terminal to ask in, or the user left the review part-way (``ReviewOutcome``).
UNREVIEWED_OUTCOMES = frozenset({"no_tty", "cancelled"})


def unreviewed_flagged(log: dict[str, Any]) -> tuple[str, int] | None:
    """Return ``(outcome, undecided count)`` when the file records flagged values nobody decided.

    ``None`` when the review was finished or skipped by choice, when nothing
    was flagged, or when the file records no review: an unsanitized capture,
    or one a library caller sanitized without one.
    """
    metadata = log.get("_har_capture")
    sanitization = metadata.get("sanitization") if isinstance(metadata, dict) else None
    if not isinstance(sanitization, dict):
        return None
    outcome = sanitization.get("review")
    flagged = sanitization.get("flagged_total")
    if not isinstance(outcome, str) or outcome not in UNREVIEWED_OUTCOMES:
        return None
    if not isinstance(flagged, int) or isinstance(flagged, bool):
        return None
    # A review report can decide some values and leave the rest (``cancelled``).
    for decided in (sanitization.get("user_redacted"), sanitization.get("user_skipped")):
        if isinstance(decided, int) and not isinstance(decided, bool):
            flagged -= decided
    return (outcome, flagged) if flagged > 0 else None
