"""Sanitizer-version provenance check.

Every sanitized HAR records the har-capture version that produced it in
``log._har_capture.sanitization.version``. A capture sanitized by a release
older than ``MIN_SANITIZER_VERSION`` carries output a later release corrected,
and only a re-run from the raw capture repairs it.
"""

from __future__ import annotations

import re
from typing import Any

# The oldest release whose sanitized output is current. A release that changes
# what the sanitizer writes sets this to its own version in the release commit.
MIN_SANITIZER_VERSION = "0.13.2"

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
