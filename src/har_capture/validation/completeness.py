"""Capture-completeness validation.

Reports what a finished capture contains, so the operator sees the gaps
before handing the HAR to anyone.

A HAR missing the auth exchange still looks complete — it parses, the
entries are well-formed, the tool reports success — and downstream an auth
config gets hand-authored from evidence that was never in the file. Two
failure modes produce that: recording that began mid-session (the browser
was already logged in), and a capture holding no submission at all.

Warns only. Captures are immutable evidence; nothing here mutates or
rejects a HAR.
"""

from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from har_capture.patterns import compile_pattern, get_session_cookie_patterns

MID_SESSION_CAPTURE = "mid_session_capture"
NO_POST_REQUESTS = "no_post_requests"


@dataclass(frozen=True)
class CompletenessWarning:
    """A gap found in a finished capture.

    Attributes:
        code: Stable identifier for the gap (see module-level constants)
        message: What is missing or suspect about the capture
        remedy: The action that produces a complete capture
    """

    code: str
    message: str
    remedy: str


@dataclass
class CaptureCompletenessReport:
    """What a finished capture contains.

    Attributes:
        total_entries: Number of request/response entries captured
        method_counts: Request count per HTTP method
        unique_urls: Number of distinct request URLs
        set_cookie_responses: Responses carrying a ``Set-Cookie`` header. Not
            proof a session was established — logout and preference cookies
            land here too — so it never drives a warning.
        first_request_session_cookies: Session-cookie names on the first
            request: the mid-session signal. "First" is by
            ``startedDateTime`` when every entry has one, else file order.
        warnings: Gaps found; empty when the capture looks complete
    """

    total_entries: int = 0
    method_counts: dict[str, int] = field(default_factory=dict)
    unique_urls: int = 0
    set_cookie_responses: int = 0
    first_request_session_cookies: list[str] = field(default_factory=list)
    warnings: list[CompletenessWarning] = field(default_factory=list)

    @property
    def post_count(self) -> int:
        """Number of POST requests captured."""
        return self.method_counts.get("POST", 0)

    @property
    def complete(self) -> bool:
        """True when no gaps were found."""
        return not self.warnings


def _compile_session_cookie_patterns(
    custom_patterns_path: Path | str | None = None,
) -> list[re.Pattern[str]]:
    """Compile the session-cookie name patterns, skipping invalid regexes."""
    compiled = (
        compile_pattern({"regex": pattern, "flags": ["IGNORECASE"]})
        for pattern in get_session_cookie_patterns(custom_patterns_path)
    )
    return [pattern for pattern in compiled if pattern is not None]


def _request_cookie_names(request: dict[str, Any]) -> list[str]:
    """Collect cookie names on a request, in first-appearance order.

    Reads both the parsed ``cookies`` array and the raw ``Cookie`` header —
    HAR producers populate one, the other, or both.
    """
    names: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            names.append(name)

    for cookie in request.get("cookies") or []:
        if isinstance(cookie, dict):
            _add(str(cookie.get("name", "")))

    for header in request.get("headers") or []:
        if not isinstance(header, dict) or str(header.get("name", "")).lower() != "cookie":
            continue
        # load() drops unparseable pairs rather than raising.
        parsed = SimpleCookie()
        parsed.load(str(header.get("value", "")))
        for name in parsed:
            _add(name)

    return names


def _has_set_cookie(response: dict[str, Any]) -> bool:
    """True if the response carries a Set-Cookie header."""
    return any(
        isinstance(header, dict) and str(header.get("name", "")).lower() == "set-cookie"
        for header in response.get("headers") or []
    )


def _first_entry(entries: list[Any]) -> dict[str, Any] | None:
    """Return the chronologically first entry.

    Entry order is trusted only as a fallback. HAR files from other tools
    are not guaranteed to be sorted, and the mid-session signal depends on
    genuinely reading the earliest request, so ``startedDateTime`` wins when
    every entry carries one.

    ISO-8601 stamps sort correctly as text as long as the UTC offset is
    consistent, which holds within a single file: every entry comes from one
    recorder. Comparing across mixed offsets would need real datetime
    parsing, and no HAR producer emits mixed offsets in one log.
    """
    usable = [e for e in entries if isinstance(e, dict)]
    if not usable:
        return None
    stamps = [str(e.get("startedDateTime") or "") for e in usable]
    if all(stamps):
        # The index is load-bearing, not decoration: it breaks ties so min()
        # never falls through to comparing the entry dicts (a TypeError).
        # Same-millisecond stamps are routine with parallel asset loads.
        return min(zip(stamps, range(len(usable)), usable, strict=True))[2]
    return usable[0]


def analyze_capture_completeness(
    har: dict[str, Any],
    custom_patterns_path: Path | str | None = None,
) -> CaptureCompletenessReport:
    """Report what a capture contains and what it is missing.

    On the capture path this runs against the raw HAR before bloat
    filtering, which can remove the true first entry. It is equally valid
    against a sanitized HAR from any source: cookie *values* are redacted
    by sanitization but names survive, and names are all this reads.

    Args:
        har: Parsed HAR data
        custom_patterns_path: Optional custom capture-settings file
            contributing extra session-cookie name patterns

    Returns:
        CaptureCompletenessReport with a coverage summary and any warnings
    """
    entries = har.get("log", {}).get("entries") or []

    report = CaptureCompletenessReport(total_entries=len(entries))

    urls: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if _has_set_cookie(entry.get("response") or {}):
            report.set_cookie_responses += 1
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "GET").upper()
        report.method_counts[method] = report.method_counts.get(method, 0) + 1
        url = str(request.get("url") or "")
        if url:
            urls.add(url)
    report.unique_urls = len(urls)

    first_entry = _first_entry(entries)
    first_request = first_entry.get("request") if first_entry else None
    if isinstance(first_request, dict):
        session_patterns = _compile_session_cookie_patterns(custom_patterns_path)
        report.first_request_session_cookies = [
            name
            for name in _request_cookie_names(first_request)
            if any(pattern.fullmatch(name) for pattern in session_patterns)
        ]

    if report.first_request_session_cookies:
        names = ", ".join(report.first_request_session_cookies)
        report.warnings.append(
            CompletenessWarning(
                code=MID_SESSION_CAPTURE,
                message=(
                    f"Recording began mid-session: session cookie(s) {names} were already "
                    "present on the first request, so the browser was logged in before "
                    "capture started. The login exchange is NOT in this file."
                ),
                remedy=(
                    "Log out of the device (or clear the browser's cookies for it), "
                    "then re-record and perform the login inside the capture."
                ),
            )
        )

    if not report.post_count:
        report.warnings.append(
            CompletenessWarning(
                code=NO_POST_REQUESTS,
                message=(
                    "No POST requests were captured — no form or auth submission was "
                    "recorded. If this device logs in via POST, the auth exchange is "
                    "NOT in this file."
                ),
                remedy=(
                    "Re-record and complete the full login (submit the form) while the capture is running."
                ),
            )
        )

    return report


def load_har(har_path: Path | str) -> dict[str, Any]:
    """Load a HAR file, transparently handling gzip.

    Args:
        har_path: Path to a ``.har`` or ``.har.gz`` file

    Returns:
        Parsed HAR data
    """
    har_path = Path(har_path)
    if har_path.suffix == ".gz":
        with gzip.open(har_path, "rt", encoding="utf-8") as f:
            gz_data: dict[str, Any] = json.load(f)
            return gz_data
    with open(har_path, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


def analyze_har_file(
    har_path: Path | str,
    custom_patterns_path: Path | str | None = None,
) -> CaptureCompletenessReport:
    """Report what the HAR at ``har_path`` contains and what it is missing.

    Args:
        har_path: Path to a ``.har`` or ``.har.gz`` file
        custom_patterns_path: Optional custom capture-settings file
            contributing extra session-cookie name patterns

    Returns:
        CaptureCompletenessReport with a coverage summary and any warnings
    """
    return analyze_capture_completeness(load_har(har_path), custom_patterns_path)
