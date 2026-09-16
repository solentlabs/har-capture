"""Capture-completeness validation.

Reports what a finished capture contains, so the operator sees the gaps
before handing the HAR to anyone.

A HAR missing the auth exchange still looks complete — it parses, the
entries are well-formed, the tool reports success — and downstream an auth
config gets hand-authored from evidence that was never in the file. Two
failure modes produce that: recording that began mid-session (the browser
was already logged in), and a capture holding no submission at all. A third
gap is a capture holding exactly one credential submission: the refused
login, as valuable as the success, was never recorded.

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
from urllib.parse import parse_qsl

from har_capture.patterns import (
    JSON_MAX_DEPTH,
    annotated_url_credential_entries,
    compile_pattern,
    get_password_field_patterns,
    get_session_cookie_patterns,
    iter_url_credentials,
    parse_json_container,
)
from har_capture.sanitization.har import check_har_types

MID_SESSION_CAPTURE = "mid_session_capture"
NO_CREDENTIAL_SUBMISSION = "no_credential_submission"
SINGLE_CREDENTIAL_SUBMISSION = "single_credential_submission"

# Methods whose body can submit a login: a form, or JSON (the SB8200 PHP
# firmware logs in with a JSON PUT).
_SUBMISSION_METHODS = frozenset({"POST", "PUT", "PATCH"})

# Authorization schemes whose value is the credential itself (RFC 7617,
# RFC 7616). A Bearer token presents a session already established.
_CREDENTIAL_SCHEMES = frozenset({"basic", "digest"})

# Userinfo ahead of the host, up to its last '@' (a password can hold one).
_USERINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#]*@")


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
        credential_submission_counts: Number of credential submissions per
            request URL (query, fragment and userinfo dropped — they can
            carry the credential, and ``get`` prints this for the raw
            capture). See ``analyze_capture_completeness`` for what counts.
            Exactly one submission in the whole capture means no refused
            login was recorded — auth-failure evidence is as valuable as the
            success and cannot be reconstructed later.
        warnings: Gaps found; empty when the capture looks complete
    """

    total_entries: int = 0
    method_counts: dict[str, int] = field(default_factory=dict)
    unique_urls: int = 0
    set_cookie_responses: int = 0
    first_request_session_cookies: list[str] = field(default_factory=list)
    credential_submission_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[CompletenessWarning] = field(default_factory=list)

    @property
    def credential_submission_count(self) -> int:
        """Total credential submissions across all URLs."""
        return sum(self.credential_submission_counts.values())

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


def _compile_password_field_patterns(
    custom_patterns_path: Path | str | None = None,
) -> list[re.Pattern[str]]:
    """Compile the password-parameter name patterns, skipping invalid regexes."""
    compiled = (
        compile_pattern({"regex": pattern, "flags": ["IGNORECASE"]})
        for pattern in get_password_field_patterns(custom_patterns_path)
    )
    return [pattern for pattern in compiled if pattern is not None]


def _is_password_name(name: str, patterns: list[re.Pattern[str]]) -> bool:
    """True if a field name matches a password-field pattern."""
    return any(pattern.search(name) for pattern in patterns)


def _json_has_password(data: dict[str, Any] | list[Any], patterns: list[re.Pattern[str]]) -> bool:
    """True if a parsed JSON body holds a non-empty string under a password-named key.

    Walks nested objects and arrays (an HNAP login nests its fields under
    ``Login``) to ``JSON_MAX_DEPTH``, the depth the sanitizer and validator
    read to. A non-string value is not a submission: containers are walked
    into, and a boolean or number under such a key is a setting
    (``showPassword: true``).
    """
    stack: list[tuple[Any, int]] = [(data, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > JSON_MAX_DEPTH:
            continue
        members = node.items() if isinstance(node, dict) else ((None, value) for value in node)
        for key, value in members:
            if isinstance(value, str):
                if value and key is not None and _is_password_name(str(key), patterns):
                    return True
            elif isinstance(value, dict | list):
                stack.append((value, depth + 1))
    return False


def _body_has_password(request: dict[str, Any], patterns: list[re.Pattern[str]]) -> bool:
    """True if a request body carries a non-empty value under a password-named field.

    Reads the parsed ``params`` array when present, else the ``text`` by its
    shape, not its declared type: a JSON object or array is walked by key,
    other text is read as urlencoded. Text that looks like JSON but does not
    parse is not read at all — ``parse_qsl`` would make field names out of
    its values. Only names and emptiness are read, and sanitization keeps
    both (it never empties a value, and keeps an empty one), so the answer
    is the same on raw and sanitized HARs.
    """
    post_data = request.get("postData")
    if not isinstance(post_data, dict):
        return False

    params = post_data.get("params")
    if isinstance(params, list) and params:
        return any(
            isinstance(param, dict)
            and isinstance(param.get("value"), str)
            and bool(param["value"])
            and _is_password_name(str(param.get("name", "")), patterns)
            for param in params
        )

    text = post_data.get("text")
    if not isinstance(text, str) or not text:
        return False
    parsed = parse_json_container(text)
    if parsed is not None:
        return _json_has_password(parsed, patterns)
    if text.lstrip().startswith(("{", "[")):
        return False
    return any(
        value and _is_password_name(name, patterns) for name, value in parse_qsl(text, keep_blank_values=True)
    )


def _credential_header_values(request: dict[str, Any]) -> list[str]:
    """Return the Basic/Digest ``Authorization`` values a request carries.

    The whole value is the identity of one submission: a browser resends the
    same Basic value on every request to the realm, and a refused attempt
    carries a different one. Sanitization hashes each value to its own
    placeholder, so distinct values stay distinct.
    """
    values: list[str] = []
    for header in request.get("headers") or []:
        if not isinstance(header, dict) or str(header.get("name", "")).lower() != "authorization":
            continue
        value = str(header.get("value", "")).strip()
        scheme, _, credentials = value.partition(" ")
        if scheme.lower() in _CREDENTIAL_SCHEMES and credentials.strip():
            values.append(value)
    return values


def _submission_url(url: str) -> str:
    """Return a request URL without its query, fragment or userinfo.

    Split by hand rather than with ``urlparse``, which raises on a URL it
    cannot parse (an unbalanced IPv6 bracket).
    """
    return _USERINFO_RE.sub(r"\1", re.split(r"[?#]", url, maxsplit=1)[0])


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
    against a sanitized HAR from any source: every signal read here survives
    sanitization — cookie and field names, whether a value is empty, the
    ``Authorization`` scheme, distinct header values, and the URL-credential
    annotation.

    A credential submission is a request that carries one of:

    - a POST/PUT/PATCH body with a non-empty value under a password-named
      field (form ``params``, urlencoded text, or JSON keys at any depth);
    - a base64 ``user:pass`` URL credential, or on a sanitized file an entry
      the ``_sanitized_credentials`` annotation lists;
    - a Basic or Digest ``Authorization`` value not seen on an earlier
      request (browsers resend it on every request to the realm).

    Each request counts once. "No submission" is reported only when the
    capture holds none of these and no POST/PUT/PATCH at all: a write request
    whose login this cannot read (a hashed or encrypted form) must not draw a
    false "re-record".

    Args:
        har: Parsed HAR data
        custom_patterns_path: Optional custom capture-settings file
            contributing extra session-cookie name patterns

    Returns:
        CaptureCompletenessReport with a coverage summary and any warnings
    """
    log = har.get("log", {})
    entries = log.get("entries") or []

    report = CaptureCompletenessReport(total_entries=len(entries))

    password_patterns = _compile_password_field_patterns(custom_patterns_path)
    annotated = annotated_url_credential_entries(log)
    header_values: set[str] = set()

    urls: set[str] = set()
    for index, entry in enumerate(entries):
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
        credential_headers = _credential_header_values(request)
        new_header = not header_values.issuperset(credential_headers)
        header_values.update(credential_headers)
        if (
            (method in _SUBMISSION_METHODS and _body_has_password(request, password_patterns))
            or index in annotated
            or next(iter_url_credentials(request), None) is not None
            or new_header
        ):
            key = _submission_url(url)
            report.credential_submission_counts[key] = report.credential_submission_counts.get(key, 0) + 1
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

    if report.credential_submission_count == 1:
        login_url = next(iter(report.credential_submission_counts))
        report.warnings.append(
            CompletenessWarning(
                code=SINGLE_CREDENTIAL_SUBMISSION,
                message=(
                    f"Only one credential submission was captured ({login_url}). "
                    "A deliberately refused login (wrong password) is NOT in this "
                    "file, so how the device rejects bad credentials cannot be "
                    "told apart from success later."
                ),
                remedy=(
                    "Re-record and submit a wrong password once before logging in "
                    "normally — both attempts in the same capture."
                ),
            )
        )

    if not report.credential_submission_count and not any(
        report.method_counts.get(method) for method in _SUBMISSION_METHODS
    ):
        report.warnings.append(
            CompletenessWarning(
                code=NO_CREDENTIAL_SUBMISSION,
                message=(
                    "No credential submission was captured — no POST, PUT or PATCH "
                    "request, no Basic or Digest Authorization header, and no URL "
                    "credential. If this device requires a login, the auth exchange "
                    "is NOT in this file."
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
    har_data = load_har(har_path)
    check_har_types(har_data)
    return analyze_capture_completeness(har_data, custom_patterns_path)
