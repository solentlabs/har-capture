"""Tests for capture-completeness validation.

Test Coverage:
    - Mid-session detection (Cookie header, cookies array, case-insensitive names)
    - No-submission detection (nothing that could carry a login)
    - Single-credential-submission detection (missing refused login)
    - What counts as a credential submission: form, urlencoded and JSON
      bodies of POST/PUT/PATCH, URL credentials (raw or annotated), and
      Basic/Digest headers counted once per distinct value
    - Raw/sanitized parity: sanitizing a capture never changes its gaps
    - Session vs. benign cookie-name matching against the built-in pattern list
    - Coverage summary counts (methods, unique URLs, Set-Cookie responses)
    - Malformed/empty HAR tolerance
    - Custom capture-settings merge for session cookie names
    - Pipeline integration: the report is attached to CaptureResult

Test Strategy:
    - Table-driven with @pytest.mark.parametrize
    - HAR fixtures in tests/fixtures/test_completeness.json
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from har_capture.patterns import clear_pattern_cache, get_password_field_patterns, get_session_cookie_patterns
from har_capture.sanitization import sanitize_har
from har_capture.validation.completeness import (
    DOCUMENT_WITHOUT_BODY,
    LOGIN_WITHOUT_COOKIES,
    MID_SESSION_CAPTURE,
    NO_CREDENTIAL_SUBMISSION,
    NO_ROOT_REQUEST,
    SINGLE_CREDENTIAL_SUBMISSION,
    analyze_capture_completeness,
)

FIXTURES_PATH = Path(__file__).parent.parent / "fixtures" / "test_completeness.json"
FIXTURES = json.loads(FIXTURES_PATH.read_text())


def _har(key: str, *, cookies: bool = True) -> dict[str, Any]:
    """Return a deep copy of a fixture HAR.

    The fixtures model a capture recorded by the capture window, where the
    device sets a cookie: ``cookies`` gives the first response a Set-Cookie
    header, so a row tests only the gap it names. ``cookies=False`` keeps the
    fixture as a browser export that left cookies out.
    """
    har = copy.deepcopy(FIXTURES[key])
    if cookies:
        entries = har.get("log", {}).get("entries") or []
        response = entries[0].get("response") if entries and isinstance(entries[0], dict) else None
        if isinstance(response, dict) and isinstance(response.get("headers"), list):
            response["headers"].append({"name": "Set-Cookie", "value": "lang=en"})
    return har


def _cookie_har(name: str) -> dict[str, Any]:
    """Return the probe HAR carrying a single cookie of the given name."""
    har = _har("cookie_probe_template")
    har["log"]["entries"][0]["request"]["headers"][0]["value"] = f"{name}=v"
    return har


# ┌──────────────────────────────────┬───────────────────────────────────────────────┬──────────────────────────────────────┐
# │ fixture_key                      │ expected_codes                                │ description                          │
# └──────────────────────────────────┴───────────────────────────────────────────────┴──────────────────────────────────────┘
#
# A write request (POST/PUT/PATCH) whose login the tool cannot read (HNAP
# phase one only, encrypted AuthData) must not draw "no submission": 117 CMM
# fleet captures have one, so only a capture with nothing that could carry a
# login does.
#
# fmt: off
WARNING_CASES = [
    # (fixture_key,                       expected_codes,                                   description)
    ("clean_login_flow",                  [],                                               "login_captured_no_warnings"),
    ("mid_session_cookie_header",         [MID_SESSION_CAPTURE],                            "phpsessid_in_cookie_header"),
    ("mid_session_cookies_array",         [MID_SESSION_CAPTURE],                            "jsessionid_in_cookies_array"),
    ("mid_session_and_no_submission",     [MID_SESSION_CAPTURE, NO_CREDENTIAL_SUBMISSION],  "both_gaps_reported"),
    ("no_credential_submission",          [NO_CREDENTIAL_SUBMISSION],                       "gets_only"),
    ("benign_first_request_cookie",       [],                                               "non_session_cookie_ignored"),
    ("empty_har",                         [NO_CREDENTIAL_SUBMISSION, NO_ROOT_REQUEST],                           "empty_capture"),
    ("single_credential_submission",      [SINGLE_CREDENTIAL_SUBMISSION],                   "one_login_no_refused_attempt"),
    ("two_credential_submissions",        [],                                               "refused_plus_real_login"),
    ("post_without_password_field",       [],                                               "action_post_is_not_a_login"),
    ("credential_urlencoded_text",        [SINGLE_CREDENTIAL_SUBMISSION],                   "urlencoded_text_body_counted"),
    ("credential_json_body",              [SINGLE_CREDENTIAL_SUBMISSION],                   "json_body_counted"),
    ("put_json_login",                    [SINGLE_CREDENTIAL_SUBMISSION],                   "put_json_login_counted"),
    ("hnap_two_phase",                    [SINGLE_CREDENTIAL_SUBMISSION],                   "hnap_empty_first_phase_not_counted"),
    ("basic_auth_only",                   [SINGLE_CREDENTIAL_SUBMISSION],                   "basic_header_resent_counted_once"),
    ("basic_auth_refused_then_accepted",  [],                                               "two_basic_values_two_submissions"),
    ("url_token_raw",                     [SINGLE_CREDENTIAL_SUBMISSION],                   "url_credential_counted"),
    ("url_token_sanitized_metadata",      [SINGLE_CREDENTIAL_SUBMISSION],                   "annotated_url_credential_counted"),
    ("put_without_credential",            [],                                               "put_write_request_not_no_submission"),
    ("no_root_request",                   [NO_ROOT_REQUEST],                                "deep_link_start_no_root"),
    ("root_without_slash",                [],                                               "bare_authority_is_root"),
    ("root_with_query",                   [],                                               "root_with_query_is_root"),
    ("root_post_counts",                  [],                                               "any_method_to_root_counts"),
    ("document_size_unknown",             [DOCUMENT_WITHOUT_BODY],                          "html_size_minus_one_no_text"),
    ("document_empty_text",               [DOCUMENT_WITHOUT_BODY],                          "html_empty_text_nonzero_size"),
    ("document_header_mime",              [DOCUMENT_WITHOUT_BODY],                          "html_from_content_type_header"),
    ("document_stored",                   [],                                               "html_with_body"),
    ("document_truly_empty",              [],                                               "html_size_zero_is_empty_not_lost"),
    ("bodyless_redirect",                 [],                                               "non_2xx_not_a_document"),
    ("bodyless_non_html",                 [],                                               "non_html_not_a_document"),
    ("packed_credential_form_two",        [],                                               "packed_arguments_form_counted_with_snmp_get"),
    ("packed_credential_form_one",        [SINGLE_CREDENTIAL_SUBMISSION],                   "packed_arguments_form_is_a_submission"),
    ("packed_credential_empty_value",     [],                                               "empty_packed_value_not_a_submission"),
    ("document_redirect_stub",            [],                                               "small_content_length_is_redirect_stub"),
    ("document_large_with_length",        [DOCUMENT_WITHOUT_BODY],                          "large_content_length_is_truncated_page"),
    ("document_zero_body_size",           [],                                               "zero_body_size_is_empty_reply"),
    ("document_lost_body_keeps_size",     [DOCUMENT_WITHOUT_BODY],                          "nonzero_body_size_is_lost_body"),
    ("document_unparsable_length",        [DOCUMENT_WITHOUT_BODY],                          "unparsable_content_length_is_not_a_stub"),
]
# fmt: on

SESSION_NAMES = FIXTURES["session_cookie_names"]["session"]
BENIGN_NAMES = FIXTURES["session_cookie_names"]["benign"]


class TestWarnings:
    """Gap detection."""

    @pytest.mark.parametrize(
        ("fixture_key", "expected_codes", "description"),
        WARNING_CASES,
        ids=[c[2] for c in WARNING_CASES],
    )
    def test_warning_codes(self, fixture_key: str, expected_codes: list[str], description: str) -> None:
        """Test each capture shape produces exactly the expected warnings."""
        report = analyze_capture_completeness(_har(fixture_key))

        assert [w.code for w in report.warnings] == expected_codes, description
        assert report.complete == (not expected_codes)

    def test_mid_session_warning_names_the_cookie(self) -> None:
        """Test the mid-session warning identifies the offending cookie."""
        report = analyze_capture_completeness(_har("mid_session_cookie_header"))

        assert report.first_request_session_cookies == ["PHPSESSID"]
        warning = report.warnings[0]
        assert "PHPSESSID" in warning.message
        assert "re-record" in warning.remedy

    def test_session_cookie_on_later_request_is_not_mid_session(self) -> None:
        """Test a session established during capture does not warn.

        clean_login_flow sets PHPSESSID mid-capture and sends it on a later
        request — that is a complete capture, not a mid-session one.
        """
        report = analyze_capture_completeness(_har("clean_login_flow"))

        assert report.first_request_session_cookies == []
        assert report.complete

    def test_cookie_name_reported_once_across_sources(self) -> None:
        """Test a cookie in both the array and the header is reported once.

        Names dedupe case-insensitively, empty names are dropped, and an
        unparseable pair in the header does not lose the real cookie.
        """
        report = analyze_capture_completeness(_har("mid_session_duplicate_sources"))

        assert report.first_request_session_cookies == ["PHPSESSID"]

    def test_out_of_order_entries_resolved_by_timestamp(self) -> None:
        """Test the earliest request wins even when written second.

        HAR files from other tools are not guaranteed to be sorted, and the
        mid-session signal is meaningless if read from the wrong entry.
        """
        report = analyze_capture_completeness(_har("out_of_order_entries"))

        assert report.first_request_session_cookies == ["PHPSESSID"]

    def test_identical_timestamps_do_not_raise(self) -> None:
        """Test tied timestamps resolve by position instead of crashing.

        Two requests in the same millisecond are routine with parallel asset
        loads; without a tiebreaker, min() would compare entry dicts and
        raise TypeError.
        """
        report = analyze_capture_completeness(_har("identical_timestamps"))

        assert report.first_request_session_cookies == ["PHPSESSID"]

    def test_partial_timestamps_fall_back_to_file_order(self) -> None:
        """Test sorting is skipped when any entry lacks startedDateTime."""
        report = analyze_capture_completeness(_har("partial_timestamps"))

        assert report.first_request_session_cookies == ["PHPSESSID"]

    def test_no_root_remedy_says_bare_address(self) -> None:
        """Test the no-root warning tells the contributor how to re-record."""
        warning = analyze_capture_completeness(_har("no_root_request")).warnings[0]

        assert "root" in warning.message
        assert "re-record" in warning.remedy.lower()
        assert "bare" in warning.remedy

    def test_unstored_documents_named_once_without_query(self) -> None:
        """Test body-less documents are listed deduped, query-free, and capped."""
        report = analyze_capture_completeness(_har("documents_many_unstored"))

        message = next(w.message for w in report.warnings if w.code == DOCUMENT_WITHOUT_BODY)
        assert "p0.html" in message
        assert "?x=1" not in message
        assert "and 2 more" in message

    def test_packed_credential_form_counts_by_post_url_not_snmp_get(self) -> None:
        """Test the packed `arguments` login form is the submission, never a GET beside it."""
        report = analyze_capture_completeness(_har("packed_credential_form_two"))

        assert report.credential_submission_counts == {"http://192.168.100.1/cgi-bin/basic_pwd_cgi": 2}

    def test_redirect_stubs_recorded_without_warning(self) -> None:
        """Test small body-less documents are listed on the report, not warned about."""
        report = analyze_capture_completeness(_har("document_redirect_stub"))

        assert report.redirect_stub_documents == [
            "http://192.168.100.1/",
            "http://192.168.100.1/cgi-bin/status_cgi",
        ]
        assert report.complete

    def test_warnings_do_not_mutate_the_har(self) -> None:
        """Test analysis leaves the HAR untouched (captures are evidence)."""
        har = _har("mid_session_cookie_header")
        before = copy.deepcopy(har)

        analyze_capture_completeness(har)

        assert har == before


class TestSessionCookieNames:
    """Cookie-name matching against the built-in pattern list."""

    @pytest.mark.parametrize("name", SESSION_NAMES)
    def test_session_names_detected(self, name: str) -> None:
        """Test known session cookie names trigger the mid-session warning."""
        report = analyze_capture_completeness(_cookie_har(name))

        assert report.first_request_session_cookies == [name]

    @pytest.mark.parametrize("name", BENIGN_NAMES)
    def test_benign_names_ignored(self, name: str) -> None:
        """Test non-session cookie names do not trigger a false warning."""
        report = analyze_capture_completeness(_cookie_har(name))

        assert report.first_request_session_cookies == []


SUBMISSION_CASES = FIXTURES["credential_submission_cases"]
SUBMISSION_URL_CASES = FIXTURES["submission_url_cases"]


def _submission_har(case: dict[str, Any]) -> dict[str, Any]:
    """Build a HAR holding one entry per request of a submission case."""
    entries = [
        {"request": copy.deepcopy(request), "response": {"status": 200, "headers": []}}
        for request in case["requests"]
    ]
    log: dict[str, Any] = {"entries": entries}
    if "sanitized_credentials" in case:
        log["_har_capture"] = {"_sanitized_credentials": copy.deepcopy(case["sanitized_credentials"])}
    return {"log": log}


class TestCredentialSubmissions:
    """What counts as a credential submission, one shape per row."""

    @pytest.mark.parametrize("case", SUBMISSION_CASES, ids=[c["id"] for c in SUBMISSION_CASES])
    def test_submission_count(self, case: dict[str, Any]) -> None:
        """Test each request shape contributes the expected submissions."""
        report = analyze_capture_completeness(_submission_har(case))

        assert report.credential_submission_count == case["count"], case["id"]

    @pytest.mark.parametrize("case", SUBMISSION_URL_CASES, ids=[c["id"] for c in SUBMISSION_URL_CASES])
    def test_submission_url_shown_without_query_or_userinfo(self, case: dict[str, Any]) -> None:
        """Test a submission is keyed by a URL that cannot carry its credential.

        ``get`` prints the report for the raw capture, so the query, fragment
        and userinfo — where a URL credential lives — never reach the key.
        """
        request = {
            "method": "POST",
            "url": case["url"],
            "postData": {"params": [{"name": "pwd", "value": "x1"}]},
        }

        report = analyze_capture_completeness({"log": {"entries": [{"request": request}]}})

        assert report.credential_submission_counts == {case["shown"]: 1}

    def test_single_warning_never_prints_the_url_credential(self) -> None:
        """Test the single-submission warning names the page, not the credential."""
        report = analyze_capture_completeness(_har("url_token_raw"))

        message = report.warnings[0].message
        assert "http://192.168.100.1/cmconnectionstatus.html" in message
        assert "login_" not in message
        assert "YWRtaW46" not in message


class TestSanitizedParity:
    """Sanitizing a capture never changes what completeness reports.

    Every signal is read from something the sanitizer keeps: field and
    cookie names, whether a value is empty, the header scheme, distinct
    header values (hashed per value), and the URL-credential annotation.
    """

    @pytest.mark.parametrize(
        ("fixture_key", "expected_codes", "description"),
        WARNING_CASES,
        ids=[c[2] for c in WARNING_CASES],
    )
    def test_same_gaps_after_sanitizing(
        self, fixture_key: str, expected_codes: list[str], description: str
    ) -> None:
        """Test each capture shape reports the same gaps once sanitized."""
        sanitized, _ = sanitize_har(_har(fixture_key))

        report = analyze_capture_completeness(sanitized)

        assert [w.code for w in report.warnings] == expected_codes, description

    @pytest.mark.parametrize("case", SUBMISSION_CASES, ids=[c["id"] for c in SUBMISSION_CASES])
    def test_same_count_after_sanitizing(self, case: dict[str, Any]) -> None:
        """Test each request shape counts the same once sanitized."""
        sanitized, _ = sanitize_har(_submission_har(case))

        report = analyze_capture_completeness(sanitized)

        assert report.credential_submission_count == case["count"], case["id"]

    def test_same_count_after_sanitizing_twice(self) -> None:
        """Test a re-sanitized URL-token capture still counts its login.

        The second run cannot recognize its own ``AUTH_`` placeholder, so
        only the annotation the first run wrote carries the submission.
        """
        once, _ = sanitize_har(_har("url_token_raw"))
        twice, _ = sanitize_har(once)

        report = analyze_capture_completeness(twice)

        assert [w.code for w in report.warnings] == [SINGLE_CREDENTIAL_SUBMISSION]


class TestCoverageSummary:
    """The operator-facing coverage numbers."""

    def test_summary_counts(self) -> None:
        """Test entry, method, URL, and Set-Cookie counts."""
        report = analyze_capture_completeness(_har("summary_counts"))

        assert report.total_entries == 5
        assert report.method_counts == {"GET": 3, "POST": 1, "DELETE": 1}
        assert report.unique_urls == 4
        assert report.set_cookie_responses == 2
        assert report.credential_submission_count == 0

    def test_empty_har_summary(self) -> None:
        """Test an empty capture reports zeros rather than raising."""
        report = analyze_capture_completeness(_har("empty_har"))

        assert report.total_entries == 0
        assert report.method_counts == {}
        assert report.unique_urls == 0
        assert report.credential_submission_count == 0

    def test_malformed_entries_do_not_inflate_counts(self) -> None:
        """Test entries without a usable request contribute no method or URL.

        The fixture has one real request plus a response-only entry and an
        empty entry. Those two are counted in total_entries (they are in the
        file) but must not register a phantom GET or an empty unique URL.
        """
        report = analyze_capture_completeness(_har("malformed_entries"))

        assert report.total_entries == 3
        assert report.method_counts == {"GET": 1}
        assert report.unique_urls == 1

    def test_request_without_url_counts_method_but_no_url(self) -> None:
        """Test a request missing its URL still counts as a request.

        The method is real evidence; an empty string is not a URL and must
        not land in the unique-URL count.
        """
        har = {"log": {"entries": [{"request": {"method": "POST"}, "response": {"headers": []}}]}}

        report = analyze_capture_completeness(har)

        assert report.method_counts == {"POST": 1}
        assert report.unique_urls == 0

    @pytest.mark.parametrize(
        "har",
        [
            {"log": {"entries": [{"request": "not-a-dict"}]}},
            {"log": {"entries": ["not-a-dict-entry"]}},
            {"log": {"entries": [{}]}},
        ],
        ids=["request_not_a_dict", "entry_not_a_dict", "entry_empty"],
    )
    def test_tolerates_malformed_first_entry(self, har: dict[str, Any]) -> None:
        """Test a malformed first entry degrades instead of raising.

        A library caller gets a usable report; only the capture pipeline has
        a try/except to fall back on.
        """
        report = analyze_capture_completeness(har)

        assert report.first_request_session_cookies == []

    def test_malformed_entry_still_finds_session_cookie(self) -> None:
        """Test non-dict headers are skipped without losing real cookies."""
        report = analyze_capture_completeness(_har("malformed_entries"))

        assert report.first_request_session_cookies == ["PHPSESSID"]

    def test_missing_log_key(self) -> None:
        """Test a HAR with no log section degrades to an empty report."""
        report = analyze_capture_completeness({})

        assert report.total_entries == 0
        assert [w.code for w in report.warnings] == [NO_CREDENTIAL_SUBMISSION, NO_ROOT_REQUEST]


class TestSessionCookiePatternLoading:
    """Pattern loading from capture.json.

    Each test brackets itself with ``clear_pattern_cache()`` because
    ``load_capture_settings`` caches per path, and a merged custom set must
    not leak into other tests.
    """

    @staticmethod
    def _custom_settings(tmp_path: Path, *name_patterns: str) -> Path:
        """Write a capture-settings file contributing session cookie patterns."""
        path = tmp_path / "custom_capture.json"
        path.write_text(json.dumps({"session_cookies": {"name_patterns": list(name_patterns)}}))
        return path

    def test_builtin_patterns_loaded(self) -> None:
        """Test the built-in session cookie patterns are non-empty."""
        assert get_session_cookie_patterns()

    def test_custom_patterns_extend_builtins(self, tmp_path: Path) -> None:
        """Test a custom file adds device names without dropping built-ins."""
        clear_pattern_cache()
        custom = self._custom_settings(tmp_path, "^devicesession$")

        try:
            patterns = get_session_cookie_patterns(custom)

            assert "^devicesession$" in patterns
            assert "^phpsessid$" in patterns
        finally:
            clear_pattern_cache()

    def test_custom_pattern_detects_device_cookie(self, tmp_path: Path) -> None:
        """Test a custom pattern feeds through to mid-session detection."""
        clear_pattern_cache()
        custom = self._custom_settings(tmp_path, "^devicesession$")

        try:
            report = analyze_capture_completeness(_cookie_har("DeviceSession"), custom_patterns_path=custom)

            assert report.first_request_session_cookies == ["DeviceSession"]
        finally:
            clear_pattern_cache()

    def test_invalid_regex_skipped(self, tmp_path: Path) -> None:
        """Test an invalid custom regex is skipped, and valid ones still match."""
        clear_pattern_cache()
        custom = self._custom_settings(tmp_path, "([unclosed")

        try:
            report = analyze_capture_completeness(
                _har("mid_session_cookie_header"), custom_patterns_path=custom
            )

            assert report.first_request_session_cookies == ["PHPSESSID"]
        finally:
            clear_pattern_cache()


class TestPasswordFieldPatternLoading:
    """Password-field pattern loading from capture.json."""

    def test_builtin_patterns_loaded(self) -> None:
        """Test the built-in password-field patterns are non-empty."""
        assert get_password_field_patterns()

    def test_custom_patterns_extend_builtins(self, tmp_path: Path) -> None:
        """Test a custom file adds device field names without dropping built-ins."""
        clear_pattern_cache()
        custom = tmp_path / "custom_capture.json"
        custom.write_text(json.dumps({"password_fields": {"name_patterns": ["geheimnis"]}}))

        try:
            patterns = get_password_field_patterns(custom)

            assert "geheimnis" in patterns
            assert "pwd" in patterns
        finally:
            clear_pattern_cache()


class TestPipelineIntegration:
    """The report reaches the caller through the capture pipeline."""

    def test_post_capture_pipeline_attaches_report(self, tmp_path: Path) -> None:
        """Test _run_post_capture_pipeline populates CaptureResult.completeness."""
        from har_capture.capture.browser import CaptureOptions, _run_post_capture_pipeline

        temp_har = tmp_path / "raw.har"
        temp_har.write_text(json.dumps(_har("mid_session_cookie_header")))

        result = _run_post_capture_pipeline(
            temp_path=temp_har,
            output_path=tmp_path / "out.har",
            sanitized_output=tmp_path / "out.sanitized.har",
            sanitize=False,
            compress=False,
            keep_raw=True,
            interactive=False,
            capture_options=CaptureOptions(),
        )

        assert result.completeness is not None
        assert [w.code for w in result.completeness.warnings] == [MID_SESSION_CAPTURE]

    def test_unreadable_har_does_not_fail_capture(self, tmp_path: Path) -> None:
        """Test a completeness failure degrades to None, not a failed capture."""
        from har_capture.capture.browser import CaptureOptions, _run_post_capture_pipeline

        temp_har = tmp_path / "raw.har"
        temp_har.write_text("{not json")

        result = _run_post_capture_pipeline(
            temp_path=temp_har,
            output_path=tmp_path / "out.har",
            sanitized_output=tmp_path / "out.sanitized.har",
            sanitize=False,
            compress=False,
            keep_raw=True,
            interactive=False,
            capture_options=CaptureOptions(),
        )

        assert result.completeness is None
        assert result.success


# (fixture_key, cookie placed on the first exchange, expected_codes, description)
# A form login with no cookie anywhere is the DevTools-export shape; any cookie
# on either side clears it, and a header-auth device (no form login) is never
# asked to re-record for cookies it may not use.
# fmt: off
LOGIN_COOKIE_CASES = [
    ("clean_login_flow",      None,                                                               [LOGIN_WITHOUT_COOKIES], "form_login_no_cookies"),
    ("clean_login_flow",      {"response_header": {"name": "Set-Cookie", "value": "auth=abc"}},   [],                      "set_cookie_header"),
    ("clean_login_flow",      {"request_header": {"name": "Cookie", "value": "auth=abc"}},        [],                      "cookie_header"),
    ("clean_login_flow",      {"request_cookies": [{"name": "auth", "value": "abc"}]},            [],                      "request_cookies_array"),
    ("clean_login_flow",      {"response_cookies": [{"name": "auth", "value": "abc"}]},           [],                      "response_cookies_array"),
    ("basic_auth_only",       None,                                                               [SINGLE_CREDENTIAL_SUBMISSION], "header_auth_not_asked_for_cookies"),
    ("no_credential_submission", None,                                                            [NO_CREDENTIAL_SUBMISSION], "no_login_no_cookie_warning"),
]
# fmt: on


def _with_cookie(fixture_key: str, cookie: dict[str, Any] | None) -> dict[str, Any]:
    """A fixture HAR stripped of every cookie, plus the given one on its first exchange."""
    har = _har(fixture_key, cookies=False)
    for item in har["log"]["entries"]:
        for side in (item["request"], item["response"]):
            side.pop("cookies", None)
            side["headers"] = [
                h for h in side["headers"] if h["name"].lower() not in ("cookie", "set-cookie")
            ]
    entry = har["log"]["entries"][0]
    for name, value in (cookie or {}).items():
        if name == "response_header":
            entry["response"].setdefault("headers", []).append(value)
        elif name == "request_header":
            entry["request"].setdefault("headers", []).append(value)
        elif name == "request_cookies":
            entry["request"]["cookies"] = value
        elif name == "response_cookies":
            entry["response"]["cookies"] = value
    return har


class TestLoginWithoutCookies:
    """A form login recorded without any cookie asks for a recapture."""

    @pytest.mark.parametrize(
        ("fixture_key", "cookie", "expected_codes", "description"),
        LOGIN_COOKIE_CASES,
        ids=[c[3] for c in LOGIN_COOKIE_CASES],
    )
    def test_warning_codes(
        self, fixture_key: str, cookie: dict[str, Any] | None, expected_codes: list[str], description: str
    ) -> None:
        """Test each cookie placement produces exactly the expected gaps."""
        report = analyze_capture_completeness(_with_cookie(fixture_key, cookie))

        assert [w.code for w in report.warnings] == expected_codes, description

    @pytest.mark.parametrize(
        ("fixture_key", "cookie", "expected_codes", "description"),
        LOGIN_COOKIE_CASES,
        ids=[c[3] for c in LOGIN_COOKIE_CASES],
    )
    def test_same_gaps_after_sanitizing(
        self, fixture_key: str, cookie: dict[str, Any] | None, expected_codes: list[str], description: str
    ) -> None:
        """Test the sanitizer neither hides nor invents the cookie gap."""
        sanitized, _ = sanitize_har(_with_cookie(fixture_key, cookie))

        report = analyze_capture_completeness(sanitized)

        assert [w.code for w in report.warnings] == expected_codes, description

    @pytest.mark.parametrize(
        ("creator", "expected_codes"),
        [
            ("Playwright", []),
            ("playwright", []),
            ("WebInspector", [LOGIN_WITHOUT_COOKIES]),
            ("composite (hybrid of two same-device captures)", [LOGIN_WITHOUT_COOKIES]),
            (None, [LOGIN_WITHOUT_COOKIES]),
        ],
        ids=["playwright", "playwright_lowercase", "devtools", "composite", "no_creator"],
    )
    def test_capture_window_files_are_not_asked_to_recapture(
        self, creator: str | None, expected_codes: list[str]
    ) -> None:
        """Test a cookieless file the capture window recorded is trusted; any other producer is not."""
        har = _with_cookie("clean_login_flow", None)
        har["log"].pop("creator", None)
        if creator is not None:
            har["log"]["creator"] = {"name": creator, "version": "1"}

        for source in (har, sanitize_har(copy.deepcopy(har))[0]):
            assert [w.code for w in analyze_capture_completeness(source).warnings] == expected_codes

    def test_remedy_names_the_capture_command(self) -> None:
        """Test the remedy points at har-capture's own capture, not the browser export."""
        warning = analyze_capture_completeness(_with_cookie("clean_login_flow", None)).warnings[0]

        assert "har-capture get" in warning.remedy
        assert "developer tools" in warning.remedy
