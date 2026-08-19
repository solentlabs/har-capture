"""Tests for capture-completeness validation.

Test Coverage:
    - Mid-session detection (Cookie header, cookies array, case-insensitive names)
    - Zero-POST detection
    - Single-credential-POST detection (missing refused login)
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
from har_capture.validation.completeness import (
    MID_SESSION_CAPTURE,
    NO_POST_REQUESTS,
    SINGLE_CREDENTIAL_POST,
    analyze_capture_completeness,
)

FIXTURES_PATH = Path(__file__).parent.parent / "fixtures" / "test_completeness.json"
FIXTURES = json.loads(FIXTURES_PATH.read_text())


def _har(key: str) -> dict[str, Any]:
    """Return a deep copy of a fixture HAR."""
    return copy.deepcopy(FIXTURES[key])


def _cookie_har(name: str) -> dict[str, Any]:
    """Return the probe HAR carrying a single cookie of the given name."""
    har = _har("cookie_probe_template")
    har["log"]["entries"][0]["request"]["headers"][0]["value"] = f"{name}=v"
    return har


# fmt: off
WARNING_CASES = [
    # (fixture_key,               expected_codes,                            description)
    ("clean_login_flow",          [],                                        "login_captured_no_warnings"),
    ("mid_session_cookie_header", [MID_SESSION_CAPTURE],                     "phpsessid_in_cookie_header"),
    ("mid_session_cookies_array", [MID_SESSION_CAPTURE],                     "jsessionid_in_cookies_array"),
    ("mid_session_and_no_post",   [MID_SESSION_CAPTURE, NO_POST_REQUESTS],   "both_gaps_reported"),
    ("no_post_requests",          [NO_POST_REQUESTS],                        "gets_only"),
    ("benign_first_request_cookie", [],                                      "non_session_cookie_ignored"),
    ("empty_har",                 [NO_POST_REQUESTS],                        "empty_capture"),
    ("single_credential_post",    [SINGLE_CREDENTIAL_POST],                  "one_login_no_refused_attempt"),
    ("two_credential_posts",      [],                                        "refused_plus_real_login"),
    ("post_without_password_field", [],                                      "action_post_is_not_a_login"),
    ("credential_post_urlencoded_text", [SINGLE_CREDENTIAL_POST],            "urlencoded_text_body_counted"),
    ("credential_post_json_body_not_counted", [],                            "json_body_with_equals_not_counted"),
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


class TestCoverageSummary:
    """The operator-facing coverage numbers."""

    def test_summary_counts(self) -> None:
        """Test entry, method, URL, and Set-Cookie counts."""
        report = analyze_capture_completeness(_har("summary_counts"))

        assert report.total_entries == 5
        assert report.method_counts == {"GET": 3, "POST": 1, "DELETE": 1}
        assert report.unique_urls == 4
        assert report.set_cookie_responses == 2
        assert report.post_count == 1

    def test_empty_har_summary(self) -> None:
        """Test an empty capture reports zeros rather than raising."""
        report = analyze_capture_completeness(_har("empty_har"))

        assert report.total_entries == 0
        assert report.method_counts == {}
        assert report.unique_urls == 0
        assert report.post_count == 0

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
        assert [w.code for w in report.warnings] == [NO_POST_REQUESTS]


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
