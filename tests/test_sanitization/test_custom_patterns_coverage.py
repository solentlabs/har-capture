"""Cross-cutting coverage audit for ``custom_patterns`` propagation.

Every public sanitization entry point that accepts ``custom_patterns`` must
apply the override to every detection site reachable from that entry point.
This file enumerates every (entry_point x detection_site) pair as a
parametrized test and asserts the override takes effect.

Background: 0.7.0 shipped a ``ContextVar``-scoped ``custom_patterns`` override
but entered the scope only at two leaf entry points (``sanitize_post_data``,
``sanitize_html``). Three detection sites (``sanitize_header_value``,
structured ``queryString`` params, URL query params) ran from wrapper entry
points BEFORE the leaves were called, so ``custom_patterns`` silently no-op'd
when callers used ``sanitize_entry`` / ``sanitize_har`` / ``sanitize_har_file``.
0.7.1 closed the specific gap by entering both scopes at ``sanitize_entry``.

This file exists so the *class* of gap can't recur. Adding a new detection
site in source should require adding a matching row here; adding a new public
entry point that accepts ``custom_patterns`` likewise. A missing row is a
coverage claim without evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from har_capture.sanitization import (
    sanitize_entry,
    sanitize_har,
    sanitize_har_file,
    sanitize_html,
    sanitize_post_data,
)

# -----------------------------------------------------------------------------
# Audit constants
#
# SENSITIVE is a distinctive marker that must NEVER appear in sanitized output
# for any test row. Any assertion that finds it means the detection site did
# not honor custom_patterns for that entry point.
# -----------------------------------------------------------------------------

SENSITIVE = "COVERAGE_AUDIT_MUST_REDACT"

# Custom field-name (for fields.auto_redact_patterns coverage) and custom
# header-name (for headers.full_redact coverage). Chosen to not collide with
# any built-in pattern so that a row's redaction is attributable solely to
# the custom_patterns extension under test.
CUSTOM_FIELD_NAME = "xcovfield"
CUSTOM_HEADER_NAME = "x-coverage-audit"

CUSTOM_FIELD_PATTERNS: dict = {"fields": {"auto_redact_patterns": [CUSTOM_FIELD_NAME]}}
CUSTOM_HEADER_PATTERNS: dict = {"headers": {"full_redact": [CUSTOM_HEADER_NAME]}}


# -----------------------------------------------------------------------------
# Builders: produce a minimum input containing a single detection site.
# Each builder plants SENSITIVE at the call's detection site only — any
# other appearance of SENSITIVE in the output signals a false positive elsewhere.
# -----------------------------------------------------------------------------


def _wrap_request(request: dict) -> dict:
    return {
        "request": request,
        "response": {
            "status": 200,
            "headers": [],
            "content": {"text": "", "mimeType": "text/plain"},
        },
    }


def _postdata_form_params() -> dict:
    return {
        "mimeType": "application/x-www-form-urlencoded",
        "params": [{"name": CUSTOM_FIELD_NAME, "value": SENSITIVE}],
    }


def _postdata_urlencoded() -> dict:
    return {
        "mimeType": "application/x-www-form-urlencoded",
        "text": f"user=admin&{CUSTOM_FIELD_NAME}={SENSITIVE}",
    }


def _postdata_json() -> dict:
    return {
        "mimeType": "application/json",
        "text": json.dumps({CUSTOM_FIELD_NAME: SENSITIVE}),
    }


def _postdata_xml() -> dict:
    return {
        "mimeType": "text/xml",
        "text": f"<root><{CUSTOM_FIELD_NAME}>{SENSITIVE}</{CUSTOM_FIELD_NAME}></root>",
    }


def _html_inline_script() -> str:
    return f'localStorage.setItem("{CUSTOM_FIELD_NAME}", "{SENSITIVE}")'


def _entry_header() -> dict:
    return _wrap_request(
        {
            "method": "GET",
            "url": "http://example.com/",
            "headers": [{"name": CUSTOM_HEADER_NAME, "value": SENSITIVE}],
        }
    )


def _entry_querystring() -> dict:
    return _wrap_request(
        {
            "method": "GET",
            "url": "http://example.com/",
            "headers": [],
            "queryString": [{"name": CUSTOM_FIELD_NAME, "value": SENSITIVE}],
        }
    )


def _entry_url_query() -> dict:
    return _wrap_request(
        {
            "method": "GET",
            "url": f"http://example.com/path?{CUSTOM_FIELD_NAME}={SENSITIVE}",
            "headers": [],
        }
    )


def _entry_form_params() -> dict:
    return _wrap_request(
        {
            "method": "POST",
            "url": "http://example.com/",
            "headers": [],
            "postData": _postdata_form_params(),
        }
    )


def _entry_form_urlencoded() -> dict:
    return _wrap_request(
        {
            "method": "POST",
            "url": "http://example.com/",
            "headers": [],
            "postData": _postdata_urlencoded(),
        }
    )


def _entry_json_body() -> dict:
    return _wrap_request(
        {
            "method": "POST",
            "url": "http://example.com/",
            "headers": [],
            "postData": _postdata_json(),
        }
    )


def _entry_xml_body() -> dict:
    return _wrap_request(
        {
            "method": "POST",
            "url": "http://example.com/",
            "headers": [],
            "postData": _postdata_xml(),
        }
    )


def _entry_inline_script_response() -> dict:
    return {
        "request": {
            "method": "GET",
            "url": "http://example.com/",
            "headers": [],
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": {
                "text": _html_inline_script(),
                "mimeType": "text/html",
            },
        },
    }


# -----------------------------------------------------------------------------
# Entry-point invokers: call each public API and return the serialized result
# as a single string the assertion can search.
# -----------------------------------------------------------------------------


def _serialize(obj: object) -> str:
    if isinstance(obj, str):
        return obj
    return json.dumps(obj)


def _invoke_post_data(postdata: dict, custom_patterns: dict) -> str:
    return _serialize(sanitize_post_data(postdata, custom_patterns=custom_patterns))


def _invoke_html(html: str, custom_patterns: dict) -> str:
    return sanitize_html(html, salt=None, custom_patterns=custom_patterns)


def _invoke_entry(entry: dict, custom_patterns: dict) -> str:
    return _serialize(sanitize_entry(entry, salt=None, custom_patterns=custom_patterns))


def _invoke_har(entry: dict, custom_patterns: dict) -> str:
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "coverage-audit", "version": "0"},
            "entries": [entry],
        }
    }
    sanitized, _ = sanitize_har(har, salt=None, custom_patterns=custom_patterns)
    return _serialize(sanitized)


@pytest.fixture
def har_file_invoker(tmp_path: Path):
    """Returns an invoker closed over tmp_path so sanitize_har_file rows can be parametrized."""

    def invoke(entry: dict, custom_patterns: dict) -> str:
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "coverage-audit", "version": "0"},
                "entries": [entry],
            }
        }
        input_path = tmp_path / "in.har"
        input_path.write_text(json.dumps(har))
        output_path, _ = sanitize_har_file(
            str(input_path),
            str(tmp_path / "out.har"),
            salt=None,
            custom_patterns=custom_patterns,
        )
        return Path(output_path).read_text()

    return invoke


# -----------------------------------------------------------------------------
# Coverage matrix
#
# Each row: (id, invoker_or_None, builder, custom_patterns)
#
# The matrix below is the executable form of the coverage claim "every public
# entry point honors custom_patterns at every detection site reachable from
# that entry point." Adding a new detection site requires adding a row per
# entry point that reaches it. Adding a new entry point requires adding rows
# for every detection site it should cover.
#
# sanitize_har_file rows go in a separate parametrize because they need the
# tmp_path-bound invoker fixture.
# -----------------------------------------------------------------------------


# (id, invoker, builder, custom_patterns)
COVERAGE_MATRIX = [
    # ----- sanitize_post_data: detection sites reachable via postData -----
    ("post_data/form_params", _invoke_post_data, _postdata_form_params, CUSTOM_FIELD_PATTERNS),
    ("post_data/form_urlencoded", _invoke_post_data, _postdata_urlencoded, CUSTOM_FIELD_PATTERNS),
    ("post_data/json_body", _invoke_post_data, _postdata_json, CUSTOM_FIELD_PATTERNS),
    ("post_data/xml_body", _invoke_post_data, _postdata_xml, CUSTOM_FIELD_PATTERNS),
    # ----- sanitize_html: detection sites reachable via raw HTML -----
    ("html/inline_script_setitem", _invoke_html, _html_inline_script, CUSTOM_FIELD_PATTERNS),
    # ----- sanitize_entry: every detection site reachable from a full entry -----
    ("entry/header_full_redact", _invoke_entry, _entry_header, CUSTOM_HEADER_PATTERNS),
    ("entry/structured_querystring", _invoke_entry, _entry_querystring, CUSTOM_FIELD_PATTERNS),
    ("entry/url_query_param", _invoke_entry, _entry_url_query, CUSTOM_FIELD_PATTERNS),
    ("entry/form_params", _invoke_entry, _entry_form_params, CUSTOM_FIELD_PATTERNS),
    ("entry/form_urlencoded", _invoke_entry, _entry_form_urlencoded, CUSTOM_FIELD_PATTERNS),
    ("entry/json_body", _invoke_entry, _entry_json_body, CUSTOM_FIELD_PATTERNS),
    ("entry/xml_body", _invoke_entry, _entry_xml_body, CUSTOM_FIELD_PATTERNS),
    (
        "entry/response_html_inline_script",
        _invoke_entry,
        _entry_inline_script_response,
        CUSTOM_FIELD_PATTERNS,
    ),
    # ----- sanitize_har: same detection sites, wrapped in a HAR log -----
    ("har/header_full_redact", _invoke_har, _entry_header, CUSTOM_HEADER_PATTERNS),
    ("har/structured_querystring", _invoke_har, _entry_querystring, CUSTOM_FIELD_PATTERNS),
    ("har/url_query_param", _invoke_har, _entry_url_query, CUSTOM_FIELD_PATTERNS),
    ("har/form_params", _invoke_har, _entry_form_params, CUSTOM_FIELD_PATTERNS),
    ("har/form_urlencoded", _invoke_har, _entry_form_urlencoded, CUSTOM_FIELD_PATTERNS),
    ("har/json_body", _invoke_har, _entry_json_body, CUSTOM_FIELD_PATTERNS),
    ("har/xml_body", _invoke_har, _entry_xml_body, CUSTOM_FIELD_PATTERNS),
    ("har/response_html_inline_script", _invoke_har, _entry_inline_script_response, CUSTOM_FIELD_PATTERNS),
]


# sanitize_har_file rows — same coverage, invoker bound to tmp_path.
# (id, builder, custom_patterns)
HAR_FILE_MATRIX = [
    ("har_file/header_full_redact", _entry_header, CUSTOM_HEADER_PATTERNS),
    ("har_file/structured_querystring", _entry_querystring, CUSTOM_FIELD_PATTERNS),
    ("har_file/url_query_param", _entry_url_query, CUSTOM_FIELD_PATTERNS),
    ("har_file/form_params", _entry_form_params, CUSTOM_FIELD_PATTERNS),
    ("har_file/form_urlencoded", _entry_form_urlencoded, CUSTOM_FIELD_PATTERNS),
    ("har_file/json_body", _entry_json_body, CUSTOM_FIELD_PATTERNS),
    ("har_file/xml_body", _entry_xml_body, CUSTOM_FIELD_PATTERNS),
    ("har_file/response_html_inline_script", _entry_inline_script_response, CUSTOM_FIELD_PATTERNS),
]


class TestCustomPatternsCoverageAudit:
    """Cross-cutting audit of custom_patterns coverage.

    Every public entry point honors custom_patterns at every reachable
    detection site.

    Failure modes this test catches:
    - A new detection site added to sanitization code that doesn't read from
      the ContextVar scope.
    - A refactor that moves the scope entry out of a wrapper entry point so
      detection sites running before the leaf scopes stop seeing the override.
    - A new public entry point accepting custom_patterns that forgets to enter
      both the field and header scopes.
    """

    @pytest.mark.parametrize(
        ("desc", "invoker", "builder", "custom_patterns"),
        COVERAGE_MATRIX,
        ids=[row[0] for row in COVERAGE_MATRIX],
    )
    def test_detection_site_honors_custom_patterns(self, desc, invoker, builder, custom_patterns) -> None:
        """Every (entry_point x detection_site) pair must redact the custom-marked value."""
        body = builder()
        output = invoker(body, custom_patterns)
        assert SENSITIVE not in output, (
            f"{desc}: custom_patterns did not reach this detection site — "
            f"{SENSITIVE!r} leaked into the sanitized output: {output[:500]!r}"
        )

    @pytest.mark.parametrize(
        ("desc", "builder", "custom_patterns"),
        HAR_FILE_MATRIX,
        ids=[row[0] for row in HAR_FILE_MATRIX],
    )
    def test_sanitize_har_file_detection_site_honors_custom_patterns(
        self, desc, builder, custom_patterns, har_file_invoker
    ) -> None:
        """sanitize_har_file rows: same matrix, wrapped around tmp_path I/O."""
        body = builder()
        output = har_file_invoker(body, custom_patterns)
        assert SENSITIVE not in output, (
            f"{desc}: custom_patterns did not reach this detection site via "
            f"sanitize_har_file — {SENSITIVE!r} leaked: {output[:500]!r}"
        )

    def test_sensitive_marker_leaks_without_custom_patterns(self) -> None:
        """Control test: without custom_patterns, the marker is NOT redacted.

        Proves each positive row above is actually testing something — i.e.
        that the custom_patterns argument is what's driving redaction, not a
        built-in pattern coincidentally catching our marker.
        """
        # Pick one representative row and run it with custom_patterns=None.
        body = _entry_header()
        output = _invoke_entry(body, custom_patterns=None)  # type: ignore[arg-type]
        assert SENSITIVE in output, (
            "Control check failed: the test marker was redacted WITHOUT "
            "custom_patterns. Either a built-in pattern matches it (change "
            "SENSITIVE to something more distinctive) or the positive rows "
            "would pass even when the feature is broken."
        )
