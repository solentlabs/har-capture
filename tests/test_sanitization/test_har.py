"""Tests for HAR sanitization utilities.

This module tests sanitization of HTTP Archive (HAR) format files,
ensuring sensitive data is redacted while preserving debugging utility.

Test Coverage:
    - Sensitive field detection in various HAR sections
    - Header sanitization (Authorization, Cookie, Set-Cookie)
    - POST data sanitization (form fields, JSON payloads)
    - Entry-level sanitization (requests and responses)
    - Full HAR file sanitization end-to-end
    - Correlation-preserving redaction with salted hashes

Test Strategy:
    - Unit tests for each sanitization layer
    - Integration tests for complete HAR processing
    - Validation that non-sensitive data is preserved
    - Hash consistency verification across values

Dependencies:
    - pytest for test framework
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from har_capture.patterns import Hasher
from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.har import (
    HarValidationError,
    _decode_base64_json,
    _detect_client_side_cookies,
    _detect_url_credential_entries,
    _embed_sanitization_metadata,
    _extract_url_credential_raw,
    _is_echoed_credential,
    _parse_cookie_names,
    _parse_set_cookie_name,
    _sanitize_form_urlencoded,
    _sanitize_json_recursive,
    _sanitize_string_patterns,
    apply_user_redactions,
    is_flaggable_field,
    is_sensitive_field,
    sanitize_entry,
    sanitize_har,
    sanitize_har_file,
    sanitize_header_value,
    sanitize_post_data,
    validate_har_structure,
)
from har_capture.sanitization.report import (
    FlaggedValue,
    HeuristicMode,
    RedactionStatus,
    SanitizationReport,
)

# =============================================================================
# Fixture Loading
# =============================================================================

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _load_fixture(name: str) -> dict:
    """Load a JSON fixture file and return the parsed dict."""
    with open(_FIXTURES_DIR / name) as f:
        return json.load(f)


_HAR_FIXTURE = _load_fixture("test_har.json")

# =============================================================================
# Test Data Tables -- large tables loaded from tests/fixtures/test_har.json
# =============================================================================

# Sensitive field detection: (field_name, expected, id)
SENSITIVE_FIELD_CASES = [
    (c["field_name"], c["expected"], c["id"]) for c in _HAR_FIXTURE["sensitive_field_cases"]
]

# Header redaction: (header_name, header_value, expected_contains, id)
HEADER_REDACTION_CASES = [
    (c["header_name"], c["header_value"], c["expected_contains"], c["id"])
    for c in _HAR_FIXTURE["header_redaction_cases"]
]

# ┌─────────────────────────┬─────────────────────────────┬─────────────────────┐
# │ header_name             │ header_value                │ description         │
# ├─────────────────────────┼─────────────────────────────┼─────────────────────┤
# │ HTTP header name        │ Value that should be gone   │ test case name      │
# └─────────────────────────┴─────────────────────────────┴─────────────────────┘
#
# fmt: off
HEADER_VALUE_REMOVED_CASES = [
    ("Authorization",       "Bearer abc123xyz",           "auth_bearer_removed"),
    ("Cookie",              "session=abc123",             "cookie_value_removed"),
    ("Set-Cookie",          "session=xyz789; Path=/",     "set_cookie_value_removed"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestSensitiveFieldDetection:
    """Tests for sensitive field detection."""

    @pytest.mark.parametrize(
        ("field_name", "expected", "desc"),
        SENSITIVE_FIELD_CASES,
        ids=[c[2] for c in SENSITIVE_FIELD_CASES],
    )
    def test_sensitive_field_detection(self, field_name: str, expected: bool, desc: str) -> None:
        """Test detection of sensitive vs safe field names."""
        result = is_sensitive_field(field_name)
        assert result is expected, f"{desc}: '{field_name}' should be {'sensitive' if expected else 'safe'}"


class TestHeaderSanitization:
    """Tests for header value sanitization."""

    @pytest.mark.parametrize(
        ("name", "value", "expected_contains", "desc"),
        HEADER_REDACTION_CASES,
        ids=[c[3] for c in HEADER_REDACTION_CASES],
    )
    def test_header_sanitization(self, name: str, value: str, expected_contains: str, desc: str) -> None:
        """Test header value sanitization."""
        result = sanitize_header_value(name, value)
        assert expected_contains in result, f"{desc}: result should contain '{expected_contains}'"

    @pytest.mark.parametrize(
        ("name", "value", "desc"),
        HEADER_VALUE_REMOVED_CASES,
        ids=[c[2] for c in HEADER_VALUE_REMOVED_CASES],
    )
    def test_sensitive_value_removed(self, name: str, value: str, desc: str) -> None:
        """Test sensitive header values are removed."""
        result = sanitize_header_value(name, value)
        # Extract the actual secret part (after = for cookies, whole value for auth)
        if "=" in value:
            secret = value.split("=", maxsplit=1)[1].split(";", maxsplit=1)[0]
        else:
            secret = value.rsplit(" ", maxsplit=1)[-1] if " " in value else value
        assert secret not in result, f"{desc}: secret '{secret}' should be removed"


class TestSchemeRedactBranch:
    """Tests for the ``scheme_redact`` bucket on ``sanitize_header_value``.

    Authorization-style headers carry "Scheme credentials". Preserving the
    scheme token (when it matches a known RFC scheme) keeps the protocol
    shape intact for downstream consumers without leaking the secret.
    Unknown schemes fall through to full redaction so a non-standard
    leading token can't escape.
    """

    @pytest.mark.parametrize(
        ("scheme",),
        [("Basic",), ("Bearer",), ("Digest",), ("NTLM",), ("Negotiate",), ("OAuth",)],
        ids=["basic", "bearer", "digest", "ntlm", "negotiate", "oauth"],
    )
    def test_known_scheme_preserved_credential_redacted(self, scheme: str) -> None:
        value = f"{scheme} the_secret_part_abc123"
        result = sanitize_header_value("Authorization", value)
        assert result.startswith(f"{scheme} "), f"scheme {scheme!r} must be preserved"
        assert "the_secret_part_abc123" not in result

    def test_scheme_casing_preserved_as_sent(self) -> None:
        """Lowercase ``bearer`` is still a known scheme; original casing is preserved in output."""
        assert sanitize_header_value("Authorization", "bearer xyz") == "bearer [REDACTED]"

    def test_unknown_scheme_falls_through_to_full_redact(self) -> None:
        """A non-RFC scheme is not preserved — the whole value is redacted."""
        result = sanitize_header_value("Authorization", "FancyScheme abc123")
        assert "FancyScheme" not in result
        assert "abc123" not in result
        assert result == "[REDACTED]"

    def test_no_whitespace_falls_through_to_full_redact(self) -> None:
        """A single token with no scheme/credential split → full redact."""
        assert sanitize_header_value("Authorization", "SoloToken") == "[REDACTED]"

    def test_empty_value_full_redacts(self) -> None:
        """An empty Authorization value is fully redacted (no token to preserve)."""
        assert sanitize_header_value("Authorization", "") == "[REDACTED]"

    def test_lowercase_header_name_still_matches(self) -> None:
        """Header-name matching is case-insensitive."""
        assert sanitize_header_value("authorization", "Bearer xyz") == "Bearer [REDACTED]"

    def test_scheme_preserved_with_hasher_yields_stable_tag(self) -> None:
        """With a hasher, the credential becomes a stable AUTH_<hash> tag — same value, same tag."""
        from har_capture.patterns import Hasher

        hasher = Hasher(salt="test-salt")
        r1 = sanitize_header_value("Authorization", "Bearer abc123", hasher=hasher)
        r2 = sanitize_header_value("Authorization", "Bearer abc123", hasher=hasher)
        assert r1 == r2
        assert r1.startswith("Bearer ")
        assert r1.split(" ", 1)[1].startswith("AUTH_")
        # Different credential → different tag.
        r3 = sanitize_header_value("Authorization", "Bearer different_value", hasher=hasher)
        assert r3 != r1
        assert r3.startswith("Bearer ")

    def test_leading_whitespace_tolerated(self) -> None:
        """A leading space before the scheme shouldn't defeat the split."""
        result = sanitize_header_value("Authorization", "  Bearer abc123")
        assert result == "Bearer [REDACTED]"


class TestPostDataSanitization:
    """Tests for POST data sanitization."""

    # fmt: off
    POST_PARAM_CASES = [
        # (field_name, field_value, should_redact, description)
        ("loginPassword",   "secret123",    True,   "password_redacted"),
        ("userPassword",    "mypass",       True,   "user_password_redacted"),
        ("auth_token",      "tok123",       True,   "auth_token_redacted"),
        ("loginName",       "admin",        False,  "login_name_flagged_not_redacted"),
        ("email",           "a@b.com",      False,  "email_preserved"),
        ("channel",         "123",          False,  "channel_preserved"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("field_name", "field_value", "should_redact", "desc"),
        POST_PARAM_CASES,
        ids=[c[3] for c in POST_PARAM_CASES],
    )
    def test_post_param_sanitization(
        self, field_name: str, field_value: str, should_redact: bool, desc: str
    ) -> None:
        """Test POST parameter sanitization."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": field_name, "value": field_value}],
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        result_value = result["params"][0]["value"]

        if should_redact:
            assert result_value == "[REDACTED]", f"{desc}: value should be redacted"
        else:
            assert result_value == field_value, f"{desc}: value should be preserved"

    def test_sanitizes_password_in_text(self) -> None:
        """Test password in text redaction."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "fieldName=admin&loginPassword=secret123",
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        assert "fieldName=admin" in result["text"]
        assert "loginPassword=[REDACTED]" in result["text"]
        assert "secret123" not in result["text"]

    def test_sanitizes_json_post_data(self) -> None:
        """Test JSON password redaction."""
        post_data = {
            "mimeType": "application/json",
            "text": '{"displayName": "admin", "password": "secret123"}',
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        parsed = json.loads(result["text"])
        assert parsed["displayName"] == "admin"
        assert parsed["password"] == "[REDACTED]"

    def test_sanitizes_nested_json(self) -> None:
        """Test nested JSON password redaction with recursive handling."""
        post_data = {
            "mimeType": "application/json",
            "text": '{"displayName": "admin", "password": "secret"}',
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        parsed = json.loads(result["text"])
        assert parsed["displayName"] == "admin"
        assert parsed["password"] == "[REDACTED]"

    # fmt: off
    EDGE_CASES = [
        (None,  None,   "none_returns_none"),
        ({},    {},     "empty_returns_empty"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("input_data", "expected", "desc"),
        EDGE_CASES,
        ids=[c[2] for c in EDGE_CASES],
    )
    def test_edge_cases(self, input_data, expected, desc: str) -> None:
        """Test edge cases."""
        result = sanitize_post_data(input_data)
        assert result == expected, f"{desc}"


# -----------------------------------------------------------------------------
# Fixture-driven tables for sanitize_post_data(..., custom_patterns=...)
# -----------------------------------------------------------------------------

CUSTOM_PATTERNS_TEXT_CASES = [
    (
        c["id"],
        c["post_data"],
        c["custom_patterns"],
        c["must_contain"],
        c["must_not_contain"],
    )
    for c in _HAR_FIXTURE["custom_patterns_cases"]
]

CUSTOM_PATTERNS_PARAMS_CASES = [
    (
        c["id"],
        c["params"],
        c["custom_patterns"],
        c["expected_values"],
    )
    for c in _HAR_FIXTURE["custom_patterns_params_cases"]
]


class TestPostDataCustomPatterns:
    """Per-call ``custom_patterns`` extension on ``sanitize_post_data``.

    Table-driven: each case in ``tests/fixtures/test_har.json`` under
    ``custom_patterns_cases`` / ``custom_patterns_params_cases`` exercises one
    slice of the (MIME type x custom_patterns x field shape) matrix. The
    fixture is the source of truth for the positive matrix; the standalone
    methods below cover identities (None vs omission) and invariants that
    don't fit the table shape.
    """

    @pytest.mark.parametrize(
        ("desc", "post_data", "custom_patterns", "must_contain", "must_not_contain"),
        CUSTOM_PATTERNS_TEXT_CASES,
        ids=[c[0] for c in CUSTOM_PATTERNS_TEXT_CASES],
    )
    def test_text_body_redaction_matrix(
        self,
        desc: str,
        post_data: dict,
        custom_patterns: dict | None,
        must_contain: list[str],
        must_not_contain: list[str],
    ) -> None:
        """Exercise form / JSON / XML bodies x (default, custom_patterns)."""
        result = sanitize_post_data(post_data, custom_patterns=custom_patterns)
        assert result is not None, desc
        text = result.get("text", "")
        for needle in must_contain:
            assert needle in text, f"{desc}: expected {needle!r} in {text!r}"
        for needle in must_not_contain:
            assert needle not in text, f"{desc}: {needle!r} should have been redacted in {text!r}"

    @pytest.mark.parametrize(
        ("desc", "params", "custom_patterns", "expected_values"),
        CUSTOM_PATTERNS_PARAMS_CASES,
        ids=[c[0] for c in CUSTOM_PATTERNS_PARAMS_CASES],
    )
    def test_params_redaction_matrix(
        self,
        desc: str,
        params: list[dict],
        custom_patterns: dict | None,
        expected_values: dict[str, str],
    ) -> None:
        """Exercise postData.params x (default, custom_patterns)."""
        post_data = {"mimeType": "application/x-www-form-urlencoded", "params": params}
        result = sanitize_post_data(post_data, custom_patterns=custom_patterns)
        assert result is not None, desc
        by_name = {p["name"]: p["value"] for p in result["params"]}
        for name, expected in expected_values.items():
            assert by_name[name] == expected, f"{desc}: {name} expected {expected!r}, got {by_name[name]!r}"

    def test_none_matches_omission(self) -> None:
        """``custom_patterns=None`` produces identical output to omitting the kwarg."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "user=admin&password=secret123&vendorpw=alsosecret",
        }
        default = sanitize_post_data(post_data)
        explicit_none = sanitize_post_data(post_data, custom_patterns=None)
        assert default == explicit_none

    def test_sequential_calls_with_different_patterns_do_not_leak_state(self) -> None:
        """Sequential calls with differing custom_patterns must not share state.

        Module globals and the ContextVar must not be mutated in a way that
        changes the output of a subsequent default call.
        """
        body = "user=admin&vendorpw=one&loginPassword=two&extra=three"

        def form(text: str) -> dict:
            return {"mimeType": "application/x-www-form-urlencoded", "text": text}

        # Baseline captured BEFORE any custom_patterns calls.
        baseline = sanitize_post_data(form(body))

        result_a = sanitize_post_data(
            form(body),
            custom_patterns={"fields": {"auto_redact_patterns": ["vendorpw"]}},
        )
        result_b = sanitize_post_data(
            form(body),
            custom_patterns={"fields": {"auto_redact_patterns": ["extra"]}},
        )

        # Default call AFTER the custom calls must be identical to the baseline
        # — proof that neither module globals nor the ContextVar leaked into it.
        result_default = sanitize_post_data(form(body))

        assert (
            baseline is not None
            and result_a is not None
            and result_b is not None
            and result_default is not None
        )
        assert result_default == baseline

        # A redacts vendorpw but not extra; B redacts extra but not vendorpw.
        assert "vendorpw=[REDACTED]" in result_a["text"]
        assert "extra=three" in result_a["text"]
        assert "extra=[REDACTED]" in result_b["text"]
        assert "vendorpw=one" in result_b["text"]

        # Built-in loginPassword is redacted in every variant.
        for r in (baseline, result_a, result_b, result_default):
            assert "loginPassword=[REDACTED]" in r["text"]


# -----------------------------------------------------------------------------
# Internals — resolver / cache / scope / compiler fallbacks
# -----------------------------------------------------------------------------


# (desc, input_dict, expected_auto_matches, expected_flag_matches_or_none)
# Each row compiles a sensitive-patterns dict and asserts which names match
# the resulting auto-redact regex and the flag regex (None when no flag
# patterns are declared).
COMPILE_FIELD_PATTERN_CASES = [
    (
        "current_schema_both_sections",
        {"fields": {"auto_redact_patterns": ["vendorpw"], "flag_patterns": ["deployenv"]}},
        ["vendorpw"],
        ["deployenv"],
    ),
    (
        "legacy_patterns_key_only",
        {"fields": {"patterns": ["legacytok"]}},
        ["legacytok"],
        None,
    ),
    (
        "hardcoded_fallback_when_fields_empty",
        {"fields": {}},
        ["password", "secret", "token", "key", "auth"],
        None,
    ),
    (
        "hardcoded_fallback_when_fields_missing_entirely",
        {},
        ["password", "secret", "token"],
        None,
    ),
]


class TestCompileSensitiveFieldPatterns:
    """Direct coverage for :func:`_compile_sensitive_field_patterns` legacy paths."""

    @pytest.mark.parametrize(
        ("desc", "sensitive_data", "auto_matches", "flag_matches"),
        COMPILE_FIELD_PATTERN_CASES,
        ids=[c[0] for c in COMPILE_FIELD_PATTERN_CASES],
    )
    def test_compile_matrix(
        self,
        desc: str,
        sensitive_data: dict,
        auto_matches: list[str],
        flag_matches: list[str] | None,
    ) -> None:
        from har_capture.sanitization.har import _compile_sensitive_field_patterns

        auto_re, flag_re = _compile_sensitive_field_patterns(sensitive_data)
        for name in auto_matches:
            assert auto_re.search(name), f"{desc}: auto regex should match {name!r}"
        if flag_matches is None:
            assert flag_re is None, f"{desc}: flag regex should be None"
        else:
            assert flag_re is not None, f"{desc}: flag regex should be compiled"
            for name in flag_matches:
                assert flag_re.search(name), f"{desc}: flag regex should match {name!r}"


class TestFieldPatternSet:
    """Direct coverage for the :class:`_FieldPatternSet` helper methods."""

    def test_matches_flaggable_returns_false_when_flag_re_is_none(self) -> None:
        """Guard the explicit None branch in matches_flaggable."""
        import re as _re

        from har_capture.sanitization.har import _FieldPatternSet

        pset = _FieldPatternSet(field_re=_re.compile("password"), flag_re=None)
        assert pset.matches_sensitive("password") is True
        assert pset.matches_flaggable("anything") is False


class TestCustomPatternsCacheKey:
    """Direct coverage for :func:`_custom_patterns_cache_key`."""

    def test_dict_produces_stable_key_regardless_of_insertion_order(self) -> None:
        from har_capture.sanitization.har import _custom_patterns_cache_key

        a = {"fields": {"auto_redact_patterns": ["vendorpw"], "flag_patterns": ["env"]}}
        b = {"fields": {"flag_patterns": ["env"], "auto_redact_patterns": ["vendorpw"]}}
        assert _custom_patterns_cache_key(a) == _custom_patterns_cache_key(b)

    def test_path_input_normalized_to_absolute(self, tmp_path: Path) -> None:
        from har_capture.sanitization.har import _custom_patterns_cache_key

        path = tmp_path / "does-not-exist.json"
        key = _custom_patterns_cache_key(str(path))
        assert key is not None and key.startswith("path:")
        assert key.endswith("/does-not-exist.json")

    def test_non_serializable_dict_returns_none(self) -> None:
        """Objects that neither JSON-serialize nor string-coerce return None.

        A None cache key means the caller compiles fresh each call instead of
        crashing on the unstringifiable dict.
        """
        from har_capture.sanitization.har import _custom_patterns_cache_key

        class _Unserializable:
            def __str__(self) -> str:
                raise TypeError("refuses to serialize")

        key = _custom_patterns_cache_key({"fields": {"x": _Unserializable()}})
        assert key is None


class TestResolveFieldPatterns:
    """Direct coverage for :func:`_resolve_field_patterns` caching behavior."""

    def _clear_cache(self) -> None:
        from har_capture.sanitization.har import _CUSTOM_FIELD_RE_CACHE

        _CUSTOM_FIELD_RE_CACHE.clear()

    def test_none_returns_default_set_without_touching_cache(self) -> None:
        from har_capture.sanitization.har import (
            _CUSTOM_FIELD_RE_CACHE,
            _DEFAULT_FIELD_PATTERNS,
            _resolve_field_patterns,
        )

        self._clear_cache()
        result = _resolve_field_patterns(None)
        assert result is _DEFAULT_FIELD_PATTERNS
        assert len(_CUSTOM_FIELD_RE_CACHE) == 0

    def test_same_dict_returns_cached_instance(self) -> None:
        from har_capture.sanitization.har import _resolve_field_patterns

        self._clear_cache()
        custom = {"fields": {"auto_redact_patterns": ["vendorpw"]}}
        first = _resolve_field_patterns(custom)
        second = _resolve_field_patterns(custom)
        assert first is second, "second call should hit the cache and return the same instance"

    def test_different_dicts_produce_different_instances(self) -> None:
        from har_capture.sanitization.har import _resolve_field_patterns

        self._clear_cache()
        a = _resolve_field_patterns({"fields": {"auto_redact_patterns": ["vendorpw"]}})
        b = _resolve_field_patterns({"fields": {"auto_redact_patterns": ["extra"]}})
        assert a is not b
        assert a.matches_sensitive("vendorpw") and not b.matches_sensitive("vendorpw")
        assert b.matches_sensitive("extra") and not a.matches_sensitive("extra")

    def test_cache_eviction_bounded_by_max(self) -> None:
        """Cache size is capped at _CUSTOM_FIELD_RE_CACHE_MAX entries.

        When exceeded, the oldest entry is evicted so the dict never grows
        unboundedly.
        """
        from har_capture.sanitization.har import (
            _CUSTOM_FIELD_RE_CACHE,
            _CUSTOM_FIELD_RE_CACHE_MAX,
            _resolve_field_patterns,
        )

        self._clear_cache()
        for i in range(_CUSTOM_FIELD_RE_CACHE_MAX + 5):
            _resolve_field_patterns({"fields": {"auto_redact_patterns": [f"p{i}"]}})

        assert len(_CUSTOM_FIELD_RE_CACHE) == _CUSTOM_FIELD_RE_CACHE_MAX

    def test_header_sets_cache_eviction_bounded_by_max(self) -> None:
        """The header-sets cache is bounded by the same max as the field cache.

        Both caches share `_CUSTOM_FIELD_RE_CACHE_MAX`; only the field one had
        an eviction test, so the header cache's bound was unverified.
        """
        from har_capture.sanitization.har import (
            _CUSTOM_FIELD_RE_CACHE_MAX,
            _CUSTOM_HEADER_SETS_CACHE,
            _resolve_header_sets,
        )

        _CUSTOM_HEADER_SETS_CACHE.clear()
        for i in range(_CUSTOM_FIELD_RE_CACHE_MAX + 5):
            _resolve_header_sets({"headers": {"full_redact": [f"x-hdr-{i}"]}})

        assert len(_CUSTOM_HEADER_SETS_CACHE) == _CUSTOM_FIELD_RE_CACHE_MAX

    def test_header_sets_cache_returns_cached_instance(self) -> None:
        """A repeat call with the same patterns must not recompile."""
        from har_capture.sanitization.har import (
            _CUSTOM_HEADER_SETS_CACHE,
            _resolve_header_sets,
        )

        _CUSTOM_HEADER_SETS_CACHE.clear()
        patterns = {"headers": {"full_redact": ["x-vendor-token"]}}

        assert _resolve_header_sets(patterns) is _resolve_header_sets(patterns)


class TestFieldPatternsScope:
    """Direct coverage for the :func:`_field_patterns_scope` context manager."""

    def test_scope_restores_previous_value_on_normal_exit(self) -> None:
        from har_capture.sanitization.har import (
            _DEFAULT_FIELD_PATTERNS,
            _FIELD_PATTERNS_CTX,
            _field_patterns_scope,
        )

        assert _FIELD_PATTERNS_CTX.get() is _DEFAULT_FIELD_PATTERNS
        with _field_patterns_scope({"fields": {"auto_redact_patterns": ["vendorpw"]}}):
            assert _FIELD_PATTERNS_CTX.get().matches_sensitive("vendorpw")
        assert _FIELD_PATTERNS_CTX.get() is _DEFAULT_FIELD_PATTERNS

    def test_scope_restores_previous_value_on_exception(self) -> None:
        from har_capture.sanitization.har import (
            _DEFAULT_FIELD_PATTERNS,
            _FIELD_PATTERNS_CTX,
            _field_patterns_scope,
        )

        assert _FIELD_PATTERNS_CTX.get() is _DEFAULT_FIELD_PATTERNS
        with (
            pytest.raises(RuntimeError, match="boom"),
            _field_patterns_scope({"fields": {"auto_redact_patterns": ["vendorpw"]}}),
        ):
            raise RuntimeError("boom")
        assert _FIELD_PATTERNS_CTX.get() is _DEFAULT_FIELD_PATTERNS

    def test_nested_scopes_stack_correctly(self) -> None:
        from har_capture.sanitization.har import (
            _FIELD_PATTERNS_CTX,
            _field_patterns_scope,
        )

        with _field_patterns_scope({"fields": {"auto_redact_patterns": ["outer"]}}):
            outer = _FIELD_PATTERNS_CTX.get()
            assert outer.matches_sensitive("outer")
            assert not outer.matches_sensitive("inner")
            with _field_patterns_scope({"fields": {"auto_redact_patterns": ["inner"]}}):
                inner = _FIELD_PATTERNS_CTX.get()
                assert inner.matches_sensitive("inner")
            # Inner scope exited — outer set is restored.
            assert _FIELD_PATTERNS_CTX.get() is outer


class TestContextVarIsolatesThreads:
    """The ContextVar must not bleed between concurrent threads."""

    def test_concurrent_threads_see_independent_patterns(self) -> None:
        import threading

        from har_capture.sanitization.har import (
            _FIELD_PATTERNS_CTX,
            _field_patterns_scope,
        )

        barrier = threading.Barrier(2)
        results: dict[str, bool] = {}

        def worker(name: str, custom_field: str) -> None:
            with _field_patterns_scope({"fields": {"auto_redact_patterns": [custom_field]}}):
                barrier.wait()  # both threads enter their scopes before any checks run
                results[name] = _FIELD_PATTERNS_CTX.get().matches_sensitive(custom_field)
                results[f"{name}_cross"] = _FIELD_PATTERNS_CTX.get().matches_sensitive("zzz_other_field")

        t1 = threading.Thread(target=worker, args=("t1", "aaa_only_t1"))
        t2 = threading.Thread(target=worker, args=("t2", "bbb_only_t2"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results["t1"] is True
        assert results["t2"] is True
        # Neither thread sees the other's field — the ContextVar is isolated.
        assert results["t1_cross"] is False
        assert results["t2_cross"] is False


# -----------------------------------------------------------------------------
# Header-set custom_patterns coverage (0.7.1 fix)
# -----------------------------------------------------------------------------


class TestHeaderSetsInternals:
    """Direct coverage for the parallel header-sets infrastructure."""

    def test_compile_header_sets_normalizes_case_and_freezes(self) -> None:
        from har_capture.sanitization.har import _compile_header_sets

        sets = _compile_header_sets(
            {
                "headers": {
                    "full_redact": ["Authorization", "X-Modem-Auth"],
                    "cookie_redact": ["Cookie"],
                    "scheme_redact": ["Proxy-Authorization"],
                }
            }
        )
        assert sets.full_redact == frozenset({"authorization", "x-modem-auth"})
        assert sets.cookie_redact == frozenset({"cookie"})
        assert sets.scheme_redact == frozenset({"proxy-authorization"})
        assert isinstance(sets.full_redact, frozenset)
        assert isinstance(sets.scheme_redact, frozenset)

    def test_compile_header_sets_missing_scheme_redact_defaults_empty(self) -> None:
        """A custom pattern dict without scheme_redact yields an empty set, not a KeyError."""
        from har_capture.sanitization.har import _compile_header_sets

        sets = _compile_header_sets({"headers": {"full_redact": ["X-Custom"]}})
        assert sets.scheme_redact == frozenset()

    def test_resolve_header_sets_none_returns_default(self) -> None:
        from har_capture.sanitization.har import (
            _DEFAULT_HEADER_SETS,
            _resolve_header_sets,
        )

        assert _resolve_header_sets(None) is _DEFAULT_HEADER_SETS

    def test_resolve_header_sets_merges_custom_additively(self) -> None:
        from har_capture.sanitization.har import _resolve_header_sets

        sets = _resolve_header_sets({"headers": {"full_redact": ["X-Modem-Auth"]}})
        # A built-in full_redact entry is still present, custom header added.
        assert "x-auth-token" in sets.full_redact
        assert "x-modem-auth" in sets.full_redact
        # Authorization now lives in scheme_redact, unaffected by custom full_redact extension.
        assert "authorization" in sets.scheme_redact

    def test_resolve_header_sets_cache_hit_returns_same_instance(self) -> None:
        from har_capture.sanitization.har import (
            _CUSTOM_HEADER_SETS_CACHE,
            _resolve_header_sets,
        )

        _CUSTOM_HEADER_SETS_CACHE.clear()
        custom = {"headers": {"full_redact": ["X-Modem-Auth"]}}
        a = _resolve_header_sets(custom)
        b = _resolve_header_sets(custom)
        assert a is b

    def test_header_sets_scope_restores_on_exception(self) -> None:
        from har_capture.sanitization.har import (
            _DEFAULT_HEADER_SETS,
            _HEADER_SETS_CTX,
            _header_sets_scope,
        )

        assert _HEADER_SETS_CTX.get() is _DEFAULT_HEADER_SETS
        with (
            pytest.raises(RuntimeError, match="boom"),
            _header_sets_scope({"headers": {"full_redact": ["x-modem-auth"]}}),
        ):
            raise RuntimeError("boom")
        assert _HEADER_SETS_CTX.get() is _DEFAULT_HEADER_SETS


class TestCustomPatternsPropagationThroughEntry:
    """Regression tests for 0.7.0 custom_patterns propagation gaps.

    Three detection sites in ``_sanitize_request`` / ``_sanitize_response``
    (header values, structured ``queryString`` params, and URL-query params)
    run BEFORE ``sanitize_post_data`` / ``sanitize_html`` get a chance to
    enter their own scopes. Entering both ContextVar scopes at
    ``sanitize_entry`` closes the gap.
    """

    CUSTOM_MODEM_HEADER = {"headers": {"full_redact": ["x-modem-auth"]}}
    CUSTOM_VENDORPW_FIELD = {"fields": {"auto_redact_patterns": ["vendorpw"]}}

    def _entry(self, request: dict, response: dict | None = None) -> dict:
        return {
            "request": request,
            "response": response
            or {"status": 200, "headers": [], "content": {"text": "", "mimeType": "text/plain"}},
        }

    def test_custom_header_is_NOT_redacted_without_custom_patterns(self) -> None:
        """Baseline: x-modem-auth passes through by default."""
        entry = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/",
                "headers": [{"name": "X-Modem-Auth", "value": "secret_token_123"}],
            }
        )
        result = sanitize_entry(entry, salt=None)
        header = next(h for h in result["request"]["headers"] if h["name"] == "X-Modem-Auth")
        assert header["value"] == "secret_token_123"

    def test_custom_header_IS_redacted_when_custom_patterns_passed(self) -> None:
        """sanitize_entry's custom_patterns must reach sanitize_header_value."""
        entry = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/",
                "headers": [{"name": "X-Modem-Auth", "value": "secret_token_123"}],
            }
        )
        result = sanitize_entry(entry, salt=None, custom_patterns=self.CUSTOM_MODEM_HEADER)
        header = next(h for h in result["request"]["headers"] if h["name"] == "X-Modem-Auth")
        assert header["value"] != "secret_token_123"
        assert "secret_token_123" not in header["value"]

    def test_custom_field_redacts_structured_querystring_param(self) -> None:
        """QueryString params in _sanitize_request must honor custom_patterns too."""
        entry = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/path?vendorpw=alsosecret",
                "headers": [],
                "queryString": [{"name": "vendorpw", "value": "alsosecret"}],
            }
        )
        result = sanitize_entry(entry, salt=None, custom_patterns=self.CUSTOM_VENDORPW_FIELD)
        qs = result["request"]["queryString"]
        vendorpw = next(p for p in qs if p["name"] == "vendorpw")
        assert vendorpw["value"] != "alsosecret"
        assert "alsosecret" not in vendorpw["value"]

    def test_custom_field_redacts_url_query_param_in_request_url(self) -> None:
        """The url string itself (via _sanitize_url_query_params) must honor it."""
        entry = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/path?vendorpw=alsosecret&safe=ok",
                "headers": [],
            }
        )
        result = sanitize_entry(entry, salt=None, custom_patterns=self.CUSTOM_VENDORPW_FIELD)
        url = result["request"]["url"]
        assert "vendorpw=alsosecret" not in url
        assert "safe=ok" in url

    def test_builtin_header_still_redacted_when_custom_patterns_provided(self) -> None:
        """Authorization (built-in) must still redact when custom_patterns extends the set."""
        entry = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/",
                "headers": [
                    {"name": "Authorization", "value": "Bearer builtin_secret"},
                    {"name": "X-Modem-Auth", "value": "custom_secret"},
                ],
            }
        )
        result = sanitize_entry(entry, salt=None, custom_patterns=self.CUSTOM_MODEM_HEADER)
        by_name = {h["name"]: h["value"] for h in result["request"]["headers"]}
        assert "builtin_secret" not in by_name["Authorization"]
        assert "custom_secret" not in by_name["X-Modem-Auth"]

    def test_custom_patterns_at_sanitize_har_level_reaches_headers(self) -> None:
        """sanitize_har wraps sanitize_entry — custom_patterns must flow end-to-end."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "0"},
                "entries": [
                    self._entry(
                        {
                            "method": "GET",
                            "url": "http://example.com/",
                            "headers": [{"name": "X-Modem-Auth", "value": "deep_secret"}],
                        }
                    )
                ],
            }
        }
        sanitized, _ = sanitize_har(har, salt=None, custom_patterns=self.CUSTOM_MODEM_HEADER)
        header = next(
            h for h in sanitized["log"]["entries"][0]["request"]["headers"] if h["name"] == "X-Modem-Auth"
        )
        assert "deep_secret" not in header["value"]

    def test_scope_does_not_leak_between_entries(self) -> None:
        """Per-call scope means two consecutive sanitize_entry calls don't share state."""
        entry_with_custom = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/",
                "headers": [{"name": "X-Modem-Auth", "value": "first_secret"}],
            }
        )
        entry_default = self._entry(
            {
                "method": "GET",
                "url": "http://example.com/",
                "headers": [{"name": "X-Modem-Auth", "value": "baseline"}],
            }
        )

        sanitize_entry(entry_with_custom, salt=None, custom_patterns=self.CUSTOM_MODEM_HEADER)
        result = sanitize_entry(entry_default, salt=None)
        header = next(h for h in result["request"]["headers"] if h["name"] == "X-Modem-Auth")
        # No custom_patterns on second call ⇒ X-Modem-Auth passes through.
        assert header["value"] == "baseline"


class TestEntrySanitization:
    """Tests for full HAR entry sanitization."""

    def test_sanitizes_request_headers(self) -> None:
        """Test request header sanitization."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://example.com/",
                "headers": [
                    {"name": "Cookie", "value": "session=secret123"},
                    {"name": "Content-Type", "value": "text/html"},
                ],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": "", "mimeType": "text/html"},
            },
        }
        result = sanitize_entry(entry, salt=None)
        cookie_header = next(h for h in result["request"]["headers"] if h["name"] == "Cookie")
        assert "secret123" not in cookie_header["value"]
        # Cookie values are redacted with ***COOKIE*** placeholder
        assert "***COOKIE***" in cookie_header["value"] or "[REDACTED]" in cookie_header["value"]

    def test_sanitizes_response_headers(self) -> None:
        """Test response header sanitization."""
        entry = {
            "request": {"method": "GET", "url": "http://test/", "headers": []},
            "response": {
                "status": 200,
                "headers": [{"name": "Set-Cookie", "value": "token=abc123; HttpOnly"}],
                "content": {"text": "", "mimeType": "text/html"},
            },
        }
        result = sanitize_entry(entry)
        cookie_header = next(h for h in result["response"]["headers"] if h["name"] == "Set-Cookie")
        assert "abc123" not in cookie_header["value"]

    def test_sanitizes_response_content(self) -> None:
        """Test response content sanitization."""
        entry = {
            "request": {"method": "GET", "url": "http://example.com/", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "text": "<html>MAC: AA:BB:CC:DD:EE:FF</html>",
                    "mimeType": "text/html",
                },
            },
        }
        result = sanitize_entry(entry, salt=None)
        content = result["response"]["content"]["text"]
        assert "AA:BB:CC:DD:EE:FF" not in content
        assert "XX:XX:XX:XX:XX:XX" in content

    def test_sanitizes_query_string(self) -> None:
        """Test query string parameter sanitization."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://test/?password=secret",
                "headers": [],
                "queryString": [{"name": "password", "value": "secret"}],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        password_param = next(p for p in result["request"]["queryString"] if p["name"] == "password")
        # Password values are redacted with ***FIELD*** placeholder (salt=None)
        assert password_param["value"] in ("[REDACTED]", "***FIELD***")


class TestFullHarSanitization:
    """Tests for complete HAR sanitization."""

    def test_sanitizes_all_entries(self) -> None:
        """Test all entries are sanitized."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/",
                            "headers": [{"name": "Cookie", "value": "session=abc"}],
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": "MAC: 11:22:33:44:55:66", "mimeType": "text/html"},
                        },
                    },
                ],
            }
        }
        result, _ = sanitize_har(har_data, salt=None)
        entry = result["log"]["entries"][0]
        assert "11:22:33:44:55:66" not in entry["response"]["content"]["text"]

    def test_sanitizes_multiple_entries(self) -> None:
        """Test multiple entries are all sanitized."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"method": "GET", "url": "http://test/1", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": "MAC: AA:AA:AA:AA:AA:AA", "mimeType": "text/html"},
                        },
                    },
                    {
                        "request": {"method": "GET", "url": "http://test/2", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": "MAC: BB:BB:BB:BB:BB:BB", "mimeType": "text/html"},
                        },
                    },
                ],
            }
        }
        result, _ = sanitize_har(har_data, salt=None)
        assert "AA:AA:AA:AA:AA:AA" not in result["log"]["entries"][0]["response"]["content"]["text"]
        assert "BB:BB:BB:BB:BB:BB" not in result["log"]["entries"][1]["response"]["content"]["text"]

    def test_handles_missing_log(self) -> None:
        """Test handling of missing log key."""
        har_data = {"invalid": "structure"}
        result, _ = sanitize_har(har_data)
        assert "invalid" in result

    def test_handles_empty_entries(self) -> None:
        """Test handling of empty entries list."""
        har_data = {"log": {"version": "1.2", "entries": []}}
        result, _ = sanitize_har(har_data)
        assert result["log"]["entries"] == []

    def test_preserves_structure(self) -> None:
        """Test HAR structure is preserved."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test", "version": "1.0"},
                "entries": [],
                "pages": [{"title": "Test Page"}],
            }
        }
        result, _ = sanitize_har(har_data)
        assert result["log"]["version"] == "1.2"
        assert result["log"]["creator"]["name"] == "Test"
        assert len(result["log"]["pages"]) == 1

    def test_sanitizes_page_titles(self) -> None:
        """Test page titles are sanitized."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [],
                "pages": [{"title": "Device MAC: AA:BB:CC:DD:EE:FF"}],
            }
        }
        result, _ = sanitize_har(har_data, salt=None)
        assert "AA:BB:CC:DD:EE:FF" not in result["log"]["pages"][0]["title"]


class TestURLStringSanitization:
    """Tests for URL string query parameter sanitization."""

    # fmt: off
    URL_SANITIZATION_CASES = [
        # (url, should_redact_value, desc)
        ("http://example.com/login?access_token=secret123&page=1", "secret123", "access_token_in_url"),
        ("http://example.com/api?password=hunter2&format=json", "hunter2", "password_in_url"),
        ("http://example.com/data?page=1&limit=10", None, "no_sensitive_params"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("url", "should_redact_value", "desc"),
        URL_SANITIZATION_CASES,
        ids=[c[2] for c in URL_SANITIZATION_CASES],
    )
    def test_url_query_param_sanitization(self, url: str, should_redact_value: str | None, desc: str) -> None:
        """Test sensitive query parameters are redacted in URL string."""
        entry = {
            "request": {"method": "GET", "url": url, "headers": [], "queryString": []},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        result_url = result["request"]["url"]
        if should_redact_value:
            assert should_redact_value not in result_url, f"{desc}: value should be redacted from URL"
        else:
            assert result_url == url, f"{desc}: URL should be unchanged"


class TestURLPathSanitization:
    """Tests for URL path segment sanitization (flagged, not auto-redacted)."""

    # fmt: off
    URL_PATH_CASES = [
        ("http://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile", "uuid_in_path"),
        ("http://api.example.com/keys/sk-1234567890abcdefghij/verify", "api_key_prefix_in_path"),
        ("http://api.example.com/tokens/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6/refresh", "long_mixed_token_in_path"),
        ("http://api.example.com/devices/DEV-ABC123456/status", "device_serial_in_path"),
        ("http://api.example.com/customers/CUST-67890/profile", "customer_id_in_path"),
        ("http://example.com/api/v1/status", "normal_path_preserved"),
        ("http://example.com/api/GetDeviceInformation/details", "long_alpha_path_preserved"),
        ("http://example.com/api/configurationSettings/list", "camelcase_path_preserved"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("url", "desc"),
        URL_PATH_CASES,
        ids=[c[1] for c in URL_PATH_CASES],
    )
    def test_url_path_segments_preserved(self, url: str, desc: str) -> None:
        """Test path segments are preserved (flagged for review, not auto-redacted)."""
        entry = {
            "request": {"method": "GET", "url": url, "headers": [], "queryString": []},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        result_url = result["request"]["url"]
        assert result_url == url, f"{desc}: URL should be preserved (flagged, not redacted)"


class TestResponseContentFallback:
    """Tests for fallback mime type sanitization."""

    # fmt: off
    FALLBACK_CASES = [
        ("text/plain", "IP: 192.168.1.100", "192.168.1.100", "text_plain_sanitized"),
        ("text/javascript", "var ip='192.168.2.50'", "192.168.2.50", "text_javascript_sanitized"),
        ("", "IP: 192.168.3.50 here", "192.168.3.50", "missing_mime_sanitized"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("mime_type", "content_text", "expected_redacted", "desc"),
        FALLBACK_CASES,
        ids=[c[3] for c in FALLBACK_CASES],
    )
    def test_text_content_fallback_sanitization(
        self, mime_type: str, content_text: str, expected_redacted: str, desc: str
    ) -> None:
        """Test text/* and missing mime type content gets pattern-sanitized."""
        entry = {
            "request": {"method": "GET", "url": "http://test/", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": content_text, "mimeType": mime_type},
            },
        }
        result = sanitize_entry(entry, salt=None)
        content = result["response"]["content"]["text"]
        assert expected_redacted not in content, f"{desc}: PII should be redacted"

    def test_base64_content_skipped(self) -> None:
        """Test base64-encoded content is not pattern-sanitized."""
        entry = {
            "request": {"method": "GET", "url": "http://test/", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "text": "MTkyLjE2OC4xLjEwMA==",
                    "mimeType": "application/octet-stream",
                    "encoding": "base64",
                },
            },
        }
        result = sanitize_entry(entry, salt=None)
        assert result["response"]["content"]["text"] == "MTkyLjE2OC4xLjEwMA=="


class TestNestedJSONSanitization:
    """Tests for _sanitize_json_text handling nested objects."""

    def test_nested_sensitive_fields_in_post_data(self) -> None:
        """Test _sanitize_json_text now handles nested sensitive fields."""
        post_data = {
            "mimeType": "application/json",
            "text": '{"data": {"password": "secret", "nested": {"token": "abc123"}}}',
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        parsed = json.loads(result["text"])
        assert parsed["data"]["password"] == "[REDACTED]"
        assert parsed["data"]["nested"]["token"] == "[REDACTED]"


class TestIPValidation:
    """Tests for IP validation in string pattern sanitization."""

    @pytest.mark.parametrize(
        ("input_text", "should_contain", "desc"),
        [
            ("IP: 192.168.999.999", "192.168.999.999", "invalid_octets_preserved"),
            ("IP: 192.168.1.100", None, "valid_ip_redacted"),
        ],
    )
    def test_ip_validation_in_string_patterns(
        self, input_text: str, should_contain: str | None, desc: str
    ) -> None:
        """Test IP validation rejects invalid octets in string patterns."""
        from har_capture.sanitization.har import _sanitize_string_patterns

        result = _sanitize_string_patterns(input_text)
        if should_contain:
            assert should_contain in result, f"{desc}: invalid IP should be preserved"
        else:
            assert "192.168.1.100" not in result, f"{desc}: valid IP should be redacted"


class TestSensitiveFieldPatterns:
    """Tests for tightened sensitive field patterns (over-matching fixes)."""

    # Over-matching prevention: (field_name, expected, id)
    OVER_MATCHING_CASES = [
        (c["field_name"], c["expected"], c["id"]) for c in _HAR_FIXTURE["over_matching_cases"]
    ]

    @pytest.mark.parametrize(
        ("field_name", "expected", "desc"),
        OVER_MATCHING_CASES,
        ids=[c[2] for c in OVER_MATCHING_CASES],
    )
    def test_sensitive_field_pattern_accuracy(self, field_name: str, expected: bool, desc: str) -> None:
        """Test tightened patterns prevent over-matching."""
        assert is_sensitive_field(field_name) == expected, f"{desc}"


class TestSSNAndCreditCardPatterns:
    """Tests for SSN (flagged) and credit card (auto-redacted) pattern detection."""

    @pytest.mark.parametrize(
        ("input_text", "should_redact", "desc"),
        [
            ("SSN: 123-45-6789", False, "ssn_flagged_not_redacted"),
            ("Date: 2024-01-15", False, "date_not_matched"),
            ("Card: 4111111111111111", True, "visa_detected"),
            ("Card: 5500000000000004", True, "mastercard_detected"),
            ("Card: 371449635398431", True, "amex_detected"),
            ("Number: 1234567890123456", False, "random_digits_no_luhn"),
        ],
    )
    def test_financial_pii_detection(self, input_text: str, should_redact: bool, desc: str) -> None:
        """Test credit card auto-redaction and SSN preservation (flagged only)."""
        from har_capture.sanitization.har import _sanitize_string_patterns

        result = _sanitize_string_patterns(input_text)
        if should_redact:
            # Extract the value that should be redacted
            original_numbers = [w for w in input_text.split() if any(c.isdigit() for c in w)]
            for num in original_numbers:
                if len(num) > 8:  # Only check long numbers (CC)
                    assert num not in result, f"{desc}: {num} should be redacted"
        else:
            assert result == input_text, f"{desc}: text should be unchanged"


class TestFlaggableFieldDetection:
    """Tests for is_flaggable_field() — fields flagged for review, not auto-redacted."""

    # Flaggable field detection: (field_name, expected, id)
    FLAGGABLE_FIELD_CASES = [
        (c["field_name"], c["expected"], c["id"]) for c in _HAR_FIXTURE["flaggable_field_cases"]
    ]

    @pytest.mark.parametrize(
        ("field_name", "expected", "desc"),
        FLAGGABLE_FIELD_CASES,
        ids=[c[2] for c in FLAGGABLE_FIELD_CASES],
    )
    def test_flaggable_field_detection(self, field_name: str, expected: bool, desc: str) -> None:
        """Test detection of flaggable vs non-flaggable field names."""
        result = is_flaggable_field(field_name)
        assert result is expected, (
            f"{desc}: '{field_name}' should be {'flaggable' if expected else 'not flaggable'}"
        )


class TestFlaggingBehavior:
    """Tests that flaggable fields, SSNs, and URL paths are flagged (not auto-redacted)."""

    def test_ssn_flagged_not_redacted(self) -> None:
        """Test SSN patterns are flagged for review, not auto-redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns("SSN: 123-45-6789", collector=collector)
        assert "123-45-6789" in result, "SSN should be preserved in output"
        assert any(f.category == "ssn" for f in collector.flagged), "SSN should be in flagged list"

    def test_url_path_uuid_flagged(self) -> None:
        """Test UUID in URL path is flagged, not redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_url_path

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        url = "http://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile"
        result = _sanitize_url_path(url, hasher, collector)
        assert "550e8400-e29b-41d4-a716-446655440000" in result, "UUID should be preserved"
        assert any(f.category == "uuid" for f in collector.flagged), "UUID should be flagged"

    def test_url_path_api_key_flagged(self) -> None:
        """Test API key prefix in URL path is flagged, not redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_url_path

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        url = "http://api.example.com/keys/sk-1234567890abcdefghij/verify"
        result = _sanitize_url_path(url, hasher, collector)
        assert "sk-1234567890abcdefghij" in result, "API key should be preserved"
        assert any(f.category == "api_key" for f in collector.flagged), "API key should be flagged"

    def test_url_path_long_token_flagged(self) -> None:
        """Test long token in URL path is flagged, not redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_url_path

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        url = "http://api.example.com/tokens/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6/refresh"
        result = _sanitize_url_path(url, hasher, collector)
        assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" in result, "Token should be preserved"
        assert any(f.category == "token" for f in collector.flagged), "Token should be flagged"

    def test_url_path_device_serial_flagged(self) -> None:
        """Test device/serial number in URL path is flagged, not redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_url_path

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        url = "http://api.example.com/devices/DEV-ABC123456/status"
        result = _sanitize_url_path(url, hasher, collector)
        assert "DEV-ABC123456" in result, "Device serial should be preserved"
        assert any(f.category == "device_serial" for f in collector.flagged), (
            "Device serial should be flagged"
        )

    @pytest.mark.parametrize(
        ("segment", "desc"),
        [
            ("DEV-ABC123456", "device_prefix"),
            ("CUST-67890", "customer_prefix"),
            ("SN-XY12345678", "serial_number_prefix"),
            ("HW-ABCDE12345", "hardware_prefix"),
        ],
        ids=["device_prefix", "customer_prefix", "serial_number_prefix", "hardware_prefix"],
    )
    def test_url_path_device_serial_variants_flagged(self, segment: str, desc: str) -> None:
        """Test various device/serial number patterns are flagged."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_url_path

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        url = f"http://api.example.com/items/{segment}/info"
        result = _sanitize_url_path(url, hasher, collector)
        assert segment in result, f"{desc}: segment should be preserved"
        assert any(f.category == "device_serial" for f in collector.flagged), f"{desc}: should be flagged"

    def test_flaggable_field_in_json_flagged(self) -> None:
        """Test flaggable fields in JSON are flagged, value preserved."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_json_recursive

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        data = {"username": "admin", "password": "secret123"}
        result = _sanitize_json_recursive(data, hasher, collector)
        assert result["username"] == "admin", "Flaggable field value should be preserved"
        assert result["password"] in ("[REDACTED]", "***FIELD***"), "Sensitive field should be auto-redacted"
        assert any(f.original_value == "admin" and f.category == "field" for f in collector.flagged)

    def test_flaggable_field_in_post_params_flagged(self) -> None:
        """Test flaggable fields in POST params are flagged, value preserved."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "loginName", "value": "admin"},
                {"name": "password", "value": "secret"},
            ],
        }
        result = sanitize_post_data(post_data, hasher, collector)
        assert result is not None
        login_param = next(p for p in result["params"] if p["name"] == "loginName")
        password_param = next(p for p in result["params"] if p["name"] == "password")
        assert login_param["value"] == "admin", "Flaggable field should be preserved"
        assert password_param["value"] in ("[REDACTED]", "***FIELD***"), "Sensitive field should be redacted"
        assert any(f.original_value == "admin" for f in collector.flagged)

    def test_flaggable_field_in_query_string_flagged(self) -> None:
        """Test flaggable fields in queryString are flagged, value preserved."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_request

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        req = {
            "method": "GET",
            "url": "http://test/?username=admin&password=secret",
            "headers": [],
            "queryString": [
                {"name": "username", "value": "admin"},
                {"name": "password", "value": "secret"},
            ],
        }
        _sanitize_request(req, hasher, collector)
        username_param = next(p for p in req["queryString"] if p["name"] == "username")
        password_param = next(p for p in req["queryString"] if p["name"] == "password")
        assert username_param["value"] == "admin", "Flaggable queryString param should be preserved"
        assert password_param["value"] in ("[REDACTED]", "***FIELD***"), (
            "Sensitive queryString param should be redacted"
        )
        assert any(f.original_value == "admin" for f in collector.flagged)


class TestPhoneNumberPatterns:
    """Tests for phone number pattern detection (flagged, not auto-redacted)."""

    # fmt: off
    PHONE_FLAGGED_CASES = [
        ("Call: (555) 123-4567",            "(555) 123-4567",   "us_parens_format"),
        ("Phone: 555-123-4567",             "555-123-4567",     "us_dash_format"),
        ("Tel: +1 555 123 4567",            "+1 555 123 4567",  "us_intl_format"),
        ("Contact: +1-555-123-4567",        "+1-555-123-4567",  "us_intl_dash_format"),
        ("Fax: 555.123.4567",               "555.123.4567",     "us_dot_format"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("input_text", "expected_phone", "desc"),
        PHONE_FLAGGED_CASES,
        ids=[c[2] for c in PHONE_FLAGGED_CASES],
    )
    def test_phone_flagged_not_redacted(self, input_text: str, expected_phone: str, desc: str) -> None:
        """Test phone number patterns are flagged for review, not auto-redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns(input_text, collector=collector)
        assert expected_phone in result, f"{desc}: phone number should be preserved in output"
        assert any(f.category == "phone" for f in collector.flagged), f"{desc}: phone should be flagged"

    # fmt: off
    PHONE_NOT_MATCHED_CASES = [
        ("ID: 12345",               "short_number"),
        ("Code: 123-45",            "too_short_with_dash"),
        ("Version: 1.2.3",          "version_number"),
        ("tok_1234567890",          "token_with_digits"),
        ("abc1234567890xyz",        "digits_inside_word"),
        # Separator-free digit runs are constants/counters, not phones —
        # CM2500 firmware md5.js constants were flagged 31x per review.
        ("var a = 1732584193;",     "md5_js_init_constant"),
        ("count: 5551234567",       "bare_ten_digits"),
        ("epoch 17325841934",       "bare_eleven_digits"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("input_text", "desc"),
        PHONE_NOT_MATCHED_CASES,
        ids=[c[1] for c in PHONE_NOT_MATCHED_CASES],
    )
    def test_non_phone_not_flagged(self, input_text: str, desc: str) -> None:
        """Test non-phone patterns are not flagged."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        _sanitize_string_patterns(input_text, collector=collector)
        assert not any(f.category == "phone" for f in collector.flagged), f"{desc}: should not flag as phone"


# =============================================================================
# Public IP Sanitization in JSON/String Patterns
# =============================================================================


class TestPublicIpSanitization:
    """Tests for public IP address sanitization in string patterns.

    Public IPs should be redacted anywhere they appear in HAR content
    (JSON values, HTML bodies, headers) while private IPs get separate handling.
    """

    # fmt: off
    PUBLIC_IP_REDACTED_CASES = [
        ("73.158.42.197",                 "bare_public_ip"),
        ("WAN IP: 73.158.42.197",        "public_ip_in_text"),
        ('{"wanIp": "73.158.42.197"}',   "public_ip_in_json_string"),
        ("IP=8.8.8.8&dns=1.1.1.1",       "multiple_public_ips"),
        ("203.0.113.42",                  "documentation_range_ip"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("input_text", "desc"),
        PUBLIC_IP_REDACTED_CASES,
        ids=[c[1] for c in PUBLIC_IP_REDACTED_CASES],
    )
    def test_public_ip_redacted(self, input_text: str, desc: str) -> None:
        """Test public IPs are redacted in string patterns."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns(input_text, collector=collector)
        # Extract the IP from input to verify it's gone
        import re

        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", input_text)
        for ip in ips:
            first_octet = int(ip.split(".")[0])
            # Only check non-private IPs
            if not ip.startswith(("10.", "192.168.", "127.")) and first_octet not in (0, 255):
                assert ip not in result, f"{desc}: public IP {ip} should be redacted"

    # fmt: off
    PRIVATE_IP_REDACTED_CASES = [
        ("192.168.5.100",  "private_192_168"),
        ("172.16.0.50",    "private_172_16"),
    ]
    PRIVATE_IP_PRESERVED_CASES = [
        ("192.168.1.1",    "gateway_192_168_1_1"),
        ("10.0.0.1",       "gateway_10_0_0_1"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("input_text", "desc"),
        PRIVATE_IP_REDACTED_CASES,
        ids=[c[1] for c in PRIVATE_IP_REDACTED_CASES],
    )
    def test_private_ip_redacted(self, input_text: str, desc: str) -> None:
        """Test non-gateway private IPs are redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns(input_text, collector=collector)
        assert input_text not in result, f"{desc}: private IP should be redacted"

    @pytest.mark.parametrize(
        ("input_text", "desc"),
        PRIVATE_IP_PRESERVED_CASES,
        ids=[c[1] for c in PRIVATE_IP_PRESERVED_CASES],
    )
    def test_gateway_ips_preserved(self, input_text: str, desc: str) -> None:
        """Test common gateway IPs are preserved (not redacted)."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns(input_text, collector=collector)
        assert input_text in result, f"{desc}: gateway IP should be preserved"

    def test_public_ip_in_json_response(self) -> None:
        """Test public IP in JSON response body is sanitized end-to-end."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/api/status",
                "headers": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "mimeType": "application/json",
                    "text": json.dumps({"wanIp": "73.158.42.197", "status": "connected"}),
                },
            },
        }
        result = sanitize_entry(entry, salt=None)
        content = json.loads(result["response"]["content"]["text"])
        assert "73.158.42.197" not in content["wanIp"], "Public IP should be redacted in JSON response"
        assert content["status"] == "connected", "Non-sensitive value should be preserved"

    def test_public_ip_collector_records(self) -> None:
        """Test that public IP redactions are recorded in collector."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_string_patterns

        hasher = Hasher.create(None)
        collector = RedactionCollector(hasher=hasher)
        _sanitize_string_patterns("WAN: 73.158.42.197", collector=collector)
        assert collector.auto_redacted_counts.get("public_ip", 0) > 0, "Should record public_ip redaction"


# =============================================================================
# Cookie Object Sanitization
# =============================================================================


class TestCookieObjectSanitization:
    """Tests for cookie object sanitization in request/response.

    Playwright parses Cookie and Set-Cookie headers into structured objects
    under request.cookies and response.cookies. These need sanitization
    alongside the header string sanitization.
    """

    def test_request_cookie_objects_sanitized(self) -> None:
        """Test request cookie objects have values redacted."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/",
                "headers": [],
                "cookies": [
                    {"name": "session_id", "value": "abc123secret"},
                    {"name": "tracking", "value": "xyz789token"},
                ],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {"mimeType": "text/html", "text": "<html></html>"},
            },
        }
        result = sanitize_entry(entry, salt=None)
        for cookie in result["request"]["cookies"]:
            assert cookie["value"] != "abc123secret", f"Cookie {cookie['name']} value should be redacted"
            assert cookie["value"] != "xyz789token", f"Cookie {cookie['name']} value should be redacted"

    def test_response_cookie_objects_sanitized(self) -> None:
        """Test response cookie objects have values redacted."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/",
                "headers": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "cookies": [
                    {"name": "PHPSESSID", "value": "sess_abc123456"},
                    {"name": "auth_token", "value": "tok_secret789"},
                ],
                "content": {"mimeType": "text/html", "text": "<html></html>"},
            },
        }
        result = sanitize_entry(entry, salt=None)
        for cookie in result["response"]["cookies"]:
            assert cookie["value"] != "sess_abc123456", f"Cookie {cookie['name']} value should be redacted"
            assert cookie["value"] != "tok_secret789", f"Cookie {cookie['name']} value should be redacted"

    def test_cookie_names_preserved(self) -> None:
        """Test cookie names are not modified during sanitization."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/",
                "headers": [],
                "cookies": [
                    {"name": "session_id", "value": "secret123"},
                ],
            },
            "response": {
                "status": 200,
                "headers": [],
                "cookies": [
                    {"name": "PHPSESSID", "value": "secret456"},
                ],
                "content": {"mimeType": "text/html", "text": "<html></html>"},
            },
        }
        result = sanitize_entry(entry, salt=None)
        assert result["request"]["cookies"][0]["name"] == "session_id"
        assert result["response"]["cookies"][0]["name"] == "PHPSESSID"

    def test_empty_cookie_list_no_error(self) -> None:
        """Test empty cookie lists don't cause errors."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/",
                "headers": [],
                "cookies": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "cookies": [],
                "content": {"mimeType": "text/html", "text": "<html></html>"},
            },
        }
        sanitize_entry(entry, salt=None)  # Should not raise

    def test_cookie_hash_consistency(self) -> None:
        """Test same cookie value produces same hash across request and response."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/",
                "headers": [],
                "cookies": [
                    {"name": "token", "value": "shared_secret_value"},
                ],
            },
            "response": {
                "status": 200,
                "headers": [],
                "cookies": [
                    {"name": "token", "value": "shared_secret_value"},
                ],
                "content": {"mimeType": "text/html", "text": "<html></html>"},
            },
        }
        result = sanitize_entry(entry, salt="test-salt")
        req_hash = result["request"]["cookies"][0]["value"]
        resp_hash = result["response"]["cookies"][0]["value"]
        assert req_hash == resp_hash, "Same cookie value should produce same hash"


# =============================================================================
# Serial Number Field Detection in JSON
# =============================================================================


class TestSerialNumberJsonSanitization:
    """Tests for serial number field detection in JSON recursive sanitizer.

    JSON responses from device APIs often contain serial number fields
    that need redaction. These are detected by field name matching.
    """

    # fmt: off
    SERIAL_FIELD_CASES = [
        ("serial",        "SN827194729",   "lowercase_serial"),
        ("serial_number", "ABC123XYZ",     "snake_case"),
        ("serialNumber",  "DEF456",        "camelCase"),
        ("serialnum",     "GHI789",        "abbreviated"),
        ("sn",            "JKL012",        "two_letter"),
        ("Serial",        "MNO345",        "capitalized"),
        ("SERIAL_NUMBER", "PQR678",        "upper_snake"),
        ("SN",            "STU901",        "upper_two_letter"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("field_name", "serial_value", "desc"),
        SERIAL_FIELD_CASES,
        ids=[c[2] for c in SERIAL_FIELD_CASES],
    )
    def test_serial_field_redacted(self, field_name: str, serial_value: str, desc: str) -> None:
        """Test serial number fields are redacted in JSON."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/api/info",
                "headers": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "mimeType": "application/json",
                    "text": json.dumps({field_name: serial_value, "model": "C7000"}),
                },
            },
        }
        result = sanitize_entry(entry, salt=None)
        content = json.loads(result["response"]["content"]["text"])
        assert content[field_name] != serial_value, f"{desc}: serial should be redacted"
        assert "SERIAL" in content[field_name], f"{desc}: should use SERIAL prefix"

    def test_serial_empty_value_preserved(self) -> None:
        """Test empty serial number values are not modified."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/api/info",
                "headers": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "mimeType": "application/json",
                    "text": json.dumps({"serial": "", "model": "C7000"}),
                },
            },
        }
        result = sanitize_entry(entry, salt=None)
        content = json.loads(result["response"]["content"]["text"])
        assert content["serial"] == "", "Empty serial should be preserved"

    def test_serial_hash_consistency(self) -> None:
        """Test same serial value produces same hash."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector
        from har_capture.sanitization.har import _sanitize_json_recursive

        hasher = Hasher.create("test-salt")
        collector = RedactionCollector(hasher=hasher)
        data1 = {"serial": "SN827194729"}
        data2 = {"sn": "SN827194729"}
        result1 = _sanitize_json_recursive(data1, hasher, collector)
        result2 = _sanitize_json_recursive(data2, hasher, collector)
        assert result1["serial"] == result2["sn"], "Same serial value should produce same hash"

    def test_non_serial_field_not_affected(self) -> None:
        """Test non-serial fields are not treated as serial numbers."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://192.168.1.1/api/info",
                "headers": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "mimeType": "application/json",
                    "text": json.dumps({"model": "C7000", "firmware": "V1.03.08"}),
                },
            },
        }
        result = sanitize_entry(entry, salt=None)
        content = json.loads(result["response"]["content"]["text"])
        assert content["model"] == "C7000", "Model should be preserved"
        assert content["firmware"] == "V1.03.08", "Firmware should be preserved"


class TestBrowserCookieSanitization:
    """Tests for browser_cookies sanitization in _har_capture metadata."""

    def test_browser_cookie_values_redacted(self) -> None:
        """Test that browser_cookies values in _har_capture metadata are redacted."""
        har = {
            "log": {
                "entries": [],
                "_har_capture": {
                    "browser_cookies": [
                        {
                            "name": "XSRF_TOKEN",
                            "value": "secret123",
                            "domain": ".example.com",
                            "path": "/",
                            "httpOnly": False,
                            "secure": True,
                            "sameSite": "Lax",
                        },
                        {
                            "name": "session_id",
                            "value": "s3cr3t-s3ss10n",
                            "domain": ".example.com",
                            "path": "/",
                            "httpOnly": True,
                            "secure": True,
                            "sameSite": "Strict",
                        },
                    ],
                },
            }
        }

        result, _ = sanitize_har(har, salt="test-salt")

        cookies = result["log"]["_har_capture"]["browser_cookies"]
        assert cookies[0]["value"] != "secret123", "Cookie value should be redacted"
        assert cookies[1]["value"] != "s3cr3t-s3ss10n", "Cookie value should be redacted"

    def test_browser_cookie_structural_properties_preserved(self) -> None:
        """Test that cookie structural properties (domain, path, httpOnly, secure) are preserved."""
        har = {
            "log": {
                "entries": [],
                "_har_capture": {
                    "browser_cookies": [
                        {
                            "name": "token",
                            "value": "abc",
                            "domain": ".example.com",
                            "path": "/api",
                            "httpOnly": True,
                            "secure": True,
                            "sameSite": "Strict",
                        },
                    ],
                },
            }
        }

        result, _ = sanitize_har(har, salt="test-salt")

        cookie = result["log"]["_har_capture"]["browser_cookies"][0]
        assert cookie["name"] == "token"
        assert cookie["domain"] == ".example.com"
        assert cookie["path"] == "/api"
        assert cookie["httpOnly"] is True
        assert cookie["secure"] is True
        assert cookie["sameSite"] == "Strict"

    def test_browser_cookies_absent_no_error(self) -> None:
        """Test sanitize_har works when _har_capture has no browser_cookies."""
        har = {
            "log": {
                "entries": [],
                "_har_capture": {"tool": "har-capture", "version": "0.4.1"},
            }
        }

        result, _ = sanitize_har(har, salt="test-salt")
        assert "browser_cookies" not in result["log"]["_har_capture"]

    def test_browser_cookies_empty_list(self) -> None:
        """Test sanitize_har handles empty browser_cookies list."""
        har = {
            "log": {
                "entries": [],
                "_har_capture": {"browser_cookies": []},
            }
        }

        result, _ = sanitize_har(har, salt="test-salt")
        assert result["log"]["_har_capture"]["browser_cookies"] == []


# =============================================================================
# Client-Side Cookie Detection
# =============================================================================

# ┌────────────────────────────┬───────────────────┬──────────────────────────────────────┐
# │ cookie_header_value        │ expected_names    │ description                          │
# └────────────────────────────┴───────────────────┴──────────────────────────────────────┘
#
# fmt: off
PARSE_COOKIE_NAMES_CASES = [
    ("session=abc; token=xyz",        ["session", "token"], "two_cookies"),
    ("session=abc",                   ["session"],          "single_cookie"),
    ("  session = abc ; token=xyz  ", ["session", "token"], "whitespace_padded"),
    ("bare_no_eq",                    [],                   "no_equals_ignored"),
    ("=value; session=abc",           ["session"],          "leading_eq_name_skipped"),
    ("",                              [],                   "empty_string"),
]

PARSE_SET_COOKIE_NAME_CASES = [
    ("session=abc; Path=/; HttpOnly", "session",    "with_attributes"),
    ("token=xyz",                     "token",      "no_attributes"),
    ("credential=; Secure",           "credential", "empty_value"),
    ("HttpOnly",                      None,         "no_equals_at_all"),
    ("",                              None,         "empty_string"),
]

# Entries shape: list of {"request": {"headers": [...]}, "response": {"headers": [...]}}
_JS_ONLY = [
    {"request": {"headers": [{"name": "Cookie", "value": "credential=abc"}]},
     "response": {"headers": []}},
]
_SERVER_SET = [
    {"request": {"headers": []},
     "response": {"headers": [{"name": "Set-Cookie", "value": "session=abc; Path=/"}]}},
    {"request": {"headers": [{"name": "Cookie", "value": "session=abc"}]},
     "response": {"headers": []}},
]
_MIXED = [
    {"request": {"headers": []},
     "response": {"headers": [{"name": "Set-Cookie", "value": "session=abc; Path=/"}]}},
    {"request": {"headers": [{"name": "Cookie", "value": "session=abc; credential=xyz"}]},
     "response": {"headers": []}},
]
_DEDUP = [
    {"request": {"headers": [{"name": "Cookie", "value": "credential=abc"}]},
     "response": {"headers": []}},
    {"request": {"headers": [{"name": "Cookie", "value": "credential=xyz"}]},
     "response": {"headers": []}},
]
_MULTI = [
    {"request": {"headers": [{"name": "Cookie", "value": "a=1; b=2"}]},
     "response": {"headers": []}},
]
# Non-dict header entries exercise the isinstance(header, dict) defensive branch
_NON_DICT_HEADERS = [
    {"request": {"headers": ["not-a-dict", {"name": "Cookie", "value": "credential=abc"}]},
     "response": {"headers": ["not-a-dict", {"name": "Set-Cookie", "value": "session=xyz; Path=/"}]}},
]
# Set-Cookie with no '=' — _parse_set_cookie_name returns None; cookie must not be suppressed
_SET_COOKIE_NO_EQ = [
    {"request": {"headers": []},
     "response": {"headers": [{"name": "Set-Cookie", "value": "HttpOnly"}]}},
    {"request": {"headers": [{"name": "Cookie", "value": "credential=abc"}]},
     "response": {"headers": []}},
]

DETECT_CLIENT_SIDE_COOKIE_CASES = [
    # (entries,          expected_names,  description)
    (_JS_ONLY,          ["credential"],  "js_only_cookie"),
    (_SERVER_SET,       [],              "server_set_cookie_suppressed"),
    (_MIXED,            ["credential"],  "mixed_only_js_returned"),
    ([],                [],              "empty_capture"),
    (_DEDUP,            ["credential"],  "repeated_js_cookie_deduplicated"),
    (_MULTI,            ["a", "b"],      "multiple_js_cookies"),
    (_NON_DICT_HEADERS, ["credential"],  "non_dict_headers_skipped"),
    (_SET_COOKIE_NO_EQ, ["credential"],  "set_cookie_no_eq_not_suppressed"),
]

# Full HAR entry shape for sanitize_har integration cases
_ENTRY = lambda req_headers, resp_headers: {   # noqa: E731
    "request": {"method": "GET", "url": "http://example.com/", "headers": req_headers, "queryString": []},
    "response": {"status": 200, "headers": resp_headers, "content": {}},
}

SANITIZE_HAR_CLIENT_COOKIE_CASES = [
    # (entries,                                                                    expected,        desc)
    ([_ENTRY([], [{"name": "Set-Cookie", "value": "session=abc; Path=/"}]),
      _ENTRY([{"name": "Cookie", "value": "session=abc; credential=xyz"}], [])], ["credential"],  "js_cookie_detected"),
    ([_ENTRY([], [{"name": "Set-Cookie", "value": "session=abc; Path=/"}]),
      _ENTRY([{"name": "Cookie", "value": "session=abc"}], [])],                  [],              "all_server_set"),
    ([],                                                                           [],              "no_entries"),
]
# fmt: on


class TestClientSideCookieDetection:
    """Tests for _parse_cookie_names, _parse_set_cookie_name, _detect_client_side_cookies."""

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        PARSE_COOKIE_NAMES_CASES,
        ids=[c[2] for c in PARSE_COOKIE_NAMES_CASES],
    )
    def test_parse_cookie_names(self, value: str, expected: list[str], desc: str) -> None:
        assert _parse_cookie_names(value) == expected, desc

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        PARSE_SET_COOKIE_NAME_CASES,
        ids=[c[2] for c in PARSE_SET_COOKIE_NAME_CASES],
    )
    def test_parse_set_cookie_name(self, value: str, expected: str | None, desc: str) -> None:
        assert _parse_set_cookie_name(value) == expected, desc

    @pytest.mark.parametrize(
        ("entries", "expected", "desc"),
        DETECT_CLIENT_SIDE_COOKIE_CASES,
        ids=[c[2] for c in DETECT_CLIENT_SIDE_COOKIE_CASES],
    )
    def test_detect_client_side_cookies(self, entries: list, expected: list[str], desc: str) -> None:
        assert _detect_client_side_cookies(entries) == expected, desc

    @pytest.mark.parametrize(
        ("entries", "expected", "desc"),
        SANITIZE_HAR_CLIENT_COOKIE_CASES,
        ids=[c[2] for c in SANITIZE_HAR_CLIENT_COOKIE_CASES],
    )
    def test_sanitize_har_client_side_cookies_metadata(
        self, entries: list, expected: list[str], desc: str
    ) -> None:
        """Integration: sanitize_har writes correct _client_side_cookies into log._har_capture."""
        har = {"log": {"entries": entries}}
        result, _ = sanitize_har(har, salt="test")
        assert result["log"]["_har_capture"]["_client_side_cookies"] == expected, desc


# =============================================================================
# URL Credential Entry Annotation (_sanitized_credentials)
# =============================================================================

# ┌─────────────────────────────────────────────────────────┬────────────────────────────────┬──────────────────────────────────────┐
# │ entries                                                 │ expected_annotations           │ description                          │
# └─────────────────────────────────────────────────────────┴────────────────────────────────┴──────────────────────────────────────┘
#
# YWRtaW46cGFzcw== = base64("admin:pass")
# aGVsbG8gd29ybGQ= = base64("hello world") — no colon, not a credential
#
# fmt: off
_CRED_BARE_URL = [
    {"request": {"url": "https://device.local/api?YWRtaW46cGFzcw==", "headers": [], "queryString": []}},
]
_CRED_PARAM_VALUE_URL = [
    {"request": {"url": "https://device.local/api?auth=YWRtaW46cGFzcw==", "headers": [], "queryString": []}},
]
_CRED_QS_NAME = [
    {"request": {"url": "https://device.local/api", "headers": [],
                 "queryString": [{"name": "YWRtaW46cGFzcw==", "value": ""}]}},
]
_CRED_QS_VALUE = [
    {"request": {"url": "https://device.local/api", "headers": [],
                 "queryString": [{"name": "auth", "value": "YWRtaW46cGFzcw=="}]}},
]
_NO_CRED_URL = [
    {"request": {"url": "https://device.local/api?id=123&format=json", "headers": [], "queryString": []}},
]
_NON_CRED_BASE64_URL = [
    {"request": {"url": "https://device.local/api?data=aGVsbG8gd29ybGQ=", "headers": [], "queryString": []}},
]
_MULTI_ENTRY_CRED = [
    {"request": {"url": "https://device.local/status", "headers": [], "queryString": []}},
    {"request": {"url": "https://device.local/api?YWRtaW46cGFzcw==", "headers": [], "queryString": []}},
]
# Entry with no URL — covers `if url:` False branch
_NO_URL_ENTRY = [
    {"request": {"url": "", "headers": [], "queryString": []}},
]
# URL with a bare flag segment (no '=', not a credential) — covers `if "=" in segment:` False branch
_BARE_FLAG_SEGMENT_URL = [
    {"request": {"url": "https://device.local/api?debug&format=json", "headers": [], "queryString": []}},
]
# Non-dict entry in queryString — covers `isinstance(param, dict)` False branch
_NONDICT_QS_ENTRY = [
    {"request": {"url": "https://device.local/api", "headers": [],
                 "queryString": ["not-a-dict", {"name": "session", "value": "abc"}]}},
]

DETECT_URL_CREDENTIAL_ENTRIES_CASES = [
    # (entries,              expected_annotations,                              description)
    (_CRED_BARE_URL,        [{"entry_index": 0, "location": "url_query_param"}], "bare_cred_in_url"),
    (_CRED_PARAM_VALUE_URL, [{"entry_index": 0, "location": "url_query_param"}], "cred_in_param_value"),
    (_CRED_QS_NAME,         [{"entry_index": 0, "location": "url_query_param"}], "cred_in_qs_name"),
    (_CRED_QS_VALUE,        [{"entry_index": 0, "location": "url_query_param"}], "cred_in_qs_value"),
    (_NO_CRED_URL,          [],                                                  "no_cred_normal_params"),
    (_NON_CRED_BASE64_URL,  [],                                                  "non_cred_base64_no_colon"),
    ([],                    [],                                                  "empty_entries"),
    (_MULTI_ENTRY_CRED,     [{"entry_index": 1, "location": "url_query_param"}], "correct_entry_index"),
    (_NO_URL_ENTRY,         [],                                                  "no_url_skipped"),
    (_BARE_FLAG_SEGMENT_URL, [],                                                 "bare_flag_segment_no_eq"),
    (_NONDICT_QS_ENTRY,     [],                                                  "nondict_qs_entry_skipped"),
]

SANITIZE_HAR_SANITIZED_CRED_CASES = [
    # (entries,              expected_annotations,                              desc)
    ([_ENTRY([],             []), _ENTRY([], [])],                              [],
     "no_cred_empty_list"),
    ([_ENTRY([{"name": "Cookie", "value": "session=abc"}], [])],               [],
     "cookie_only_not_a_url_cred"),
]
# fmt: on


class TestSanitizedCredentialAnnotation:
    """Tests for _detect_url_credential_entries and _sanitized_credentials metadata."""

    @pytest.mark.parametrize(
        ("entries", "expected", "desc"),
        DETECT_URL_CREDENTIAL_ENTRIES_CASES,
        ids=[c[2] for c in DETECT_URL_CREDENTIAL_ENTRIES_CASES],
    )
    def test_detect_url_credential_entries(self, entries: list, expected: list[dict], desc: str) -> None:
        assert _detect_url_credential_entries(entries) == expected, desc

    @pytest.mark.parametrize(
        ("entries", "expected", "desc"),
        SANITIZE_HAR_SANITIZED_CRED_CASES,
        ids=[c[2] for c in SANITIZE_HAR_SANITIZED_CRED_CASES],
    )
    def test_sanitize_har_sanitized_credentials_empty(self, entries: list, expected: list, desc: str) -> None:
        """Integration: _sanitized_credentials is empty when no URL credentials present."""
        har = {"log": {"entries": entries}}
        result, _ = sanitize_har(har, salt="test")
        assert result["log"]["_har_capture"]["_sanitized_credentials"] == expected, desc

    def test_sanitize_har_records_url_credential_location(self) -> None:
        """Integration: _sanitized_credentials records entry index before placeholder replaces credential."""
        har = {
            "log": {
                "entries": [
                    _ENTRY([], []),
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://device.local/status?YWRtaW46cGFzcw==",
                            "headers": [],
                            "queryString": [{"name": "YWRtaW46cGFzcw==", "value": ""}],
                        },
                        "response": {"status": 200, "headers": [], "content": {}},
                    },
                ]
            }
        }
        result, _ = sanitize_har(har, salt="test")
        creds = result["log"]["_har_capture"]["_sanitized_credentials"]
        assert creds == [{"entry_index": 1, "location": "url_query_param"}]
        # Confirm the URL was actually sanitized (placeholder is not valid base64 credential)
        result_url = result["log"]["entries"][1]["request"]["url"]
        assert "YWRtaW46cGFzcw==" not in result_url


# =============================================================================
# Server-Token Preservation: _extract_url_credential_raw / _is_echoed_credential
# =============================================================================

# URL cred: admin:pass → YWRtaW46cGFzcw==
_ADMIN_PASS_RAW = base64.b64encode(b"admin:pass").decode()  # YWRtaW46cGFzcw==
_ADMIN_RAW = base64.b64encode(b"admin").decode()  # YWRtaW4=
_PASS_RAW = base64.b64encode(b"pass").decode()  # cGFzcw==
# A server-issued opaque token that decodes to "session:abc123" — has a colon
# so is_base64_credential() fires, but it does NOT echo the user's credential.
_SERVER_TOKEN = base64.b64encode(b"session:abc123").decode()

# url_cred_raw whose b64decode yields non-UTF-8 bytes → triggers the except branch
_NON_UTF8_CRED_RAW = base64.b64encode(b"\xff\xfe").decode()
# url_cred_raw that decodes to valid UTF-8 with no colon → triggers the no-colon branch
_NO_COLON_CRED_RAW = base64.b64encode(b"simple").decode()

# fmt: off
EXTRACT_URL_CRED_RAW_CASES = [
    # (request_dict, expected_raw, desc)
    (
        {"url": f"https://d.local/login?{_ADMIN_PASS_RAW}", "queryString": []},
        _ADMIN_PASS_RAW,
        "bare_cred_in_url",
    ),
    (
        {"url": f"https://d.local/login?token={_ADMIN_PASS_RAW}", "queryString": []},
        _ADMIN_PASS_RAW,
        "cred_as_param_value_in_url",
    ),
    (
        {"url": "https://d.local/status", "queryString": []},
        None,
        "no_cred_in_url",
    ),
    # Bare segment without '=' that isn't a cred — exercises 1417→1411 false branch
    (
        {"url": "https://d.local/page?debug", "queryString": []},
        None,
        "bare_non_cred_segment_no_eq",
    ),
    # key=value pair where value isn't a cred — exercises 1420→1411 false branch
    (
        {"url": "https://d.local/page?format=json", "queryString": []},
        None,
        "key_value_non_cred_value",
    ),
    # Non-string url — exercises line 1408 defensive branch
    (
        {"url": 9000, "queryString": []},
        None,
        "non_string_url",
    ),
    (
        {"url": "", "queryString": [{"name": "token", "value": _ADMIN_PASS_RAW}]},
        _ADMIN_PASS_RAW,
        "cred_in_querystring_value",
    ),
    (
        {"url": "", "queryString": [{"name": _ADMIN_PASS_RAW, "value": ""}]},
        _ADMIN_PASS_RAW,
        "cred_as_querystring_name",
    ),
    # Non-dict entry in queryString — exercises line 1425 continue branch
    (
        {"url": "", "queryString": ["not-a-dict"]},
        None,
        "non_dict_querystring_entry",
    ),
    # Empty value + non-cred name — exercises 1430→1423 false branch
    (
        {"url": "", "queryString": [{"name": "format", "value": ""}]},
        None,
        "non_cred_name_empty_value",
    ),
    (
        {"url": "", "queryString": []},
        None,
        "empty_request",
    ),
]

IS_ECHOED_CRED_CASES = [
    # (body, url_cred_raw, expected, desc)
    (_ADMIN_PASS_RAW, _ADMIN_PASS_RAW, True,  "exact_match"),
    (_ADMIN_RAW,      _ADMIN_PASS_RAW, True,  "btoa_user"),
    (_PASS_RAW,       _ADMIN_PASS_RAW, True,  "btoa_password"),
    (_SERVER_TOKEN,   _ADMIN_PASS_RAW, False, "server_token_not_echoed"),
    # url_cred_raw decodes to plain text with no colon → exercises line 1452 return False
    ("anything",      _NO_COLON_CRED_RAW, False, "url_cred_no_colon"),
    # url_cred_raw decodes to non-UTF-8 bytes → exercises except branch (lines 1449-1450)
    ("anything",      _NON_UTF8_CRED_RAW, False, "url_cred_non_utf8_bytes"),
]

SERVER_TOKEN_PRESERVATION_CASES = [
    # (url_cred, response_body, body_preserved, desc)
    # Server token: decodes to "session:abc123" — looks like a credential but isn't the user's
    (
        _ADMIN_PASS_RAW,
        _SERVER_TOKEN,
        True,
        "server_token_preserved_when_url_cred_present",
    ),
    # Echoed credential: response body IS the URL credential
    (
        _ADMIN_PASS_RAW,
        _ADMIN_PASS_RAW,
        False,
        "echoed_cred_redacted",
    ),
    # No URL cred context → conservative: redact anything that looks like a credential
    (
        None,
        _SERVER_TOKEN,
        False,
        "no_url_cred_context_still_redacted",
    ),
]
# fmt: on


class TestUrlCredentialRawExtraction:
    """Tests for _extract_url_credential_raw."""

    @pytest.mark.parametrize(
        ("request_dict", "expected", "desc"),
        EXTRACT_URL_CRED_RAW_CASES,
        ids=[c[2] for c in EXTRACT_URL_CRED_RAW_CASES],
    )
    def test_extract_url_credential_raw(self, request_dict: dict, expected: str | None, desc: str) -> None:
        assert _extract_url_credential_raw(request_dict) == expected, desc


class TestIsEchoedCredential:
    """Tests for _is_echoed_credential."""

    @pytest.mark.parametrize(
        ("body", "url_cred_raw", "expected", "desc"),
        IS_ECHOED_CRED_CASES,
        ids=[c[3] for c in IS_ECHOED_CRED_CASES],
    )
    def test_is_echoed_credential(self, body: str, url_cred_raw: str, expected: bool, desc: str) -> None:
        assert _is_echoed_credential(body, url_cred_raw) == expected, desc


class TestServerTokenPreservation:
    """Integration tests for server-token preservation in sanitize_har."""

    @pytest.mark.parametrize(
        ("url_cred", "response_body", "body_preserved", "desc"),
        SERVER_TOKEN_PRESERVATION_CASES,
        ids=[c[3] for c in SERVER_TOKEN_PRESERVATION_CASES],
    )
    def test_server_token_preservation(
        self, url_cred: str | None, response_body: str, body_preserved: bool, desc: str
    ) -> None:
        url = f"https://device.local/login?{url_cred}" if url_cred else "https://device.local/login"
        qs = [{"name": url_cred, "value": ""}] if url_cred else []
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": url,
                            "headers": [],
                            "queryString": qs,
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": response_body, "mimeType": "text/plain"},
                        },
                    }
                ]
            }
        }
        result, _ = sanitize_har(har, salt="test")
        result_body = result["log"]["entries"][0]["response"]["content"]["text"]
        if body_preserved:
            assert result_body == response_body, f"{desc}: server token should be preserved"
        else:
            assert result_body != response_body, f"{desc}: credential should be redacted"


# ── base64-encoded response bodies & credential values ───────────────────────
# base64(user:pass) strings are opaque credentials; base64(JSON) is a payload.
_B64_OBJECT = base64.b64encode(b'{"a": 1, "b": {"c": 2}}').decode()
_B64_ARRAY = base64.b64encode(b'[{"x": 1}, {"y": 2}]').decode()
_B64_SCALAR_NUM = base64.b64encode(b"42").decode()
_B64_SCALAR_STR = base64.b64encode(b'"just-a-string"').decode()
_B64_NON_JSON = base64.b64encode(b"admin:password").decode()
_B64_NON_UTF8 = base64.b64encode(b"\xff\xfe\xfa\xfb").decode()
_B64_USERPASS = base64.b64encode(b"admin:hunter2").decode()

# base64-JSON object/array each carry a MAC that must be redacted *in place*;
# an opaque base64(user:pass) body must collapse to a single AUTH placeholder.
_B64_JSON_OBJECT_PII = base64.b64encode(json.dumps({"mac": "AA:BB:CC:DD:EE:FF", "ch": 1}).encode()).decode()
_B64_JSON_ARRAY_PII = base64.b64encode(
    json.dumps([{"mac": "AA:BB:CC:DD:EE:FF"}, {"ch": 2}]).encode()
).decode()
_B64_OPAQUE_CRED = base64.b64encode(b"admin:supersecret").decode()

# fmt: off
DECODE_BASE64_JSON_CASES = [
    # (value, is_structured, desc)
    (_B64_OBJECT,      True,  "base64_json_object"),
    (_B64_ARRAY,       True,  "base64_json_array"),
    (_B64_SCALAR_NUM,  False, "base64_json_scalar_number"),
    (_B64_SCALAR_STR,  False, "base64_json_scalar_string"),
    (_B64_NON_JSON,    False, "base64_non_json_colon_string"),
    (_B64_NON_UTF8,    False, "base64_non_utf8_bytes"),
    ('{"a": 1}',       False, "plain_json_not_base64"),
    ("<html></html>",  False, "html_not_base64"),
    ("",               False, "empty_string"),
]

RESPONSE_BASE64_BODY_CASES = [
    # (body, structure_preserved, desc)
    (_B64_JSON_OBJECT_PII, True,  "base64_json_object_preserved"),
    (_B64_JSON_ARRAY_PII,  True,  "base64_json_array_preserved"),
    (_B64_OPAQUE_CRED,     False, "opaque_credential_collapsed"),
]

# base64(user:pass) in an unrecognized field name ('vendorpw' is not default-sensitive)
# must be redacted by the value fallback — identically across param surfaces.
BASE64_CRED_PARAM_CASES = [
    # (desc, request_fragment, accessor)
    (
        "post_param",
        {"postData": {"mimeType": "application/x-www-form-urlencoded",
                      "params": [{"name": "vendorpw", "value": _B64_USERPASS}]}},
        lambda r: r["request"]["postData"]["params"][0]["value"],
    ),
    (
        "query_param",
        {"queryString": [{"name": "vendorpw", "value": _B64_USERPASS}]},
        lambda r: r["request"]["queryString"][0]["value"],
    ),
]

# Benign params (not sensitive, not flaggable, not base64-credential by value or
# name) fall through every redaction branch untouched.
BENIGN_PARAM_CASES = [
    # (desc, request_fragment, accessor)
    (
        "post_param",
        {"postData": {"mimeType": "application/x-www-form-urlencoded",
                      "params": [{"name": "format", "value": "json"}]}},
        lambda r: r["request"]["postData"]["params"][0],
    ),
    (
        "query_param",
        {"queryString": [{"name": "format", "value": "json"}]},
        lambda r: r["request"]["queryString"][0],
    ),
]
# fmt: on


def _entry_with_response_body(body: str) -> dict[str, Any]:
    """Minimal HAR entry whose response body is ``body`` with an empty Content-Type."""
    return {
        "request": {"method": "GET", "url": "http://192.168.0.1/setup.cgi?todo=status", "headers": []},
        "response": {"status": 200, "headers": [], "content": {"text": body, "mimeType": ""}},
    }


class TestBase64JsonResponseStructure:
    """Base64-encoded JSON response bodies keep structure; opaque tokens collapse.

    Some devices (e.g. the Sercomm DM1000) return data as raw base64-encoded JSON
    from ``setup.cgi?todo=...`` endpoints with an empty Content-Type. The decoded
    body is colon-bearing, so the opaque-credential heuristic used to collapse the
    whole payload into a single ``AUTH_`` token, destroying every field name and
    the JSON shape. Structure (not PII) must survive — only values are redacted.
    """

    @pytest.mark.parametrize(
        ("body", "structure_preserved", "desc"),
        RESPONSE_BASE64_BODY_CASES,
        ids=[c[2] for c in RESPONSE_BASE64_BODY_CASES],
    )
    def test_base64_body_preserved_or_collapsed(
        self, body: str, structure_preserved: bool, desc: str
    ) -> None:
        result = sanitize_entry(_entry_with_response_body(body), salt=None)
        out_text = result["response"]["content"]["text"]
        if structure_preserved:
            decoded = json.loads(base64.b64decode(out_text).decode())
            assert isinstance(decoded, dict | list), desc
            assert "AA:BB:CC:DD:EE:FF" not in out_text, desc  # MAC redacted in place
        else:
            assert out_text == "***AUTH***", desc

    def test_field_names_and_benign_values_survive(self) -> None:
        """A base64-JSON body keeps field names + benign values; only PII is redacted."""
        payload = {
            "status": "ok",
            "downstream": [{"channel": 1, "power": "-7.0", "snr": "38.5"}],
            "lan_mac": "AA:BB:CC:DD:EE:FF",
            "password": "hunter2",
        }
        body_b64 = base64.b64encode(json.dumps(payload).encode()).decode()

        result = sanitize_entry(_entry_with_response_body(body_b64), salt=None)
        decoded = json.loads(base64.b64decode(result["response"]["content"]["text"]).decode())

        assert set(decoded) == {"status", "downstream", "lan_mac", "password"}
        assert decoded["status"] == "ok"
        assert decoded["downstream"][0] == {"channel": 1, "power": "-7.0", "snr": "38.5"}
        assert decoded["lan_mac"] != "AA:BB:CC:DD:EE:FF"  # value-pattern redaction
        assert decoded["password"] != "hunter2"  # sensitive field-name redaction


class TestDecodeBase64Json:
    """Unit tests for the _decode_base64_json payload-vs-secret discriminator."""

    @pytest.mark.parametrize(
        ("value", "is_structured", "desc"),
        DECODE_BASE64_JSON_CASES,
        ids=[c[2] for c in DECODE_BASE64_JSON_CASES],
    )
    def test_decode_base64_json(self, value: str, is_structured: bool, desc: str) -> None:
        result = _decode_base64_json(value)
        if is_structured:
            assert isinstance(result, dict | list), desc
        else:
            assert result is None, desc


class TestBase64CredentialInFields:
    """base64(user:pass) values in unrecognized field names are redacted everywhere.

    Mirrors the query-string base64-credential fallback across param surfaces: a
    value in a field like ``vendorpw`` (not default-sensitive) used to slip past
    field-name redaction while sibling ``passwd``/``cur_passwd`` were redacted.
    """

    @pytest.mark.parametrize(
        ("desc", "request_fragment", "accessor"),
        BASE64_CRED_PARAM_CASES,
        ids=[c[0] for c in BASE64_CRED_PARAM_CASES],
    )
    def test_base64_credential_value_redacted(
        self, desc: str, request_fragment: dict[str, Any], accessor: Any
    ) -> None:
        entry = {
            "request": {"method": "POST", "url": "http://device/login", "headers": [], **request_fragment},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        assert accessor(result) == "***AUTH***", desc

    @pytest.mark.parametrize(
        ("desc", "request_fragment", "accessor"),
        BENIGN_PARAM_CASES,
        ids=[c[0] for c in BENIGN_PARAM_CASES],
    )
    def test_benign_param_preserved(self, desc: str, request_fragment: dict[str, Any], accessor: Any) -> None:
        """A param that matches no redaction branch passes through untouched."""
        entry = {
            "request": {"method": "POST", "url": "http://device/status", "headers": [], **request_fragment},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        param = accessor(result)
        assert param == {"name": "format", "value": "json"}, desc

    def test_malformed_querystring_entries_skipped(self) -> None:
        """Non-dict and name-less queryString entries are left untouched, not errored."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://device/status",
                "headers": [],
                "queryString": ["not-a-dict", {"label": "x"}],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        assert result["request"]["queryString"] == ["not-a-dict", {"label": "x"}]

    def test_malformed_cookie_entries_skipped(self) -> None:
        """Non-dict and value-less request cookies are left untouched, not errored."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://device/status",
                "headers": [],
                "cookies": ["not-a-dict", {"name": "n"}],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        assert result["request"]["cookies"] == ["not-a-dict", {"name": "n"}]

    def test_request_without_url_is_tolerated(self) -> None:
        """A request with no 'url' key skips URL sanitization without erroring."""
        entry = {
            "request": {"method": "GET", "headers": []},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        assert "url" not in result["request"]

    def test_sibling_named_fields_and_form_text(self) -> None:
        """Named siblings redact by name; the base64 cred redacts by value (params + text)."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "passwd", "value": "secret"},
                {"name": "cur_passwd", "value": "classified"},
                {"name": "vendorpw", "value": _B64_USERPASS},
            ],
            "text": f"passwd=secret&cur_passwd=classified&vendorpw={_B64_USERPASS}",
        }

        result = sanitize_post_data(post_data)
        assert result is not None
        params = {p["name"]: p["value"] for p in result["params"]}
        assert params["passwd"] == "[REDACTED]"
        assert params["cur_passwd"] == "[REDACTED]"
        assert params["vendorpw"] == "[REDACTED]"  # base64 value fallback
        assert _B64_USERPASS not in result["text"]

    def test_percent_encoded_base64_credential_in_form_text(self) -> None:
        """A percent-encoded base64(user:pass) value is caught via the unquote fallback."""
        encoded = _B64_USERPASS.replace("=", "%3D")  # padding no longer base64-charset
        result = _sanitize_form_urlencoded(f"user=admin&vendorpw={encoded}")
        assert encoded not in result
        assert _B64_USERPASS not in result
        assert "vendorpw=[REDACTED]" in result

    def test_placeholder_correlation_between_params_and_text(self) -> None:
        """The same secret gets the same FIELD placeholder in params and text.

        The text copy is percent-encoded ('=' padding becomes %3D); hashing
        must run on the decoded value so both copies correlate (issue #92
        capture shape).
        """
        from har_capture.patterns import Hasher

        secret = "ZXhhbXBsZS1ub3QtcmVhbA=="  # base64('example-not-real')
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "pws", "value": secret},
                {"name": "passwd", "value": "example-not-real"},
            ],
            "text": "pws=ZXhhbXBsZS1ub3QtcmVhbA%3D%3D&passwd=example-not-real",
        }
        result = sanitize_post_data(post_data, hasher=Hasher("x" * 32))
        assert result is not None
        params = {p["name"]: p["value"] for p in result["params"]}
        text_values = dict(pair.split("=", 1) for pair in result["text"].split("&"))
        assert params["pws"].startswith("FIELD_")
        assert params["pws"] == text_values["pws"]
        assert params["passwd"] == text_values["passwd"]


class TestLoginShapedBase64Heuristic:
    """Login-shaped-form base64 heuristic: flag for review, never auto-redact.

    The backstop for vendor credential fields the name patterns don't know
    yet (issue #92 class).
    """

    _B64_BARE_PASSWORD = base64.b64encode(b"example-not-real").decode()

    def _collector(self) -> RedactionCollector:
        from har_capture.patterns import Hasher

        return RedactionCollector(hasher=Hasher("x" * 32))

    def test_flagged_in_login_shaped_params_and_text(self) -> None:
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "login_user", "value": "admin"},
                {"name": "vendorpw", "value": self._B64_BARE_PASSWORD},
            ],
            "text": f"login_user=admin&vendorpw={self._B64_BARE_PASSWORD.replace('=', '%3D')}",
        }
        collector = self._collector()
        result = sanitize_post_data(post_data, collector=collector)
        assert result is not None

        flagged = [f for f in collector.flagged if f.original_value == self._B64_BARE_PASSWORD]
        assert len(flagged) == 1, "params and text copies must dedupe to one flag"
        assert flagged[0].category == "credential"
        assert flagged[0].occurrences == 2
        # Flagged, not auto-redacted — the value survives pending user review.
        params = {p["name"]: p["value"] for p in result["params"]}
        assert params["vendorpw"] == self._B64_BARE_PASSWORD

    def test_not_flagged_without_login_context(self) -> None:
        """The same base64 value in a form with no credential-named siblings stays silent."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": "payload", "value": self._B64_BARE_PASSWORD}],
            "text": f"payload={self._B64_BARE_PASSWORD.replace('=', '%3D')}",
        }
        collector = self._collector()
        sanitize_post_data(post_data, collector=collector)
        assert collector.flagged == []

    def test_non_base64_values_not_flagged_in_login_shaped_form(self) -> None:
        """Plain values in unrecognized fields of a login form are untouched."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "login_user", "value": "admin"},
                {"name": "todo", "value": "save"},
            ],
            "text": "login_user=admin&todo=save",
        }
        collector = self._collector()
        result = sanitize_post_data(post_data, collector=collector)
        assert result is not None
        assert all(f.category != "credential" for f in collector.flagged)
        params = {p["name"]: p["value"] for p in result["params"]}
        assert params["todo"] == "save"


# ┌──────────────────────────────┬──────────────┬──────────────────────────────────────────────────────┬──────────────────────────────────────┐
# │ desc                         │ storage_key  │ har_capture_input                                    │ assertion                            │
# ├──────────────────────────────┼──────────────┼──────────────────────────────────────────────────────┼──────────────────────────────────────┤
# │ Test case name               │ Which key    │ _har_capture metadata                                │ Lambda checking result               │
# └──────────────────────────────┴──────────────┴──────────────────────────────────────────────────────┴──────────────────────────────────────┘
#
# fmt: off
WEB_STORAGE_SANITIZATION_CASES = [
    (
        "local_storage_values_redacted",
        "local_storage",
        {
            "local_storage": [
                {
                    "origin": "https://192.168.100.1",
                    "items": [
                        {"name": "PrivateKey", "value": "hmac_secret_123"},
                        {"name": "firmware_url", "value": "http://10.0.1.1/fw"},
                    ],
                },
            ],
        },
        lambda r: (
            r["local_storage"][0]["items"][0]["name"] == "PrivateKey"
            and r["local_storage"][0]["items"][0]["value"] != "hmac_secret_123"
            and r["local_storage"][0]["items"][1]["name"] == "firmware_url"
            and r["local_storage"][0]["items"][1]["value"] != "http://10.0.1.1/fw"
        ),
    ),
    (
        "session_storage_values_redacted",
        "session_storage",
        {
            "session_storage": [
                {
                    "origin": "https://192.168.100.1",
                    "items": [
                        {"name": "sjcl_key", "value": "aes256_key_abc"},
                        {"name": "csrf_token", "value": "xsrf_token_xyz"},
                    ],
                },
            ],
        },
        lambda r: (
            r["session_storage"][0]["items"][0]["name"] == "sjcl_key"
            and r["session_storage"][0]["items"][0]["value"] != "aes256_key_abc"
            and r["session_storage"][0]["items"][1]["name"] == "csrf_token"
            and r["session_storage"][0]["items"][1]["value"] != "xsrf_token_xyz"
        ),
    ),
    (
        "origin_preserved",
        "local_storage",
        {
            "local_storage": [
                {"origin": "https://192.168.100.1", "items": [{"name": "k", "value": "v"}]},
            ],
            "session_storage": [
                {"origin": "http://10.0.0.1:8080", "items": [{"name": "t", "value": "a"}]},
            ],
        },
        lambda r: (
            r["local_storage"][0]["origin"] == "https://192.168.100.1"
            and r["session_storage"][0]["origin"] == "http://10.0.0.1:8080"
        ),
    ),
    (
        "absent_no_error",
        "local_storage",
        {"tool": "har-capture", "version": "0.4.2"},
        lambda r: "local_storage" not in r and "session_storage" not in r,
    ),
    (
        "empty_lists_preserved",
        "local_storage",
        {"local_storage": [], "session_storage": []},
        lambda r: r["local_storage"] == [] and r["session_storage"] == [],
    ),
    (
        "storage_prefix_not_cookie",
        "local_storage",
        {
            "local_storage": [
                {"origin": "https://example.com", "items": [{"name": "key", "value": "secret_value"}]},
            ],
        },
        lambda r: r["local_storage"][0]["items"][0]["value"].startswith("STORAGE_"),
    ),
]
# fmt: on


class TestWebStorageSanitization:
    """Tests for web storage sanitization in _har_capture metadata."""

    @pytest.mark.parametrize(
        ("desc", "storage_key", "har_capture_input", "check"),
        WEB_STORAGE_SANITIZATION_CASES,
        ids=[c[0] for c in WEB_STORAGE_SANITIZATION_CASES],
    )
    def test_web_storage_sanitization(
        self,
        desc: str,
        storage_key: str,
        har_capture_input: dict,
        check: object,
    ) -> None:
        """Table-driven web storage sanitization tests."""
        har = {"log": {"entries": [], "_har_capture": har_capture_input}}

        result, _ = sanitize_har(har, salt="test-salt")

        meta = result["log"]["_har_capture"]
        assert check(meta), f"Assertion failed for case: {desc}"


class TestSanitizeJsonTextLogging:
    """Tests for _sanitize_json_text debug logging."""

    def test_sanitize_json_text_invalid_json_logs_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """Non-JSON text logs debug message."""
        import logging

        from har_capture.sanitization.har import _sanitize_json_text

        with caplog.at_level(logging.DEBUG):
            result = _sanitize_json_text("<html>not json</html>")
        assert result == "<html>not json</html>"
        assert "Non-JSON" in caplog.text


# =============================================================================
# Sanitization Metadata Embedding
# =============================================================================

# ┌──────────────────────┬────────────┬──────────────────────────────────────┐
# │ salt_arg             │ expected   │ description                          │
# ├──────────────────────┼────────────┼──────────────────────────────────────┤
SALT_MODE_CASES = [
    ("auto", "random", "auto keyword → random mode"),
    ("random", "random", "random keyword → random mode"),
    (None, "static", "None → static mode"),
    ("my-salt", "provided", "user string → provided mode"),
    ("s3cret!", "provided", "special chars → provided mode"),
]
# └──────────────────────┴────────────┴──────────────────────────────────────┘

# ┌──────────────────────┬──────────────────────────────────────────────────┐
# │ heuristic_mode       │ expected_value                                  │
# ├──────────────────────┼──────────────────────────────────────────────────┤
HEURISTICS_MODE_CASES = [
    (HeuristicMode.DISABLED, "disabled"),
    (HeuristicMode.FLAG, "flag"),
    (HeuristicMode.REDACT, "redact"),
]
# └──────────────────────┴──────────────────────────────────────────────────┘

# Required keys in the sanitization metadata block
_REQUIRED_METADATA_KEYS = frozenset(
    {
        "tool",
        "version",
        "sanitized_at",
        "salt_mode",
        "heuristics",
        "auto_redacted",
        "auto_redacted_counts",
        "user_redacted",
        "user_skipped",
        "flagged_total",
        "warnings",
    }
)


def _make_report(**overrides: object) -> SanitizationReport:
    """Build a minimal SanitizationReport with optional overrides."""
    defaults: dict[str, object] = {
        "input_file": "",
        "output_file": "",
        "salt": "test-salt",
        "auto_redacted_counts": {"password": 3, "mac_address": 2},
    }
    defaults.update(overrides)
    return SanitizationReport(**defaults)  # type: ignore[arg-type]


class TestEmbedSanitizationMetadataUnit:
    """Unit tests for _embed_sanitization_metadata() called directly."""

    def test_all_required_keys_present(self) -> None:
        """Metadata block contains every required key."""
        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, _make_report(), HeuristicMode.DISABLED, "auto")
        meta = har["log"]["_har_capture"]["sanitization"]  # type: ignore[index]
        assert set(meta.keys()) == _REQUIRED_METADATA_KEYS

    @pytest.mark.parametrize(
        ("salt_arg", "expected_mode", "desc"),
        SALT_MODE_CASES,
        ids=[c[2] for c in SALT_MODE_CASES],
    )
    def test_salt_mode_mapping(
        self,
        salt_arg: str | None,
        expected_mode: str,
        desc: str,
    ) -> None:
        """Salt argument maps to correct salt_mode string."""
        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, _make_report(), HeuristicMode.DISABLED, salt_arg)
        assert har["log"]["_har_capture"]["sanitization"]["salt_mode"] == expected_mode  # type: ignore[index]

    @pytest.mark.parametrize(
        ("mode", "expected_value"),
        HEURISTICS_MODE_CASES,
        ids=[m.value for m, _ in HEURISTICS_MODE_CASES],
    )
    def test_heuristics_mode_recorded(
        self,
        mode: HeuristicMode,
        expected_value: str,
    ) -> None:
        """Each HeuristicMode enum is serialised to its .value string."""
        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, _make_report(), mode, "auto")
        assert har["log"]["_har_capture"]["sanitization"]["heuristics"] == expected_value  # type: ignore[index]

    def test_report_counts_propagated(self) -> None:
        """Auto-redacted counts from the report appear in metadata."""
        report = _make_report(auto_redacted_counts={"password": 5, "mac_address": 12})
        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, report, HeuristicMode.DISABLED, "auto")
        meta = har["log"]["_har_capture"]["sanitization"]  # type: ignore[index]
        assert meta["auto_redacted"] == 17
        assert meta["auto_redacted_counts"] == {"password": 5, "mac_address": 12}

    def test_does_not_leak_salt_value(self) -> None:
        """Actual salt string must never appear anywhere in the metadata."""
        report = _make_report(salt="super-secret-salt")
        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, report, HeuristicMode.DISABLED, "super-secret-salt")
        meta_json = json.dumps(har["log"]["_har_capture"]["sanitization"])  # type: ignore[index]
        assert "super-secret-salt" not in meta_json
        # Only salt-related key should be salt_mode
        assert set(k for k in har["log"]["_har_capture"]["sanitization"] if "salt" in k) == {"salt_mode"}  # type: ignore[index]

    def test_preserves_existing_har_capture_keys(self) -> None:
        """Existing _har_capture fields are not clobbered."""
        har: dict[str, object] = {
            "log": {"_har_capture": {"version": "0.4.3", "browser_cookies": []}},
        }
        _embed_sanitization_metadata(har, _make_report(), HeuristicMode.DISABLED, "auto")
        cap = har["log"]["_har_capture"]  # type: ignore[index]
        assert cap["version"] == "0.4.3"
        assert cap["browser_cookies"] == []
        assert "sanitization" in cap

    def test_creates_log_and_har_capture_if_missing(self) -> None:
        """Works even when log and _har_capture don't exist yet."""
        har: dict[str, object] = {}
        _embed_sanitization_metadata(har, _make_report(), HeuristicMode.DISABLED, "auto")
        assert "sanitization" in har["log"]["_har_capture"]  # type: ignore[index]

    def test_user_redacted_and_skipped_defaults(self) -> None:
        """Non-interactive report yields zero user counts."""
        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, _make_report(), HeuristicMode.DISABLED, "auto")
        meta = har["log"]["_har_capture"]["sanitization"]  # type: ignore[index]
        assert meta["user_redacted"] == 0
        assert meta["user_skipped"] == 0
        assert meta["flagged_total"] == 0
        assert meta["warnings"] == []

    def test_sanitized_at_is_utc_iso(self) -> None:
        """Timestamp is a valid UTC ISO-8601 string."""
        from datetime import datetime, timezone

        har: dict[str, object] = {"log": {}}
        _embed_sanitization_metadata(har, _make_report(), HeuristicMode.DISABLED, "auto")
        ts = har["log"]["_har_capture"]["sanitization"]["sanitized_at"]  # type: ignore[index]
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timezone.utc.utcoffset(None)


class TestSanitizationMetadataIntegration:
    """Integration tests: sanitize_har() embeds metadata end-to-end."""

    def test_sanitize_har_embeds_metadata(self) -> None:
        """sanitize_har() output contains sanitization metadata with all keys."""
        result, _ = sanitize_har({"log": {"entries": []}})
        meta = result["log"]["_har_capture"]["sanitization"]
        assert set(meta.keys()) == _REQUIRED_METADATA_KEYS
        assert meta["tool"] == "har-capture"

    def test_records_redaction_counts(self) -> None:
        """HAR with sensitive data produces non-zero auto_redacted counts."""
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "http://example.com",
                            "headers": [{"name": "Authorization", "value": "Bearer tok123"}],
                        },
                        "response": {
                            "headers": [],
                            "content": {"text": "", "mimeType": "text/html"},
                        },
                    }
                ]
            }
        }
        result, _ = sanitize_har(har, salt="test")
        meta = result["log"]["_har_capture"]["sanitization"]
        assert meta["auto_redacted"] > 0
        assert isinstance(meta["auto_redacted_counts"], dict)
        assert len(meta["auto_redacted_counts"]) > 0

    def test_preserves_existing_metadata(self) -> None:
        """Existing _har_capture fields are not clobbered by sanitize_har()."""
        har = {
            "log": {
                "entries": [],
                "_har_capture": {
                    "version": "0.4.3",
                    "browser_cookies": [{"name": "sid", "value": "abc"}],
                },
            }
        }
        result, _ = sanitize_har(har, salt="test")
        cap = result["log"]["_har_capture"]
        assert "sanitization" in cap
        assert "browser_cookies" in cap
        assert cap["version"] == "0.4.3"


# =============================================================================
# Base64 Credential Detection in URL Query Parameters
# =============================================================================

# ┌──────────────────────────────────────────────────────────────┬──────────┬──────────────────────────┐
# │ url                                                          │ redacted │ description              │
# ├──────────────────────────────────────────────────────────────┼──────────┼──────────────────────────┤
# │ Full URL with query string                                   │ True/    │ test case name           │
# │                                                              │ False    │                          │
# └──────────────────────────────────────────────────────────────┴──────────┴──────────────────────────┘
#
# fmt: off
BASE64_CRED_URL_CASES = [
    # Bare base64 token as query param (URL token auth pattern)
    ("https://192.168.100.1/status.html?YWRtaW46cGFzc3dvcmQ=", True,  "bare_base64_user_pass"),
    ("https://192.168.100.1/status.html?YWRtaW46TjZyM2gydCFy", True,  "bare_base64_no_padding"),
    # Base64 token as param value
    ("https://modem.local/api?token=YWRtaW46cGFzc3dvcmQ=",     True,  "base64_as_param_value"),
    # Base64 cred in value with non-sensitive key (exercises URL-level detection)
    ("https://modem.local/api?ref=YWRtaW46cGFzc3dvcmQ=",      True,  "base64_val_nonsensitive_key"),
    # Normal query params (should NOT be detected)
    ("https://example.com/page?id=123&format=json",             False, "normal_params"),
    ("https://example.com/page?q=hello+world",                  False, "normal_search_query"),
    # Non-credential base64 (no colon in decoded)
    ("https://example.com/page?data=aGVsbG8gd29ybGQ=",         False, "base64_without_colon"),
    # Short values (too short to be credentials)
    ("https://example.com/page?x=YQ==",                        False, "too_short_base64"),
]
# fmt: on

# ┌──────────────────────────┬──────────────────────┬──────────┬──────────────────────────────┐
# │ body_text                │ mime_type            │ redacted │ description                  │
# ├──────────────────────────┼──────────────────────┼──────────┼──────────────────────────────┤
# │ Response body text       │ Content MIME type    │ True/    │ test case name               │
# │                          │                      │ False    │                              │
# └──────────────────────────┴──────────────────────┴──────────┴──────────────────────────────┘
#
# YWRtaW46cGFzcw==  = base64("admin:pass")
# aGVsbG8gd29ybGQ= = base64("hello world")  — no colon, not a credential
#
# fmt: off
BASE64_CRED_RESPONSE_BODY_CASES = [
    # Real credential — should be redacted regardless of mime type
    ("YWRtaW46cGFzcw==",     "text/plain",       True,  "bare_cred_text_plain"),
    ("YWRtaW46cGFzcw==",     "text/html",        True,  "bare_cred_text_html"),
    ("YWRtaW46cGFzcw==",     "application/json", True,  "bare_cred_application_json"),
    # Whitespace-padded credential — guard strips before checking
    ("  YWRtaW46cGFzcw==  ", "text/plain",       True,  "bare_cred_with_whitespace"),
    # Non-credential base64 (decoded value has no colon) — must not be redacted
    ("aGVsbG8gd29ybGQ=",     "text/plain",       False, "non_cred_base64_no_colon"),
]
# fmt: on


class TestBase64CredentialDetection:
    """Tests for base64-encoded credential detection in URL query parameters."""

    @pytest.mark.parametrize(
        ("url", "should_redact", "desc"),
        BASE64_CRED_URL_CASES,
        ids=[c[2] for c in BASE64_CRED_URL_CASES],
    )
    def test_base64_credential_in_url(self, url: str, should_redact: bool, desc: str) -> None:
        """Test base64-encoded user:pass credentials are detected in URLs."""
        entry = {
            "request": {"method": "GET", "url": url, "headers": [], "queryString": []},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt="test")
        result_url = result["request"]["url"]
        if should_redact:
            assert result_url != url, f"{desc}: URL should be modified"
        else:
            assert result_url == url, f"{desc}: URL should be unchanged"

    def test_base64_credential_in_query_string_array(self) -> None:
        """Test base64 credentials in structured queryString array."""
        entry = {
            "request": {
                "method": "GET",
                "url": "https://192.168.100.1/status.html?YWRtaW46cGFzc3dvcmQ=",
                "headers": [],
                "queryString": [{"name": "YWRtaW46cGFzc3dvcmQ=", "value": ""}],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt="test")
        qs = result["request"]["queryString"]
        assert qs[0]["name"] != "YWRtaW46cGFzc3dvcmQ=", "Base64 cred should be redacted in queryString"

    def test_base64_credential_in_query_string_value(self) -> None:
        """Test base64 credential in queryString param value is redacted."""
        entry = {
            "request": {
                "method": "GET",
                "url": "https://example.com/api",
                "headers": [],
                "queryString": [{"name": "token", "value": "YWRtaW46cGFzc3dvcmQ="}],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt="test")
        qs = result["request"]["queryString"]
        assert qs[0]["value"] != "YWRtaW46cGFzc3dvcmQ=", "Base64 cred in value should be redacted"

    def test_base64_credential_bare_name_without_padding(self) -> None:
        """Test base64 credential as bare param name with padding stripped."""
        cred = base64.b64encode(b"user:secret").decode()  # dXNlcjpzZWNyZXQ=
        stripped = cred.rstrip("=")
        entry = {
            "request": {
                "method": "GET",
                "url": "https://example.com/api",
                "headers": [],
                "queryString": [{"name": stripped, "value": ""}],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt="test")
        qs = result["request"]["queryString"]
        assert qs[0]["name"] != stripped, "Base64 cred name (padding stripped) should be redacted"

    @pytest.mark.parametrize(
        ("body", "mime_type", "should_redact", "desc"),
        BASE64_CRED_RESPONSE_BODY_CASES,
        ids=[c[3] for c in BASE64_CRED_RESPONSE_BODY_CASES],
    )
    def test_base64_credential_in_response_body(
        self, body: str, mime_type: str, should_redact: bool, desc: str
    ) -> None:
        """Test bare base64 credential in response body is redacted regardless of mime type."""
        entry = {
            "request": {
                "method": "GET",
                "url": "https://example.com/status",
                "headers": [],
                "queryString": [],
            },
            "response": {"status": 200, "headers": [], "content": {"text": body, "mimeType": mime_type}},
        }
        result = sanitize_entry(entry, salt="test")
        result_body = result["response"]["content"]["text"]
        if should_redact:
            assert result_body != body.strip(), f"{desc}: body should be redacted"
        else:
            assert result_body == body, f"{desc}: body should be unchanged"

    def test_base64_credential_in_response_body_records_auth_redaction(self) -> None:
        """Test that the response body base64 guard records an auth redaction on the collector."""
        hasher = Hasher.create("test-salt")
        collector = RedactionCollector(hasher=hasher)
        entry = {
            "request": {
                "method": "GET",
                "url": "https://example.com/status",
                "headers": [],
                "queryString": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": "YWRtaW46cGFzcw==", "mimeType": "text/plain"},
            },
        }
        sanitize_entry(entry, salt="test", collector=collector)
        assert collector.auto_redacted_counts.get("auth", 0) >= 1, (
            "AUTH redaction should be recorded on collector"
        )


class TestUrlQueryBareSegment:
    """Tests for URL query segments without '=' that are not base64 credentials."""

    def test_bare_query_segment_preserved(self) -> None:
        """Test bare query segment (no '=', not base64 cred) passes through unchanged."""
        entry = {
            "request": {
                "method": "GET",
                "url": "https://example.com/page?debug&password=secret",
                "headers": [],
                "queryString": [],
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt="test")
        result_url = result["request"]["url"]
        assert "debug" in result_url, "Bare non-credential segment should be preserved"
        assert "secret" not in result_url, "Sensitive param value should be redacted"


class TestCookieHeaderNoNameValuePairs:
    """Tests for cookie headers with no name=value pairs."""

    def test_cookie_header_bare_value_redacted(self) -> None:
        """Test cookie header with bare value (no = sign) is fully redacted."""
        result = sanitize_header_value("Cookie", "opaque_session_token_abc123")
        assert result != "opaque_session_token_abc123", "Bare cookie value should be redacted"

    def test_set_cookie_header_bare_value_redacted(self) -> None:
        """Test Set-Cookie header with bare value (no = sign) is fully redacted."""
        result = sanitize_header_value("Set-Cookie", "some_random_token")
        assert result != "some_random_token", "Bare Set-Cookie value should be redacted"


# =============================================================================
# Cookie Attribute Metadata Sanitization
# =============================================================================

# ┌─────────────┬──────────────────────────────────────┬──────────┬────────────────────────────────┐
# │ header_name │ header_value                         │ redacted │ description                    │
# ├─────────────┼──────────────────────────────────────┼──────────┼────────────────────────────────┤
# │ Header name │ Header value to sanitize             │ True/    │ test case name                 │
# │             │                                      │ False    │                                │
# └─────────────┴──────────────────────────────────────┴──────────┴────────────────────────────────┘
#
# fmt: off
COOKIE_ATTR_CASES = [
    # Attribute metadata (should be redacted as non-cookie data)
    ("Set-Cookie", "HttpOnly: true, Secure: true",      True,  "attribute_metadata_set_cookie"),
    ("Cookie",     "HttpOnly: true, Secure: true",      True,  "attribute_metadata_cookie"),
    ("Set-Cookie", "Secure",                            True,  "bare_secure_attribute"),
    # Normal cookies (should be redacted as cookie values)
    ("Set-Cookie", "session_id=abc123; HttpOnly; Secure", True,  "normal_set_cookie_with_attrs"),
    ("Cookie",     "session=abc123",                    True,  "normal_cookie"),
    # Non-cookie header (should be unchanged)
    ("Content-Type", "text/html",                       False, "non_cookie_header"),
]
# fmt: on


class TestCookieAttributeMetadata:
    """Tests for cookie attribute metadata sanitization."""

    @pytest.mark.parametrize(
        ("header_name", "header_value", "should_redact", "desc"),
        COOKIE_ATTR_CASES,
        ids=[c[3] for c in COOKIE_ATTR_CASES],
    )
    def test_cookie_attribute_metadata(
        self,
        header_name: str,
        header_value: str,
        should_redact: bool,
        desc: str,
    ) -> None:
        """Test cookie headers with attribute metadata are properly handled."""
        result = sanitize_header_value(header_name, header_value)
        if should_redact:
            assert result != header_value, f"{desc}: should be redacted"
        else:
            assert result == header_value, f"{desc}: should be unchanged"


# =============================================================================
# Pre-existing Coverage Gaps
# =============================================================================


class TestValidateHarStructure:
    """Tests for validate_har_structure error and warning paths."""

    # fmt: off
    VALIDATION_ERROR_CASES = [
        ({"log": "not_a_dict"},                                  "'log' must be an object",   "log_not_dict"),
        ({"log": {"version": "1.2"}},                            "Missing required 'entries'", "missing_entries"),
        ({"log": {"entries": "not_a_list"}},                     "'entries' must be an array", "entries_not_list"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("har_data", "expected_msg", "desc"),
        VALIDATION_ERROR_CASES,
        ids=[c[2] for c in VALIDATION_ERROR_CASES],
    )
    def test_structure_errors(self, har_data: dict, expected_msg: str, desc: str) -> None:
        """Test validate_har_structure raises on invalid structures."""
        with pytest.raises(HarValidationError, match=expected_msg):
            validate_har_structure(har_data)

    def test_missing_recommended_fields_warns(self) -> None:
        """Test warnings for missing log.version and log.creator."""
        har_data = {"log": {"entries": []}}
        warnings = validate_har_structure(har_data)
        assert any("version" in w for w in warnings)
        assert any("creator" in w for w in warnings)

    # fmt: off
    STRICT_CASES = [
        ({"log": {"entries": ["not_a_dict"]}},                                        "not an object",    "entry_not_dict"),
        ({"log": {"entries": [{}]}},                                                  "missing 'request'", "entry_missing_request"),
        ({"log": {"entries": [{"request": {"url": "/a"}}]}},                          "missing 'method'", "request_missing_method"),
        ({"log": {"entries": [{"request": {"method": "GET"}}]}},                      "missing 'url'",    "request_missing_url"),
        ({"log": {"entries": [{"request": {"method": "GET", "url": "/a"}}]}},         "missing 'response'", "entry_missing_response"),
        ({"log": {"entries": [{"request": {"method": "GET", "url": "/a"}, "response": {}}]}}, "missing 'status'", "response_missing_status"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("har_data", "expected_warning", "desc"),
        STRICT_CASES,
        ids=[c[2] for c in STRICT_CASES],
    )
    def test_strict_mode_warnings(self, har_data: dict, expected_warning: str, desc: str) -> None:
        """Test strict mode catches missing fields."""
        warnings = validate_har_structure(har_data, strict=True)
        assert any(expected_warning in w for w in warnings), (
            f"{desc}: expected warning containing '{expected_warning}'"
        )


class TestFormUrlencodedSanitization:
    """Tests for _sanitize_form_urlencoded edge cases."""

    def test_flaggable_field_recorded(self) -> None:
        """Test flaggable field in form data is flagged via collector."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_form_urlencoded("username=johndoe&page=1", hasher, collector)
        assert "johndoe" in result, "Flaggable field value should be preserved (not auto-redacted)"
        assert len(collector.flagged) > 0, "Should have flagged the username field"

    def test_bare_segment_without_equals(self) -> None:
        """Test bare segment (no '=') is passed through."""
        result = _sanitize_form_urlencoded("bare_value&password=secret", None, None)
        assert "bare_value" in result
        assert "secret" not in result


class TestJsonRecursiveSanitization:
    """Tests for _sanitize_json_recursive edge cases."""

    # fmt: off
    JSON_EDGE_CASES = [
        # MAC address field — with and without hasher
        ({"mac": "AA:BB:CC:DD:EE:FF"},       "mac",    "AA:BB:CC:DD:EE:FF", "mac_field_redacted"),
        ({"macaddress": "11:22:33:44:55:66"}, "macaddress", "11:22:33:44:55:66", "macaddress_field_redacted"),
        ({"mac": ""},                         "mac",    "",                  "mac_empty_preserved"),
        ({"mac": 42},                         "mac",    42,                  "mac_non_string_preserved"),
        # Serial number field
        ({"serial": "ABC12345678"},           "serial", "ABC12345678",       "serial_field_redacted"),
        ({"sn": "XYZ987"},                    "sn",     "XYZ987",            "sn_field_redacted"),
        ({"serial": ""},                      "serial", "",                  "serial_empty_preserved"),
        ({"serial": 99},                      "serial", 99,                  "serial_non_string_preserved"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("data", "field", "original_value", "desc"),
        JSON_EDGE_CASES,
        ids=[c[3] for c in JSON_EDGE_CASES],
    )
    def test_json_recursive_edge_cases(
        self, data: dict, field: str, original_value: object, desc: str
    ) -> None:
        """Test MAC and serial field handling in JSON recursive sanitization."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_json_recursive(data, hasher, collector)

        if isinstance(original_value, str) and original_value:
            assert result[field] != original_value, f"{desc}: should be redacted"
        else:
            assert result[field] == original_value, f"{desc}: should be preserved"

    def test_mac_field_without_hasher(self) -> None:
        """Test MAC field uses placeholder when no hasher provided."""
        result = _sanitize_json_recursive({"mac": "AA:BB:CC:DD:EE:FF"}, None, None)
        assert result["mac"] == "***MAC***"

    def test_serial_field_without_hasher(self) -> None:
        """Test serial field uses placeholder when no hasher provided."""
        result = _sanitize_json_recursive({"serial": "ABC123"}, None, None)
        assert result["serial"] == "***SERIAL***"

    def test_bare_primitive_passthrough(self) -> None:
        """Test non-dict/list/str values pass through unchanged."""
        assert _sanitize_json_recursive(42, None, None) == 42
        assert _sanitize_json_recursive(True, None, None) is True
        assert _sanitize_json_recursive(None, None, None) is None


class TestStringPatternSanitization:
    """Tests for _sanitize_string_patterns edge cases."""

    def test_empty_string_returns_empty(self) -> None:
        """Test empty string is returned unchanged."""
        assert _sanitize_string_patterns("") == ""

    def test_mac_without_hasher(self) -> None:
        """Test MAC replacement uses placeholder when no hasher."""
        result = _sanitize_string_patterns("Device MAC: AA:BB:CC:DD:EE:FF")
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert "***MAC***" in result

    def test_mac_without_collector(self) -> None:
        """Test MAC replacement works without a collector."""
        from har_capture.patterns import Hasher

        hasher = Hasher.create("test")
        result = _sanitize_string_patterns("Device MAC: AA:BB:CC:DD:EE:FF", hasher, None)
        assert "AA:BB:CC:DD:EE:FF" not in result

    def test_public_ip_without_hasher(self) -> None:
        """Test public IP replacement uses placeholder when no hasher."""
        result = _sanitize_string_patterns("DNS: 8.8.8.8")
        assert "8.8.8.8" not in result
        assert "***IP***" in result

    def test_public_ip_without_collector(self) -> None:
        """Test public IP replacement works without a collector."""
        from har_capture.patterns import Hasher

        hasher = Hasher.create("test")
        result = _sanitize_string_patterns("DNS: 8.8.8.8", hasher, None)
        assert "8.8.8.8" not in result

    def test_email_without_hasher(self) -> None:
        """Test email replacement uses placeholder when no hasher."""
        result = _sanitize_string_patterns("Contact: admin@example.com")
        assert "admin@example.com" not in result
        assert "***EMAIL***" in result

    def test_email_without_collector(self) -> None:
        """Test email replacement works without a collector."""
        from har_capture.patterns import Hasher

        hasher = Hasher.create("test")
        result = _sanitize_string_patterns("Contact: admin@example.com", hasher, None)
        assert "admin@example.com" not in result

    def test_credit_card_luhn_valid(self) -> None:
        """Test valid credit card number is redacted."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        # Visa test number that passes Luhn
        result = _sanitize_string_patterns("Card: 4111111111111111", hasher, collector)
        assert "4111111111111111" not in result

    def test_credit_card_luhn_invalid(self) -> None:
        """Test invalid credit card number (fails Luhn) is preserved."""
        # Visa-format but fails Luhn check
        result = _sanitize_string_patterns("Number: 4111111111111112", None, None)
        assert "4111111111111112" in result

    def test_string_patterns_with_collector_records_mac(self) -> None:
        """Test MAC in string patterns records redaction via collector."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns("Device MAC: AA:BB:CC:DD:EE:FF", hasher, collector)
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert collector.auto_redacted_counts.get("mac_address", 0) > 0

    def test_string_patterns_with_collector_records_public_ip(self) -> None:
        """Test public IP in string patterns records redaction via collector."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns("DNS: 8.8.8.8", hasher, collector)
        assert "8.8.8.8" not in result
        assert collector.auto_redacted_counts.get("public_ip", 0) > 0

    def test_string_patterns_version_string_not_treated_as_public_ip(self) -> None:
        """Test version-like string matching public IP regex is preserved."""
        result = _sanitize_string_patterns("Version: 5.7.1.5", None, None)
        assert "5.7.1.5" in result, "Version string should not be treated as a public IP"

    def test_string_patterns_with_collector_records_email(self) -> None:
        """Test email in string patterns records redaction via collector."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        result = _sanitize_string_patterns("Contact: admin@example.com", hasher, collector)
        assert "admin@example.com" not in result
        assert collector.auto_redacted_counts.get("email", 0) > 0


class TestPostDataSanitizationEdgeCases:
    """Tests for sanitize_post_data edge cases."""

    def test_form_urlencoded_text_sanitized(self) -> None:
        """Test form-urlencoded mimeType triggers text sanitization."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "password=secret123&action=login",
        }
        result = sanitize_post_data(post_data)
        assert "secret123" not in result["text"]
        assert "action=login" in result["text"]

    def test_json_text_sanitized(self) -> None:
        """Test application/json mimeType triggers JSON sanitization."""
        post_data = {
            "mimeType": "application/json",
            "text": '{"password": "secret", "user": "admin"}',
        }
        result = sanitize_post_data(post_data)
        parsed = json.loads(result["text"])
        assert parsed["password"] != "secret"

    def test_flaggable_param_in_params_array(self) -> None:
        """Test flaggable field in POST params array is flagged."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        post_data = {
            "params": [{"name": "username", "value": "johndoe"}],
        }
        result = sanitize_post_data(post_data, hasher, collector)
        assert result["params"][0]["value"] == "johndoe", "Flaggable value should be preserved"
        assert len(collector.flagged) > 0, "Should have flagged the username"


class TestUrlPathFlagging:
    """Tests for _sanitize_url_path flagging with collector."""

    # fmt: off
    PATH_FLAG_CASES = [
        ("http://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile", "uuid",          "uuid_flagged"),
        ("http://api.example.com/keys/sk-1234567890abcdefghij/verify",                "api_key",       "api_key_flagged"),
        ("http://api.example.com/devices/DEV-ABC123456/status",                       "device_serial", "device_serial_flagged"),
        ("http://api.example.com/tokens/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6/refresh",   "token",         "long_token_flagged"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("url", "expected_category", "desc"),
        PATH_FLAG_CASES,
        ids=[c[2] for c in PATH_FLAG_CASES],
    )
    def test_url_path_segments_flagged(self, url: str, expected_category: str, desc: str) -> None:
        """Test suspicious path segments are flagged via collector."""
        from har_capture.patterns import Hasher
        from har_capture.sanitization.collector import RedactionCollector

        hasher = Hasher.create("test")
        collector = RedactionCollector(hasher=hasher)
        entry = {
            "request": {"method": "GET", "url": url, "headers": [], "queryString": []},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        sanitize_entry(entry, salt="test", collector=collector)
        categories = {f.category for f in collector.flagged}
        assert expected_category in categories, f"{desc}: expected {expected_category} in {categories}"


class TestWebStorageNonDictOrigin:
    """Tests for web storage with non-dict origin entries."""

    def test_non_dict_origin_entry_skipped(self) -> None:
        """Test non-dict entries in web storage list are skipped."""
        har = {
            "log": {
                "entries": [],
                "_har_capture": {
                    "local_storage": [
                        "not_a_dict",
                        {"origin": "https://example.com", "items": [{"name": "k", "value": "secret"}]},
                    ],
                },
            }
        }
        result, _ = sanitize_har(har, salt="test")
        storage = result["log"]["_har_capture"]["local_storage"]
        assert storage[0] == "not_a_dict", "Non-dict entry should be passed through"
        assert storage[1]["items"][0]["value"] != "secret", "Valid entry should be sanitized"


class TestSanitizeHarFileEdgeCases:
    """Tests for sanitize_har_file edge cases."""

    def test_non_har_extension_output_path(self, tmp_path) -> None:
        """Test input file without .har extension gets .sanitized.har appended."""
        har_data = {"log": {"entries": []}}
        input_file = tmp_path / "capture.json"
        input_file.write_text(json.dumps(har_data))

        output_path, _ = sanitize_har_file(input_file)
        assert output_path.endswith(".sanitized.har")
        assert "capture.json.sanitized.har" in output_path


class TestApplyUserRedactions:
    """Tests for apply_user_redactions error paths."""

    def test_redaction_error_continues(self) -> None:
        """Test that a failing redaction item doesn't stop other redactions."""
        from unittest.mock import patch

        har_data = {"log": {"entries": [{"request": {"url": "http://test/"}, "response": {}}]}}
        report = SanitizationReport(
            input_file="",
            output_file="",
            salt="test",
            flagged=[
                FlaggedValue(
                    original_value="first_value",
                    category="test",
                    confidence="HIGH",
                    context="ctx",
                    reason="test",
                    status=RedactionStatus.USER_REDACTED,
                ),
                FlaggedValue(
                    original_value="http://test/",
                    category="url",
                    confidence="HIGH",
                    context="ctx",
                    reason="test url",
                    status=RedactionStatus.USER_REDACTED,
                ),
            ],
        )
        # Mock hasher to fail on first call, succeed on second
        with patch("har_capture.sanitization.har.Hasher") as mock_hasher_cls:
            mock_hash = mock_hasher_cls.create.return_value.hash_sensitive_value
            mock_hash.side_effect = [RuntimeError("hash failed"), "REDACTED_URL"]
            result = apply_user_redactions(har_data, report)
        assert isinstance(result, dict), "Should return valid result despite first item failing"
        # The second redaction should still have been attempted
        assert mock_hash.call_count == 2, "Both redaction items should have been attempted"

    def test_invalid_har_data_raises(self) -> None:
        """Test apply_user_redactions raises on invalid input."""
        report = SanitizationReport(input_file="", output_file="", salt="test")
        with pytest.raises(HarValidationError):
            apply_user_redactions("not_a_dict", report)  # type: ignore[arg-type]

    def test_missing_log_raises(self) -> None:
        """Test apply_user_redactions raises when 'log' key missing."""
        report = SanitizationReport(input_file="", output_file="", salt="test")
        with pytest.raises(HarValidationError, match="log"):
            apply_user_redactions({}, report)

    def test_redaction_item_exception_is_caught(self) -> None:
        """Test that an exception during a single redaction is caught and logged."""
        from unittest.mock import patch

        har_data = {"log": {"entries": []}}
        report = SanitizationReport(
            input_file="",
            output_file="",
            salt="test",
            flagged=[
                FlaggedValue(
                    original_value="test_value",
                    category="test",
                    confidence="HIGH",
                    context="ctx",
                    reason="test",
                    status=RedactionStatus.USER_REDACTED,
                ),
            ],
        )
        with patch("har_capture.sanitization.har.Hasher") as mock_hasher_cls:
            mock_hasher_cls.create.return_value.hash_generic.side_effect = RuntimeError("hash failed")
            result = apply_user_redactions(har_data, report)
        assert isinstance(result, dict), "Should return valid result despite error"

    def test_json_decode_error_after_replacement(self) -> None:
        """Test HarValidationError raised if json.loads fails after replacement."""
        from unittest.mock import patch

        har_data = {"log": {"entries": [{"note": "target_value"}]}}
        report = SanitizationReport(
            input_file="",
            output_file="",
            salt="test",
            flagged=[
                FlaggedValue(
                    original_value="target_value",
                    category="test",
                    confidence="HIGH",
                    context="ctx",
                    reason="test",
                    status=RedactionStatus.USER_REDACTED,
                ),
            ],
        )
        with (
            patch(
                "har_capture.sanitization.har.json.loads",
                side_effect=json.JSONDecodeError("broken", "", 0),
            ),
            pytest.raises(HarValidationError, match="Failed to parse HAR"),
        ):
            apply_user_redactions(har_data, report)


# =============================================================================
# XML POST Data Sanitization
# =============================================================================

XML_POST_DATA_CASES = [
    (c["post_data"], c["must_not_contain"], c["must_contain"], c["id"])
    for c in _HAR_FIXTURE["xml_post_data_cases"]
]


class TestXmlPostDataSanitization:
    """Tests for sanitize_post_data with XML MIME types."""

    @pytest.mark.parametrize(
        ("post_data", "must_not_contain", "must_contain", "desc"),
        XML_POST_DATA_CASES,
        ids=[c[3] for c in XML_POST_DATA_CASES],
    )
    def test_xml_post_body_sanitization(
        self,
        post_data: dict,
        must_not_contain: list[str],
        must_contain: list[str],
        desc: str,
    ) -> None:
        """XML POST bodies are sanitized: sensitive values removed, safe values preserved."""
        result = sanitize_post_data(post_data)
        text = result.get("text", "")
        for forbidden in must_not_contain:
            assert forbidden not in text, f"'{forbidden}' should be redacted in {desc}"
        for required in must_contain:
            assert required in text, f"'{required}' should be preserved in {desc}"


class TestApplicationXmlResponseRouting:
    """Tests that application/xml responses are routed through the HTML engine."""

    def test_application_xml_mac_redacted(self) -> None:
        """application/xml response content should have MACs redacted by the HTML engine."""
        entry = {
            "request": {"method": "GET", "url": "http://modem/xml/getter.xml", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "mimeType": "application/xml",
                    "text": "<device><mac>AA:BB:CC:DD:EE:FF</mac></device>",
                },
            },
        }
        result = sanitize_entry(entry, salt="test")
        content_text = result["response"]["content"]["text"]
        assert "AA:BB:CC:DD:EE:FF" not in content_text

    def test_application_xml_ip_redacted(self) -> None:
        """application/xml response content should have private IPs redacted."""
        entry = {
            "request": {"method": "GET", "url": "http://modem/status.xml", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "mimeType": "application/xml",
                    "text": "<config><gateway>192.168.1.100</gateway></config>",
                },
            },
        }
        result = sanitize_entry(entry, salt="test")
        content_text = result["response"]["content"]["text"]
        assert "192.168.1.100" not in content_text


# =============================================================================
# Pass 1b -- Redacted-Value Propagation
# =============================================================================

# Propagation eligibility: (value, eligible, id)
PROPAGATION_ELIGIBILITY_CASES = [
    (c["value"], c["eligible"], c["id"]) for c in _HAR_FIXTURE["propagation_eligibility_cases"]
]


class TestPropagationEligibility:
    """Tests for _is_propagation_eligible (SANITIZATION_SPEC Pass 1b)."""

    @pytest.mark.parametrize(
        ("value", "eligible", "desc"),
        PROPAGATION_ELIGIBILITY_CASES,
        ids=[c[2] for c in PROPAGATION_ELIGIBILITY_CASES],
    )
    def test_eligibility(self, value: str, eligible: bool, desc: str) -> None:
        """Only values that cannot coincidentally collide are globally replaceable."""
        from har_capture.sanitization.har import _is_propagation_eligible

        assert _is_propagation_eligible(value) is eligible, (
            f"{desc}: '{value}' should be {'eligible' if eligible else 'ineligible'}"
        )


def _token_flow_har(token: str, *, path_segment: str | None = None) -> dict:
    """Build a login -> use -> logout HAR where the token appears on three surfaces."""
    return {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://10.0.0.1/rest/v1/user/3/token",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"created": {"token": token, "userId": 3}}),
                        },
                    },
                },
                {
                    "request": {
                        "method": "DELETE",
                        "url": f"https://10.0.0.1/rest/v1/user/3/token/{path_segment or token}",
                        "headers": [{"name": "Authorization", "value": f"Bearer {token}"}],
                    },
                    "response": {
                        "status": 204,
                        "headers": [],
                        "content": {"mimeType": "application/json", "text": ""},
                    },
                },
            ],
        }
    }


class TestRedactedValuePropagation:
    """Tests that already-redacted values are replaced on unlabeled surfaces."""

    def test_token_in_url_path_is_redacted(self) -> None:
        """A token redacted in a body must not survive verbatim in a URL path."""
        token = "eba954f1f10817e8f36607c4db106999"
        sanitized, _ = sanitize_har(_token_flow_har(token), salt="test")

        assert token not in json.dumps(sanitized), "token survived somewhere in the HAR"

    def test_url_structure_is_preserved(self) -> None:
        """Redaction replaces the segment without changing the URL's shape."""
        token = "eba954f1f10817e8f36607c4db106999"
        original = _token_flow_har(token)
        before = original["log"]["entries"][1]["request"]["url"]
        sanitized, _ = sanitize_har(original, salt="test")
        after = sanitized["log"]["entries"][1]["request"]["url"]

        assert after.count("/") == before.count("/"), "path segment count changed"
        assert after.startswith("https://10.0.0.1/rest/v1/user/3/token/")

    def test_propagated_placeholder_matches_original(self) -> None:
        """The path gets the same placeholder the body was given."""
        token = "eba954f1f10817e8f36607c4db106999"
        sanitized, _ = sanitize_har(_token_flow_har(token), salt="test")

        body = json.loads(sanitized["log"]["entries"][0]["response"]["content"]["text"])
        placeholder = body["created"]["token"]
        url = sanitized["log"]["entries"][1]["request"]["url"]

        assert url.endswith(f"/{placeholder}"), f"path got a different placeholder than the body: {url}"

    def test_ineligible_value_is_left_alone(self) -> None:
        """A short redacted value must not be find-replaced across the file."""
        sanitized, _ = sanitize_har(_token_flow_har("1"), salt="test")

        url = sanitized["log"]["entries"][1]["request"]["url"]
        assert url == "https://10.0.0.1/rest/v1/user/3/token/1", "short value was propagated"
        assert "/rest/v1/user/3/" in url, "unrelated digits were rewritten"

    def test_unrelated_path_segments_survive(self) -> None:
        """Propagation must not touch segments that are not the secret."""
        token = "eba954f1f10817e8f36607c4db106999"
        sanitized, _ = sanitize_har(_token_flow_har(token), salt="test")

        for entry in sanitized["log"]["entries"]:
            assert "/rest/v1/user/3/token" in entry["request"]["url"]

    def test_propagation_count_recorded(self) -> None:
        """The sweep records what it replaced."""
        token = "eba954f1f10817e8f36607c4db106999"
        _, report = sanitize_har(_token_flow_har(token), salt="test")

        assert report.auto_redacted_counts.get("propagated", 0) >= 1

    def test_no_propagation_when_value_absent_elsewhere(self) -> None:
        """A capture with nothing to propagate is unchanged and records nothing."""
        token = "eba954f1f10817e8f36607c4db106999"
        har = _token_flow_har(token, path_segment="somethingelse")
        sanitized, report = sanitize_har(har, salt="test")

        assert sanitized["log"]["entries"][1]["request"]["url"].endswith("/somethingelse")
        assert report.auto_redacted_counts.get("propagated", 0) == 0

    def test_propagated_value_leaves_the_review_queue(self) -> None:
        """A value replaced everywhere is not a decision the user can affect."""
        token = "eba954f1f10817e8f36607c4db106999"
        _, report = sanitize_har(_token_flow_har(token), salt="test", heuristics=HeuristicMode.FLAG)

        assert token not in [f.original_value for f in report.flagged]

    def test_unpropagated_flag_stays_in_the_review_queue(self) -> None:
        """Dropping propagated values must not empty the queue of everything else."""
        token = "eba954f1f10817e8f36607c4db106999"
        uuid = "fb75f58f-2821-4c8e-a8e8-b44bd3f9e012"
        har = _token_flow_har(token)
        har["log"]["entries"][1]["request"]["url"] = (
            f"https://10.0.0.1/rest/v1/user/3/token/{token}/session/{uuid}"
        )
        sanitized, report = sanitize_har(har, salt="test", heuristics=HeuristicMode.FLAG)

        flagged = [f.original_value for f in report.flagged]
        assert token not in flagged, "propagated value should have left the queue"
        assert uuid in flagged, "unrelated flagged value was dropped with it"
        assert uuid in sanitized["log"]["entries"][1]["request"]["url"], (
            "a flagged-only value must not be auto-redacted"
        )


class TestPropagationFailureModes:
    """Pass 1b must degrade to a no-op, never corrupt a HAR (invariant 5)."""

    def test_unserializable_har_is_left_untouched(self) -> None:
        """A HAR that cannot be serialized skips propagation instead of raising."""
        from har_capture.sanitization.har import _propagate_redacted_values

        token = "eba954f1f10817e8f36607c4db106999"
        har = {"log": {"entries": [{"request": {"url": f"/x/{token}"}}]}, "bad": {object()}}

        assert _propagate_redacted_values(har, {token: "FIELD_abc12345"}) == 0
        assert har["log"]["entries"][0]["request"]["url"] == f"/x/{token}"

    def test_failed_round_trip_reverts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If the rewritten HAR does not parse, the original is kept."""
        from har_capture.sanitization.har import _propagate_redacted_values

        def _raise(*args: object, **kwargs: object) -> None:
            raise json.JSONDecodeError("boom", "", 0)

        monkeypatch.setattr("har_capture.sanitization.har.json.loads", _raise)

        token = "eba954f1f10817e8f36607c4db106999"
        har = {"log": {"entries": [{"request": {"url": f"/x/{token}"}}]}}

        assert _propagate_redacted_values(har, {token: "FIELD_abc12345"}) == 0
        assert har["log"]["entries"][0]["request"]["url"] == f"/x/{token}", "HAR was left half-rewritten"

    def test_empty_registry_is_a_no_op(self) -> None:
        """Nothing redacted means nothing to sweep."""
        from har_capture.sanitization.har import _propagate_redacted_values

        har = {"log": {"entries": []}}
        assert _propagate_redacted_values(har, {}) == 0


# Propagation search keys: (registry, expected_needles, id)
PROPAGATION_SEARCH_KEY_CASES = [
    (c["registry"], c["expected_needles"], c["id"]) for c in _HAR_FIXTURE["propagation_search_key_cases"]
]


class TestPropagationSearchKeys:
    """Needle expansion: encoding variants included, longest replaced first."""

    @pytest.mark.parametrize(
        ("registry", "expected_needles", "desc"),
        PROPAGATION_SEARCH_KEY_CASES,
        ids=[c[2] for c in PROPAGATION_SEARCH_KEY_CASES],
    )
    def test_search_keys(self, registry: dict, expected_needles: list, desc: str) -> None:
        """Needles cover each eligible value's encodings, ordered longest first."""
        from har_capture.sanitization.har import _propagation_search_keys

        assert [needle for needle, _ in _propagation_search_keys(registry)] == expected_needles, desc

    def test_encoded_needle_maps_to_the_same_placeholder(self) -> None:
        """Raw and percent-encoded forms must resolve to one placeholder."""
        from har_capture.sanitization.har import _propagation_search_keys

        keys = dict(_propagation_search_keys({"abc+def/ghi=jkl12345mnop": "FIELD_bbbbbbbb"}))

        assert set(keys.values()) == {"FIELD_bbbbbbbb"}


class TestPropagationOverlappingValues:
    """A value that is a prefix of another must not be substituted inside it."""

    OVERLAP_SHORT = "eba954f1f10817e8f36607c4db106999"
    OVERLAP_LONG = "eba954f1f10817e8f36607c4db106999SUFFIX01"

    @pytest.mark.parametrize(
        "registry_order",
        [("short_first"), ("long_first")],
        ids=["short_registered_first", "long_registered_first"],
    )
    def test_longest_match_wins_regardless_of_registry_order(self, registry_order: str) -> None:
        """Output must not depend on which value the sanitizer reached first."""
        from har_capture.sanitization.har import _propagate_redacted_values

        pairs = [(self.OVERLAP_SHORT, "FIELD_aaaaaaaa"), (self.OVERLAP_LONG, "FIELD_bbbbbbbb")]
        if registry_order == "long_first":
            pairs.reverse()

        har = {"log": {"entries": [{"request": {"url": f"/x/{self.OVERLAP_LONG}"}}]}}
        _propagate_redacted_values(har, dict(pairs))

        assert har["log"]["entries"][0]["request"]["url"] == "/x/FIELD_bbbbbbbb"

    def test_no_corrupted_hybrid_is_produced(self) -> None:
        """The suffix must never survive glued onto a placeholder."""
        from har_capture.sanitization.har import _propagate_redacted_values

        har = {"log": {"entries": [{"request": {"url": f"/x/{self.OVERLAP_LONG}"}}]}}
        _propagate_redacted_values(
            har, {self.OVERLAP_SHORT: "FIELD_aaaaaaaa", self.OVERLAP_LONG: "FIELD_bbbbbbbb"}
        )

        assert "SUFFIX01" not in json.dumps(har), "suffix leaked out of a mangled substitution"

    def test_both_overlapping_values_still_redacted_when_both_present(self) -> None:
        """Each value keeps its own placeholder when both appear separately."""
        from har_capture.sanitization.har import _propagate_redacted_values

        har = {
            "log": {
                "entries": [
                    {"request": {"url": f"/a/{self.OVERLAP_SHORT}"}},
                    {"request": {"url": f"/b/{self.OVERLAP_LONG}"}},
                ]
            }
        }
        _propagate_redacted_values(
            har, {self.OVERLAP_SHORT: "FIELD_aaaaaaaa", self.OVERLAP_LONG: "FIELD_bbbbbbbb"}
        )

        urls = [e["request"]["url"] for e in har["log"]["entries"]]
        assert urls == ["/a/FIELD_aaaaaaaa", "/b/FIELD_bbbbbbbb"]


class TestPropagationEncodedValues:
    """A secret that is percent-encoded on another surface must still be caught."""

    ENCODABLE = "abc+def/ghi=jkl12345mnop"

    def _flow(self, url_token: str) -> dict:
        return {
            "log": {
                "entries": [
                    {
                        "request": {"method": "POST", "url": "https://10.0.0.1/login", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"token": self.ENCODABLE}),
                            },
                        },
                    },
                    {
                        "request": {"method": "GET", "url": f"https://10.0.0.1/a/{url_token}", "headers": []},
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"mimeType": "application/json", "text": "{}"},
                        },
                    },
                ]
            }
        }

    def test_percent_encoded_path_segment_is_redacted(self) -> None:
        """The encoded copy of a redacted secret must not survive."""
        encoded = urllib.parse.quote(self.ENCODABLE, safe="")
        sanitized, _ = sanitize_har(self._flow(encoded), salt="test")

        assert encoded not in json.dumps(sanitized)
        assert self.ENCODABLE not in json.dumps(sanitized)

    def test_encoded_copy_gets_the_same_placeholder_as_the_body(self) -> None:
        """Encoding difference must not break correlation."""
        encoded = urllib.parse.quote(self.ENCODABLE, safe="")
        sanitized, _ = sanitize_har(self._flow(encoded), salt="test")

        placeholder = json.loads(sanitized["log"]["entries"][0]["response"]["content"]["text"])["token"]
        assert sanitized["log"]["entries"][1]["request"]["url"].endswith(f"/{placeholder}")

    def test_raw_and_encoded_copies_both_replaced(self) -> None:
        """A capture carrying both forms loses both."""
        from har_capture.sanitization.har import _propagate_redacted_values

        encoded = urllib.parse.quote(self.ENCODABLE, safe="")
        har = {"log": {"entries": [{"request": {"url": f"/a/{self.ENCODABLE}/b/{encoded}"}}]}}
        count = _propagate_redacted_values(har, {self.ENCODABLE: "FIELD_bbbbbbbb"})

        assert har["log"]["entries"][0]["request"]["url"] == "/a/FIELD_bbbbbbbb/b/FIELD_bbbbbbbb"
        assert count == 2
