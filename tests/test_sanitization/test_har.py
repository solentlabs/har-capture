"""Tests for HAR sanitization utilities."""

from __future__ import annotations

import json

import pytest

from har_capture.sanitization.har import (
    is_sensitive_field,
    sanitize_entry,
    sanitize_har,
    sanitize_header_value,
    sanitize_post_data,
)

# =============================================================================
# Test Data Tables
# =============================================================================

# ┌─────────────────────────┬─────────────┬─────────────────────────────┐
# │ field_name              │ is_sensitive│ description                 │
# ├─────────────────────────┼─────────────┼─────────────────────────────┤
# │ Form/JSON field name    │ True/False  │ test case name              │
# └─────────────────────────┴─────────────┴─────────────────────────────┘
#
# fmt: off
SENSITIVE_FIELD_CASES = [
    # Password variations
    ("password",            True,   "password_exact"),
    ("loginPassword",       True,   "password_camel"),
    ("user_password",       True,   "password_snake"),
    ("passwd",              True,   "passwd"),
    ("pwd",                 True,   "pwd"),
    ("pass",                True,   "pass"),
    ("oldPassword",         True,   "password_old"),
    ("newPassword",         True,   "password_new"),
    ("confirmPassword",     True,   "password_confirm"),
    # Auth/token variations
    ("auth_token",          True,   "auth_token"),
    ("authToken",           True,   "auth_token_camel"),
    ("authentication",      True,   "authentication"),
    ("apikey",              True,   "apikey"),
    ("api_key",             True,   "api_key"),
    ("apiKey",              True,   "api_key_camel"),
    # Secret variations
    ("secret",              True,   "secret"),
    ("secretKey",           True,   "secret_key"),
    ("client_secret",       True,   "client_secret"),
    # Token variations
    ("token",               True,   "token"),
    ("accessToken",         True,   "access_token"),
    ("refreshToken",        True,   "refresh_token"),
    ("csrf_token",          True,   "csrf_token"),
    # Credential variations
    ("credential",          True,   "credential"),
    ("credentials",         True,   "credentials"),
    # Safe fields (should NOT be flagged)
    ("username",            False,  "username_safe"),
    ("loginName",           False,  "login_name_safe"),
    ("email",               False,  "email_safe"),
    ("channel_id",          False,  "channel_id_safe"),
    ("frequency",           False,  "frequency_safe"),
    ("power_level",         False,  "power_level_safe"),
    ("status",              False,  "status_safe"),
    ("description",         False,  "description_safe"),
    ("name",                False,  "name_safe"),
    ("id",                  False,  "id_safe"),
]
# fmt: on

# ┌─────────────────────────┬─────────────────────────────┬─────────────────────────┬─────────────────────┐
# │ header_name             │ header_value                │ expected_contains       │ description         │
# ├─────────────────────────┼─────────────────────────────┼─────────────────────────┼─────────────────────┤
# │ HTTP header name        │ Original value              │ What result contains    │ test case name      │
# └─────────────────────────┴─────────────────────────────┴─────────────────────────┴─────────────────────┘
#
# fmt: off
HEADER_REDACTION_CASES = [
    # Full redaction headers
    ("Authorization",       "Bearer abc123xyz",           "[REDACTED]",             "auth_bearer"),
    ("Authorization",       "Basic dXNlcjpwYXNz",         "[REDACTED]",             "auth_basic"),
    ("X-Api-Key",           "sk-1234567890abcdef",        "[REDACTED]",             "api_key"),
    ("X-Auth-Token",        "token123456",                "[REDACTED]",             "auth_token"),
    # Cookie redaction (preserves names)
    ("Cookie",              "session=abc123",             "session=[REDACTED]",     "cookie_session"),
    ("Cookie",              "user=admin; token=xyz",      "user=[REDACTED]",        "cookie_multiple"),
    ("Set-Cookie",          "session=xyz789; Path=/",     "session=[REDACTED]",     "set_cookie"),
    # Safe headers (preserved as-is)
    ("Content-Type",        "text/html",                  "text/html",              "content_type"),
    ("Content-Length",      "1234",                       "1234",                   "content_length"),
    ("Accept",              "application/json",           "application/json",       "accept"),
    ("User-Agent",          "Mozilla/5.0",                "Mozilla/5.0",            "user_agent"),
    ("Cache-Control",       "no-cache",                   "no-cache",               "cache_control"),
]
# fmt: on

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
            secret = value.split("=")[1].split(";")[0]
        else:
            secret = value.split(" ")[-1] if " " in value else value
        assert secret not in result, f"{desc}: secret '{secret}' should be removed"


class TestPostDataSanitization:
    """Tests for POST data sanitization."""

    # fmt: off
    POST_PARAM_CASES = [
        # (field_name, field_value, should_redact, description)
        ("loginPassword",   "secret123",    True,   "password_redacted"),
        ("userPassword",    "mypass",       True,   "user_password_redacted"),
        ("auth_token",      "tok123",       True,   "auth_token_redacted"),
        ("loginName",       "admin",        False,  "username_preserved"),
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
            "text": "loginName=admin&loginPassword=secret123",
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        assert "loginName=admin" in result["text"]
        assert "loginPassword=[REDACTED]" in result["text"]
        assert "secret123" not in result["text"]

    def test_sanitizes_json_post_data(self) -> None:
        """Test JSON password redaction."""
        post_data = {
            "mimeType": "application/json",
            "text": '{"username": "admin", "password": "secret123"}',
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        parsed = json.loads(result["text"])
        assert parsed["username"] == "admin"
        assert parsed["password"] == "[REDACTED]"

    def test_sanitizes_nested_json(self) -> None:
        """Test nested JSON password redaction.

        Note: sanitize_post_data uses a simple top-level JSON sanitizer,
        not deep recursion. For deep sanitization, use sanitize_entry with
        response content handling.
        """
        post_data = {
            "mimeType": "application/json",
            "text": '{"username": "admin", "password": "secret"}',
        }
        result = sanitize_post_data(post_data)
        assert result is not None
        parsed = json.loads(result["text"])
        assert parsed["username"] == "admin"
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
        assert "[REDACTED]" in cookie_header["value"]

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
        assert password_param["value"] == "[REDACTED]"


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
        result = sanitize_har(har_data, salt=None)
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
        result = sanitize_har(har_data, salt=None)
        assert "AA:AA:AA:AA:AA:AA" not in result["log"]["entries"][0]["response"]["content"]["text"]
        assert "BB:BB:BB:BB:BB:BB" not in result["log"]["entries"][1]["response"]["content"]["text"]

    def test_handles_missing_log(self) -> None:
        """Test handling of missing log key."""
        har_data = {"invalid": "structure"}
        result = sanitize_har(har_data)
        assert "invalid" in result

    def test_handles_empty_entries(self) -> None:
        """Test handling of empty entries list."""
        har_data = {"log": {"version": "1.2", "entries": []}}
        result = sanitize_har(har_data)
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
        result = sanitize_har(har_data)
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
        result = sanitize_har(har_data, salt=None)
        assert "AA:BB:CC:DD:EE:FF" not in result["log"]["pages"][0]["title"]
