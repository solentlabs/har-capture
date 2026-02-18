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
    ("Password",            True,   "password_capitalized"),
    ("PASSWORD",            True,   "password_uppercase"),
    ("loginPassword",       True,   "password_camel"),
    ("user_password",       True,   "password_snake"),
    ("passwd",              True,   "passwd"),
    ("pwd",                 True,   "pwd"),
    ("pass",                True,   "pass"),
    ("oldPassword",         True,   "password_old"),
    ("newPassword",         True,   "password_new"),
    ("confirmPassword",     True,   "password_confirm"),
    ("currentPassword",     True,   "password_current"),
    ("userPass",            False,  "password_userpass_camelcase_miss"),
    ("passphrase",          True,   "passphrase"),
    # Auth/token variations
    ("auth_token",          True,   "auth_token"),
    ("authToken",           True,   "auth_token_camel"),
    ("authentication",      True,   "authentication"),
    ("apikey",              True,   "apikey"),
    ("api_key",             True,   "api_key"),
    ("apiKey",              True,   "api_key_camel"),
    ("api-key",             True,   "api_key_hyphen"),
    # Secret variations
    ("secret",              True,   "secret"),
    ("secretKey",           True,   "secret_key"),
    ("client_secret",       True,   "client_secret"),
    ("clientSecret",        True,   "client_secret_camel"),
    ("app_secret",          True,   "app_secret"),
    # Token variations
    ("token",               True,   "token"),
    ("accessToken",         True,   "access_token"),
    ("access_token",        True,   "access_token_snake"),
    ("refreshToken",        True,   "refresh_token"),
    ("refresh_token",       True,   "refresh_token_snake"),
    ("csrf_token",          True,   "csrf_token"),
    ("csrfToken",           True,   "csrf_token_camel"),
    ("bearerToken",         True,   "bearer_token"),
    ("idToken",             True,   "id_token"),
    ("id_token",            True,   "id_token_snake"),
    # OAuth variations
    ("oauth_token",         True,   "oauth_token"),
    ("oauthToken",          True,   "oauth_token_camel"),
    ("oauth_secret",        True,   "oauth_secret"),
    # Identity fields (now detected as sensitive)
    ("client_id",           True,   "client_id_detected"),
    ("clientId",            False,  "client_id_camel_not_detected"),
    # Session variations (only *token detected, not bare "session" or generic "key")
    ("session",             False,  "session_not_detected"),
    ("sessionId",           False,  "session_id_not_detected"),
    ("session_id",          False,  "session_id_snake_not_detected"),
    ("sessionToken",        True,   "session_token"),
    ("session_key",         False,  "session_key_not_detected"),
    # Credential variations
    ("credential",          True,   "credential"),
    ("credentials",         True,   "credentials"),
    ("private_key",         True,   "private_key"),
    ("privateKey",          True,   "private_key_camel"),
    # Note: nonce not currently detected (could be added)
    ("nonce",               False,  "nonce_not_detected"),
    ("form_nonce",          False,  "form_nonce_not_detected"),
    # User identity fields (now detected as sensitive)
    ("username",            True,   "username_detected"),
    ("loginName",           True,   "login_name_detected"),
    ("user",                True,   "user_detected"),
    ("login",               True,   "login_detected"),
    # Safe fields (should NOT be flagged)
    ("email",               False,  "email_safe"),
    ("channel_id",          False,  "channel_id_safe"),
    ("frequency",           False,  "frequency_safe"),
    ("power_level",         False,  "power_level_safe"),
    ("status",              False,  "status_safe"),
    ("description",         False,  "description_safe"),
    ("name",                False,  "name_safe"),
    ("id",                  False,  "id_safe"),
    ("data",                False,  "data_safe"),
    ("type",                False,  "type_safe"),
    ("value",               False,  "value_safe"),
    ("content",             False,  "content_safe"),
    ("title",               False,  "title_safe"),
    ("message",             False,  "message_safe"),
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
    # Full redaction headers - Authorization
    ("Authorization",       "Bearer abc123xyz",           "[REDACTED]",             "auth_bearer"),
    ("Authorization",       "Basic dXNlcjpwYXNz",         "[REDACTED]",             "auth_basic"),
    ("Authorization",       "Digest username=admin",      "[REDACTED]",             "auth_digest"),
    ("Authorization",       "OAuth oauth_token=xyz",      "[REDACTED]",             "auth_oauth"),
    ("authorization",       "Bearer token123",            "[REDACTED]",             "auth_lowercase"),
    # API key headers
    ("X-Api-Key",           "sk-1234567890abcdef",        "[REDACTED]",             "api_key"),
    ("X-API-KEY",           "key-abcdef123456",           "[REDACTED]",             "api_key_upper"),
    # Note: Api-Key without X- prefix not currently detected
    ("Api-Key",             "apikey123",                  "apikey123",              "api_key_no_x_not_detected"),
    # Auth token headers
    ("X-Auth-Token",        "token123456",                "[REDACTED]",             "auth_token"),
    # Note: X-Access-Token, X-Session-Token not currently detected
    ("X-Access-Token",      "access123",                  "access123",              "access_token_not_detected"),
    ("X-Session-Token",     "session456",                 "session456",             "session_token_not_detected"),
    # Note: Proxy-Authorization not currently detected
    ("Proxy-Authorization", "Basic cHJveHk6cGFzcw==",     "Basic cHJveHk6cGFzcw==", "proxy_auth_not_detected"),
    # Note: Webhook signatures not currently detected
    ("X-Hub-Signature",     "sha1=abc123def456",          "sha1=abc123def456",      "hub_signature_not_detected"),
    ("X-Signature",         "hmac-sha256=xyz789",         "hmac-sha256=xyz789",     "signature_not_detected"),
    # Cookie redaction (preserves names)
    ("Cookie",              "session=abc123",             "session=[REDACTED]",     "cookie_session"),
    ("Cookie",              "user=admin; token=xyz",      "user=[REDACTED]",        "cookie_multiple"),
    ("Cookie",              "auth=secret; path=/",        "auth=[REDACTED]",        "cookie_auth"),
    ("Set-Cookie",          "session=xyz789; Path=/",     "session=[REDACTED]",     "set_cookie"),
    ("Set-Cookie",          "token=abc; HttpOnly",        "token=[REDACTED]",       "set_cookie_httponly"),
    # Safe headers (preserved as-is)
    ("Content-Type",        "text/html",                  "text/html",              "content_type"),
    ("Content-Type",        "application/json",           "application/json",       "content_type_json"),
    ("Content-Length",      "1234",                       "1234",                   "content_length"),
    ("Accept",              "application/json",           "application/json",       "accept"),
    ("Accept-Language",     "en-US,en;q=0.9",             "en-US,en;q=0.9",         "accept_language"),
    ("Accept-Encoding",     "gzip, deflate, br",          "gzip, deflate, br",      "accept_encoding"),
    ("User-Agent",          "Mozilla/5.0",                "Mozilla/5.0",            "user_agent"),
    ("Cache-Control",       "no-cache",                   "no-cache",               "cache_control"),
    ("Host",                "example.com",                "example.com",            "host"),
    ("Origin",              "https://example.com",        "https://example.com",    "origin"),
    ("Referer",             "https://example.com/page",   "https://example.com/page","referer"),
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
            secret = value.rsplit(" ", maxsplit=1)[-1] if " " in value else value
        assert secret not in result, f"{desc}: secret '{secret}' should be removed"


class TestPostDataSanitization:
    """Tests for POST data sanitization."""

    # fmt: off
    POST_PARAM_CASES = [
        # (field_name, field_value, should_redact, description)
        ("loginPassword",   "secret123",    True,   "password_redacted"),
        ("userPassword",    "mypass",       True,   "user_password_redacted"),
        ("auth_token",      "tok123",       True,   "auth_token_redacted"),
        ("loginName",       "admin",        True,   "login_name_redacted"),
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
    """Tests for URL path segment sanitization."""

    # fmt: off
    URL_PATH_CASES = [
        ("http://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile", "550e8400-e29b-41d4-a716-446655440000", "uuid_in_path"),
        ("http://api.example.com/keys/sk-1234567890abcdefghij/verify", "sk-1234567890abcdefghij", "api_key_prefix_in_path"),
        ("http://api.example.com/tokens/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6/refresh", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "long_mixed_token_in_path"),
        ("http://example.com/api/v1/status", None, "normal_path_preserved"),
        ("http://example.com/api/GetDeviceInformation/details", None, "long_alpha_path_preserved"),
        ("http://example.com/api/configurationSettings/list", None, "camelcase_path_preserved"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("url", "sensitive_segment", "desc"),
        URL_PATH_CASES,
        ids=[c[2] for c in URL_PATH_CASES],
    )
    def test_url_path_segment_sanitization(self, url: str, sensitive_segment: str | None, desc: str) -> None:
        """Test sensitive path segments are redacted."""
        entry = {
            "request": {"method": "GET", "url": url, "headers": [], "queryString": []},
            "response": {"status": 200, "headers": [], "content": {}},
        }
        result = sanitize_entry(entry, salt=None)
        result_url = result["request"]["url"]
        if sensitive_segment:
            assert sensitive_segment not in result_url, f"{desc}: segment should be redacted"
        else:
            assert result_url == url, f"{desc}: URL should be unchanged"


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
                "content": {"text": "MTkyLjE2OC4xLjEwMA==", "mimeType": "application/octet-stream", "encoding": "base64"},
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
    def test_ip_validation_in_string_patterns(self, input_text: str, should_contain: str | None, desc: str) -> None:
        """Test IP validation rejects invalid octets in string patterns."""
        from har_capture.sanitization.har import _sanitize_string_patterns

        result = _sanitize_string_patterns(input_text)
        if should_contain:
            assert should_contain in result, f"{desc}: invalid IP should be preserved"
        else:
            assert "192.168.1.100" not in result, f"{desc}: valid IP should be redacted"


class TestSensitiveFieldPatterns:
    """Tests for tightened sensitive field patterns (over-matching fixes)."""

    # fmt: off
    OVER_MATCHING_CASES = [
        ("keyboard",      False,  "keyboard_not_matched"),
        ("bypass",         False,  "bypass_not_matched"),
        ("author",         False,  "author_not_matched"),
        ("user_agent",    False,  "user_agent_not_matched"),
        ("powerUser",     False,  "power_user_not_matched"),
        ("max_users",     False,  "max_users_not_matched"),
        ("organic",        False,  "organic_not_matched"),
        ("reorganize",     False,  "reorganize_not_matched"),
        ("domain_name",   False,  "domain_name_not_matched"),
        ("password",       True,   "password_still_matched"),
        ("username",       True,   "username_now_matched"),
        ("user",           True,   "user_matched"),
        ("user_name",     True,   "user_name_matched"),
        ("login",          True,   "login_matched"),
        ("loginName",      True,   "login_name_matched"),
        ("domain",         True,   "domain_matched"),
        ("organization",   True,   "organization_matched"),
        ("org",            True,   "org_matched"),
        ("api_key",        True,   "api_key_still_matched"),
        ("auth_token",     True,   "auth_token_still_matched"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("field_name", "expected", "desc"),
        OVER_MATCHING_CASES,
        ids=[c[2] for c in OVER_MATCHING_CASES],
    )
    def test_sensitive_field_pattern_accuracy(self, field_name: str, expected: bool, desc: str) -> None:
        """Test tightened patterns prevent over-matching."""
        assert is_sensitive_field(field_name) == expected, f"{desc}"


class TestSSNAndCreditCardPatterns:
    """Tests for SSN and credit card pattern detection."""

    @pytest.mark.parametrize(
        ("input_text", "should_redact", "desc"),
        [
            ("SSN: 123-45-6789", True, "ssn_detected"),
            ("Date: 2024-01-15", False, "date_not_matched"),
            ("Card: 4111111111111111", True, "visa_detected"),
            ("Card: 5500000000000004", True, "mastercard_detected"),
            ("Card: 371449635398431", True, "amex_detected"),
            ("Number: 1234567890123456", False, "random_digits_no_luhn"),
        ],
    )
    def test_financial_pii_detection(self, input_text: str, should_redact: bool, desc: str) -> None:
        """Test SSN and credit card patterns with Luhn validation."""
        from har_capture.sanitization.har import _sanitize_string_patterns

        result = _sanitize_string_patterns(input_text)
        if should_redact:
            # Extract the value that should be redacted
            original_numbers = [w for w in input_text.split() if any(c.isdigit() for c in w)]
            for num in original_numbers:
                if len(num) > 8:  # Only check long numbers (SSN, CC)
                    assert num not in result, f"{desc}: {num} should be redacted"
        else:
            assert result == input_text, f"{desc}: text should be unchanged"
