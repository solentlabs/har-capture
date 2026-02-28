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
    is_flaggable_field,
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
    # Identity fields (flagged, not auto-redacted)
    ("client_id",           False,  "client_id_flagged_not_redacted"),
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
    # User identity fields (flagged for review, not auto-redacted)
    ("username",            False,  "username_flagged_not_redacted"),
    ("loginName",           False,  "login_name_flagged_not_redacted"),
    ("user",                False,  "user_flagged_not_redacted"),
    ("login",               False,  "login_flagged_not_redacted"),
    ("env",                 False,  "env_flagged_not_redacted"),
    ("environment",         False,  "environment_flagged_not_redacted"),
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
        ("username",       False,  "username_flagged_not_sensitive"),
        ("user",           False,  "user_flagged_not_sensitive"),
        ("user_name",     False,  "user_name_flagged_not_sensitive"),
        ("login",          False,  "login_flagged_not_sensitive"),
        ("loginName",      False,  "login_name_flagged_not_sensitive"),
        ("domain",         False,  "domain_flagged_not_sensitive"),
        ("organization",   False,  "organization_flagged_not_sensitive"),
        ("org",            False,  "org_flagged_not_sensitive"),
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

    # fmt: off
    FLAGGABLE_FIELD_CASES = [
        # Fields that should be flaggable (review tier)
        ("username",        True,   "username_flaggable"),
        ("user_name",       True,   "user_name_flaggable"),
        ("user",            True,   "user_flaggable"),
        ("login",           True,   "login_flaggable"),
        ("loginName",       True,   "login_name_flaggable"),
        ("domain",          True,   "domain_flaggable"),
        ("tenant",          True,   "tenant_flaggable"),
        ("client_id",       True,   "client_id_flaggable"),
        ("account_id",      True,   "account_id_flaggable"),
        ("org",             True,   "org_flaggable"),
        ("organization",    True,   "organization_flaggable"),
        ("env",             True,   "env_flaggable"),
        ("environment",     True,   "environment_flaggable"),
        # Fields that are auto-redact (NOT flaggable)
        ("password",        False,  "password_not_flaggable"),
        ("secret",          False,  "secret_not_flaggable"),
        ("token",           False,  "token_not_flaggable"),
        ("api_key",         False,  "api_key_not_flaggable"),
        ("auth_token",      False,  "auth_token_not_flaggable"),
        # Safe fields (neither sensitive nor flaggable)
        ("email",           False,  "email_not_flaggable"),
        ("channel_id",      False,  "channel_id_not_flaggable"),
        ("status",          False,  "status_not_flaggable"),
        ("name",            False,  "name_not_flaggable"),
        # Over-matching prevention
        ("domain_name",     False,  "domain_name_not_flaggable"),
        ("user_agent",      False,  "user_agent_not_flaggable"),
        ("organic",         False,  "organic_not_flaggable"),
        ("reorganize",      False,  "reorganize_not_flaggable"),
        ("envelope",        False,  "envelope_not_flaggable"),
        ("environmental",   False,  "environmental_not_flaggable"),
    ]
    # fmt: on

    @pytest.mark.parametrize(
        ("field_name", "expected", "desc"),
        FLAGGABLE_FIELD_CASES,
        ids=[c[2] for c in FLAGGABLE_FIELD_CASES],
    )
    def test_flaggable_field_detection(self, field_name: str, expected: bool, desc: str) -> None:
        """Test detection of flaggable vs non-flaggable field names."""
        result = is_flaggable_field(field_name)
        assert result is expected, f"{desc}: '{field_name}' should be {'flaggable' if expected else 'not flaggable'}"


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
        assert any(f.category == "device_serial" for f in collector.flagged), "Device serial should be flagged"

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
        assert password_param["value"] in ("[REDACTED]", "***FIELD***"), "Sensitive queryString param should be redacted"
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
        sanitize_entry(entry, salt=None)  # Should not raise  # noqa: B018

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
