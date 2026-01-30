"""Table-driven tests for the validation/secrets module."""

from __future__ import annotations

import pytest

from har_capture.validation.secrets import (
    Finding,
    check_headers,
    check_post_data,
    is_cookie_attributes_only,
    is_private_ip,
    is_redacted,
    truncate,
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ is_redacted() test cases                                                    │
# ├─────────────────────────────────────┬───────────┬───────────────────────────┤
# │ value                               │ expected  │ description               │
# ├─────────────────────────────────────┼───────────┼───────────────────────────┤
# │ "[REDACTED]"                        │ True      │ standard redaction        │
# │ "REDACTED"                          │ True      │ plain REDACTED            │
# │ "xxx REDACTED xxx"                  │ True      │ contains REDACTED         │
# │ "XXXX"                              │ True      │ X placeholder             │
# │ "XXXXXXXXXX"                        │ True      │ long X placeholder        │
# │ "000000"                            │ True      │ all zeros (6+)            │
# │ "0000000000"                        │ True      │ all zeros (10)            │
# │ "XX:XX:XX:XX:XX:XX"                 │ True      │ redacted MAC              │
# │ "0.0.0.0"                           │ True      │ zero IP (allowlisted)     │
# │ "::"                                │ True      │ empty IPv6 (allowlisted)  │
# │ "x@x.invalid"                       │ True      │ redacted email            │
# │ "real-secret-value"                 │ False     │ actual secret             │
# │ "Bearer token123"                   │ False     │ auth token                │
# │ "password123"                       │ False     │ password                  │
# │ "00000"                             │ False     │ 5 zeros (not enough)      │
# │ "XX"                                │ False     │ 2 X's (not enough)        │
# └─────────────────────────────────────┴───────────┴───────────────────────────┘
#
# fmt: off
REDACTED_CASES = [
    ("[REDACTED]",           True,  "standard redaction"),
    ("REDACTED",             True,  "plain REDACTED"),
    ("xxx REDACTED xxx",     True,  "contains REDACTED"),
    ("XXXX",                 True,  "X placeholder (4+)"),
    ("XXXXXXXXXX",           True,  "long X placeholder"),
    ("000000",               True,  "all zeros (6)"),
    ("0000000000",           True,  "all zeros (10)"),
    ("XX:XX:XX:XX:XX:XX",    True,  "redacted MAC"),
    ("0.0.0.0",              True,  "zero IP (allowlisted)"),
    ("::",                   True,  "empty IPv6 (allowlisted)"),
    ("x@x.invalid",          True,  "redacted email"),
    ("real-secret-value",    False, "actual secret"),
    ("Bearer token123",      False, "auth token"),
    ("password123",          False, "password"),
    ("00000",                False, "5 zeros (not enough)"),
]
# fmt: on


@pytest.mark.parametrize(("value", "expected", "desc"), REDACTED_CASES)
def test_is_redacted(value: str, expected: bool, desc: str) -> None:
    """Test is_redacted() with various values."""
    result = is_redacted(value)
    assert result == expected, f"Failed for {desc}: {value}"


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ is_cookie_attributes_only() test cases                                      │
# ├─────────────────────────────────────┬───────────┬───────────────────────────┤
# │ value                               │ expected  │ description               │
# ├─────────────────────────────────────┼───────────┼───────────────────────────┤
# │ "Secure"                            │ True      │ just Secure               │
# │ "HttpOnly"                          │ True      │ just HttpOnly             │
# │ "Secure; HttpOnly"                  │ True      │ both attributes           │
# │ "HttpOnly; Secure"                  │ True      │ both reversed             │
# │ ""                                  │ True      │ empty string              │
# │ "  "                                │ True      │ whitespace only           │
# │ "session=abc123"                    │ False     │ actual session value      │
# │ "Secure; session=abc"               │ False     │ attributes + value        │
# │ "token=xyz; HttpOnly"               │ False     │ value + attributes        │
# └─────────────────────────────────────┴───────────┴───────────────────────────┘
#
# fmt: off
COOKIE_ATTR_CASES = [
    ("Secure",               True,  "just Secure"),
    ("HttpOnly",             True,  "just HttpOnly"),
    ("Secure; HttpOnly",     True,  "both attributes"),
    ("HttpOnly; Secure",     True,  "both reversed"),
    ("",                     True,  "empty string"),
    ("  ",                   True,  "whitespace only"),
    ("session=abc123",       False, "actual session value"),
    ("Secure; session=abc",  False, "attributes + value"),
    ("token=xyz; HttpOnly",  False, "value + attributes"),
]
# fmt: on


@pytest.mark.parametrize(("value", "expected", "desc"), COOKIE_ATTR_CASES)
def test_is_cookie_attributes_only(value: str, expected: bool, desc: str) -> None:
    """Test is_cookie_attributes_only() with various values."""
    result = is_cookie_attributes_only(value)
    assert result == expected, f"Failed for {desc}: {value}"


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ is_private_ip() test cases                                                  │
# ├─────────────────────────────────────┬───────────┬───────────────────────────┤
# │ ip                                  │ expected  │ description               │
# ├─────────────────────────────────────┼───────────┼───────────────────────────┤
# │ "10.0.0.1"                          │ True      │ 10.x.x.x range            │
# │ "10.255.255.255"                    │ True      │ 10.x end                  │
# │ "172.16.0.1"                        │ True      │ 172.16.x start            │
# │ "172.31.255.255"                    │ True      │ 172.31.x end              │
# │ "192.168.0.1"                       │ True      │ 192.168.x.x               │
# │ "192.168.100.1"                     │ True      │ 192.168.x.x               │
# │ "127.0.0.1"                         │ True      │ localhost                 │
# │ "0.0.0.0"                           │ True      │ all zeros (redacted)      │
# │ "8.8.8.8"                           │ False     │ Google DNS (public)       │
# │ "1.1.1.1"                           │ False     │ Cloudflare (public)       │
# │ "172.15.0.1"                        │ False     │ just outside 172.16-31    │
# │ "172.32.0.1"                        │ False     │ just outside 172.16-31    │
# │ "192.167.0.1"                       │ False     │ not 192.168               │
# │ "invalid"                           │ False     │ not an IP                 │
# │ "256.0.0.1"                         │ False     │ invalid octet             │
# │ "1.2.3"                             │ False     │ too few octets            │
# └─────────────────────────────────────┴───────────┴───────────────────────────┘
#
# fmt: off
PRIVATE_IP_CASES = [
    ("10.0.0.1",        True,  "10.x.x.x range"),
    ("10.255.255.255",  True,  "10.x end"),
    ("172.16.0.1",      True,  "172.16.x start"),
    ("172.31.255.255",  True,  "172.31.x end"),
    ("192.168.0.1",     True,  "192.168.x.x"),
    ("192.168.100.1",   True,  "192.168.x.x"),
    ("127.0.0.1",       True,  "localhost"),
    ("0.0.0.0",         True,  "all zeros (redacted)"),
    ("8.8.8.8",         False, "Google DNS (public)"),
    ("1.1.1.1",         False, "Cloudflare (public)"),
    ("172.15.0.1",      False, "just outside 172.16-31"),
    ("172.32.0.1",      False, "just outside 172.16-31"),
    ("192.167.0.1",     False, "not 192.168"),
    ("invalid",         False, "not an IP"),
    ("256.0.0.1",       False, "invalid octet"),
    ("1.2.3",           False, "too few octets"),
]
# fmt: on


@pytest.mark.parametrize(("ip", "expected", "desc"), PRIVATE_IP_CASES)
def test_is_private_ip(ip: str, expected: bool, desc: str) -> None:
    """Test is_private_ip() with various IPs."""
    result = is_private_ip(ip)
    assert result == expected, f"Failed for {desc}: {ip}"


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ truncate() test cases                                                       │
# ├─────────────────────────────────────┬───────────┬───────────────────────────┤
# │ value                               │ max_len   │ expected_suffix           │
# ├─────────────────────────────────────┼───────────┼───────────────────────────┤
# │ "short"                             │ 40        │ "short" (unchanged)       │
# │ "x" * 40                            │ 40        │ exact (unchanged)         │
# │ "x" * 50                            │ 40        │ ends with "..."           │
# │ "abcdefghij"                        │ 5         │ "ab..."                   │
# └─────────────────────────────────────┴───────────┴───────────────────────────┘
#
# fmt: off
TRUNCATE_CASES = [
    ("short",      40, "short",      "under limit unchanged"),
    ("x" * 40,     40, "x" * 40,     "exact limit unchanged"),
    ("x" * 50,     40, "x" * 37 + "...", "over limit truncated"),
    ("abcdefghij", 5,  "ab...",      "custom limit"),
]
# fmt: on


@pytest.mark.parametrize(("value", "max_len", "expected", "desc"), TRUNCATE_CASES)
def test_truncate(value: str, max_len: int, expected: str, desc: str) -> None:
    """Test truncate() with various values."""
    result = truncate(value, max_len)
    assert result == expected, f"Failed for {desc}"


class TestCheckHeaders:
    """Tests for check_headers() function."""

    def test_detects_authorization_header(self) -> None:
        """Test detection of Authorization header with real value."""
        headers = [{"name": "Authorization", "value": "Bearer secret-token"}]
        findings: list[Finding] = []
        check_headers(headers, "request", findings)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "authorization" in findings[0].reason.lower()

    def test_ignores_redacted_authorization(self) -> None:
        """Test redacted Authorization header is not flagged."""
        headers = [{"name": "Authorization", "value": "[REDACTED]"}]
        findings: list[Finding] = []
        check_headers(headers, "request", findings)
        assert len(findings) == 0

    def test_detects_cookie_header(self) -> None:
        """Test detection of Cookie header with session data."""
        headers = [{"name": "Cookie", "value": "session=abc123xyz"}]
        findings: list[Finding] = []
        check_headers(headers, "request", findings)
        assert len(findings) == 1
        assert "Cookie" in findings[0].field or "cookie" in findings[0].reason.lower()

    def test_ignores_cookie_attributes_only(self) -> None:
        """Test Cookie with only attributes is not flagged."""
        headers = [{"name": "Cookie", "value": "Secure; HttpOnly"}]
        findings: list[Finding] = []
        check_headers(headers, "request", findings)
        assert len(findings) == 0

    def test_ignores_empty_header_value(self) -> None:
        """Test empty header value is not flagged."""
        headers = [{"name": "Authorization", "value": ""}]
        findings: list[Finding] = []
        check_headers(headers, "request", findings)
        assert len(findings) == 0

    def test_detects_set_cookie_header(self) -> None:
        """Test detection of Set-Cookie header."""
        headers = [{"name": "Set-Cookie", "value": "session=xyz; Path=/"}]
        findings: list[Finding] = []
        check_headers(headers, "response", findings)
        assert len(findings) == 1

    def test_multiple_sensitive_headers(self) -> None:
        """Test detection of multiple sensitive headers."""
        headers = [
            {"name": "Authorization", "value": "Bearer token"},
            {"name": "Cookie", "value": "session=abc"},
        ]
        findings: list[Finding] = []
        check_headers(headers, "request", findings)
        assert len(findings) == 2


class TestCheckPostData:
    """Tests for check_post_data() function."""

    def test_detects_password_in_params(self) -> None:
        """Test detection of password field in form params."""
        post_data = {
            "params": [{"name": "password", "value": "mysecret123"}],
            "mimeType": "application/x-www-form-urlencoded",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "password" in findings[0].field.lower()

    def test_ignores_redacted_password(self) -> None:
        """Test redacted password is not flagged."""
        post_data = {
            "params": [{"name": "password", "value": "[REDACTED]"}],
            "mimeType": "application/x-www-form-urlencoded",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert len(findings) == 0

    def test_handles_empty_post_data(self) -> None:
        """Test empty post data doesn't cause errors."""
        findings: list[Finding] = []
        check_post_data(None, "request", findings)
        assert len(findings) == 0
        check_post_data({}, "request", findings)
        assert len(findings) == 0

    def test_detects_token_field(self) -> None:
        """Test detection of token field."""
        post_data = {
            "params": [{"name": "access_token", "value": "abc123xyz"}],
            "mimeType": "application/x-www-form-urlencoded",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert len(findings) == 1

    def test_detects_credential_field(self) -> None:
        """Test detection of credential field."""
        post_data = {
            "params": [{"name": "user_credential", "value": "secret"}],
            "mimeType": "application/x-www-form-urlencoded",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert len(findings) == 1


class TestFindingDataclass:
    """Tests for Finding dataclass."""

    def test_finding_creation(self) -> None:
        """Test Finding can be created with all fields."""
        finding = Finding(
            severity="error",
            location="request.headers",
            field="Authorization",
            value="Bearer xxx...",
            reason="Sensitive header",
        )
        assert finding.severity == "error"
        assert finding.location == "request.headers"
        assert finding.field == "Authorization"
        assert finding.value == "Bearer xxx..."
        assert finding.reason == "Sensitive header"

    def test_finding_warning_severity(self) -> None:
        """Test Finding with warning severity."""
        finding = Finding(
            severity="warning",
            location="response.content",
            field="email",
            value="user@example.com",
            reason="Potential email address",
        )
        assert finding.severity == "warning"
