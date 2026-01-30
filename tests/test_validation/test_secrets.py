"""Table-driven tests for the validation/secrets module."""

from __future__ import annotations

import pytest

from har_capture.validation.secrets import (
    Finding,
    check_content,
    check_headers,
    check_json_fields,
    check_post_data,
    is_cookie_attributes_only,
    is_private_ip,
    is_redacted,
    truncate,
    validate_har,
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
    # Standard redaction patterns
    ("[REDACTED]",           True,  "standard redaction"),
    ("REDACTED",             True,  "plain REDACTED"),
    ("xxx REDACTED xxx",     True,  "contains REDACTED"),
    ("<REDACTED>",           True,  "angle bracket REDACTED"),
    ("***REDACTED***",       True,  "asterisk REDACTED"),
    # Case variations
    ("redacted",             True,  "lowercase redacted"),
    ("Redacted",             True,  "title case Redacted"),
    ("REDACTED_VALUE",       True,  "redacted with suffix"),
    # X placeholder patterns
    ("XXXX",                 True,  "X placeholder (4)"),
    ("XXXXXXXXXX",           True,  "long X placeholder (10)"),
    ("xxxx",                 True,  "lowercase x placeholder"),
    ("XX:XX:XX:XX:XX:XX",    True,  "redacted MAC"),
    # Note: lowercase redacted MAC not currently detected (uppercase only)
    ("xx:xx:xx:xx:xx:xx",    False, "lowercase redacted MAC (not detected)"),
    # Numeric placeholder patterns (only zeros are detected)
    ("000000",               True,  "all zeros (6)"),
    ("0000000000",           True,  "all zeros (10)"),
    # Note: only repeated zeros detected, not other digits
    ("111111",               False, "all ones (not detected as redacted)"),
    ("999999999",            False, "all nines (not detected as redacted)"),
    # Allowlisted values
    ("0.0.0.0",              True,  "zero IP (allowlisted)"),
    ("::",                   True,  "empty IPv6 (allowlisted)"),
    ("x@x.invalid",          True,  "redacted email (x@x pattern)"),
    # Note: .invalid TLD not detected unless very short pattern
    ("user@example.invalid", False, "invalid TLD not detected"),
    # Actual secrets (should NOT be redacted)
    ("real-secret-value",    False, "actual secret"),
    ("Bearer token123",      False, "auth token"),
    ("password123",          False, "password"),
    ("abc123xyz",            False, "mixed alphanumeric"),
    # Edge cases (boundary tests)
    ("00000",                False, "5 zeros (not enough)"),
    ("XXX",                  True,  "3 X's (minimum threshold)"),
    ("XX",                   False, "2 X's (not enough)"),
    ("111",                  False, "3 ones (not detected)"),
    # Mixed content (should NOT be redacted)
    ("user123",              False, "username-like"),
    ("test@example.com",     False, "valid email"),
    ("192.168.1.1",          False, "private IP (not redacted placeholder)"),
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
    # 10.x.x.x range (Class A private)
    ("10.0.0.0",        True,  "10.x network address"),
    ("10.0.0.1",        True,  "10.x.x.x range start"),
    ("10.100.50.25",    True,  "10.x.x.x middle"),
    ("10.255.255.255",  True,  "10.x broadcast"),
    # 172.16-31.x.x range (Class B private)
    ("172.16.0.1",      True,  "172.16.x start"),
    ("172.20.100.50",   True,  "172.x middle"),
    ("172.31.255.255",  True,  "172.31.x end"),
    # 192.168.x.x range (Class C private)
    ("192.168.0.1",     True,  "192.168.0.x gateway"),
    ("192.168.1.1",     True,  "192.168.1.x gateway"),
    ("192.168.100.1",   True,  "192.168.x.x modem"),
    ("192.168.255.255", True,  "192.168.x broadcast"),
    # Loopback range (127.x.x.x)
    ("127.0.0.0",       True,  "loopback network"),
    ("127.0.0.1",       True,  "localhost"),
    ("127.255.255.255", True,  "loopback end"),
    # Note: Link-local (169.254.x.x - APIPA) not currently detected
    # These are technically private but implementation doesn't handle them
    ("169.254.0.1",     False, "link-local (not detected)"),
    ("169.254.100.50",  False, "link-local (not detected)"),
    ("169.254.255.255", False, "link-local (not detected)"),
    # Special addresses
    ("0.0.0.0",         True,  "all zeros (redacted)"),
    # Public IPs (should NOT be private)
    ("8.8.8.8",         False, "Google DNS"),
    ("8.8.4.4",         False, "Google DNS secondary"),
    ("1.1.1.1",         False, "Cloudflare DNS"),
    ("208.67.222.222",  False, "OpenDNS"),
    ("9.9.9.9",         False, "Quad9"),
    # Boundary tests (just outside private ranges)
    ("9.255.255.255",   False, "just before 10.x"),
    ("11.0.0.1",        False, "just after 10.x"),
    ("172.15.255.255",  False, "just before 172.16"),
    ("172.32.0.1",      False, "just after 172.31"),
    ("192.167.255.255", False, "just before 192.168"),
    ("192.169.0.1",     False, "just after 192.168"),
    ("169.253.255.255", False, "just before link-local"),
    ("169.255.0.1",     False, "just after link-local"),
    # Documentation/test ranges (RFC 5737)
    ("192.0.2.1",       False, "TEST-NET-1"),
    ("198.51.100.1",    False, "TEST-NET-2"),
    ("203.0.113.1",     False, "TEST-NET-3"),
    # Invalid inputs
    ("invalid",         False, "not an IP"),
    ("256.0.0.1",       False, "invalid octet > 255"),
    ("-1.0.0.0",        False, "negative octet"),
    ("1.2.3",           False, "too few octets"),
    ("1.2.3.4.5",       False, "too many octets"),
    ("",                False, "empty string"),
    ("abc.def.ghi.jkl", False, "non-numeric octets"),
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


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ check_json_fields() test cases                                              │
# ├───────────────────────────────────────────────┬─────────┬───────────────────┤
# │ data                                          │ count   │ description       │
# ├───────────────────────────────────────────────┼─────────┼───────────────────┤
# │ {"password": "secret123"}                     │ 1       │ password field    │
# │ {"user": {"api_key": "abc123"}}               │ 1       │ nested api_key    │
# │ {"password": "[REDACTED]"}                    │ 0       │ redacted value    │
# │ {"password": ""}                              │ 0       │ empty value       │
# │ [{"token": "s1"}, {"token": "s2"}]            │ 2       │ list of objects   │
# │ {"items": [{"password": "secret"}]}           │ 1       │ nested in list    │
# └───────────────────────────────────────────────┴─────────┴───────────────────┘
#
# fmt: off
CHECK_JSON_FIELDS_CASES = [
    ({"username": "admin", "password": "secret123"},              1, "password field detected"),
    ({"user": {"credentials": {"api_key": "abc123xyz"}}},         1, "nested api_key field"),
    ({"password": "[REDACTED]"},                                  0, "redacted value ignored"),
    ({"password": ""},                                            0, "empty value ignored"),
    ([{"token": "secret1"}, {"token": "secret2"}],                2, "list of objects"),
    ({"items": [{"credentials": {"password": "secret"}}]},        1, "nested in list"),
    ({"safe_field": "not sensitive"},                             0, "non-sensitive field"),
]
# fmt: on


@pytest.mark.parametrize(("data", "expected_count", "desc"), CHECK_JSON_FIELDS_CASES)
def test_check_json_fields(data: dict | list, expected_count: int, desc: str) -> None:
    """Test check_json_fields() with various JSON structures."""
    findings: list[Finding] = []
    check_json_fields(data, "request.body", findings)
    assert len(findings) == expected_count, f"Failed for {desc}"


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ check_content() test cases                                                  │
# ├───────────────────────────────────────────────┬─────────┬───────────────────┤
# │ content                                       │ has_ip  │ has_mac │ desc    │
# ├───────────────────────────────────────────────┼─────────┼─────────┼─────────┤
# │ "Server at 203.0.113.45"                      │ True    │ False   │ pub IP  │
# │ "Local at 192.168.1.1"                        │ False   │ False   │ priv IP │
# │ "MAC: AA:BB:CC:11:22:33"                      │ False   │ True    │ MAC     │
# │ "MAC: 00:00:00:00:00:00"                      │ False   │ False   │ anon MAC│
# │ ""                                            │ False   │ False   │ empty   │
# │ "[REDACTED]"                                  │ False   │ False   │ redacted│
# └───────────────────────────────────────────────┴─────────┴─────────┴─────────┘
#
# fmt: off
CHECK_CONTENT_CASES = [
    ("Server is at 203.0.113.45 and ready",  True,  False, "public IP detected"),
    ("Local server at 192.168.1.1",          False, False, "private IP ignored"),
    ("Device MAC is AA:BB:CC:11:22:33",      False, True,  "MAC address detected"),
    ("MAC: 00:00:00:00:00:00",               False, False, "anonymized MAC ignored"),
    ("",                                     False, False, "empty content"),
    ("[REDACTED]",                           False, False, "redacted content"),
]
# fmt: on


@pytest.mark.parametrize(("content", "expect_ip", "expect_mac", "desc"), CHECK_CONTENT_CASES)
def test_check_content(content: str, expect_ip: bool, expect_mac: bool, desc: str) -> None:
    """Test check_content() with various content strings."""
    findings: list[Finding] = []
    check_content(content, "response.body", findings)

    has_ip = any("ip" in f.reason.lower() for f in findings)
    has_mac = any("mac" in f.reason.lower() for f in findings)

    assert has_ip == expect_ip, f"IP detection failed for {desc}"
    assert has_mac == expect_mac, f"MAC detection failed for {desc}"


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ validate_har() test cases                                                   │
# ├─────────────────────────────────────────────────┬───────────┬───────────────┤
# │ har_data                                        │ has_find  │ description   │
# ├─────────────────────────────────────────────────┼───────────┼───────────────┤
# │ HAR with Authorization header                   │ True      │ auth header   │
# │ HAR with clean Content-Type only                │ False     │ clean HAR     │
# │ HAR with password in POST data                  │ True      │ post password │
# │ HAR with Cookie header                          │ True      │ cookie header │
# └─────────────────────────────────────────────────┴───────────┴───────────────┘
#
# fmt: off
VALIDATE_HAR_CASES = [
    # (har_data, expect_findings, match_field, description)
    (
        {"log": {"entries": [{"request": {"url": "http://x.com", "headers": [{"name": "Authorization", "value": "Bearer secret"}]}, "response": {"headers": []}}]}},
        True, "Authorization", "auth header detected",
    ),
    (
        {"log": {"entries": [{"request": {"url": "http://x.com", "headers": [{"name": "Content-Type", "value": "text/html"}]}, "response": {"headers": [], "content": {"text": "Hello", "mimeType": "text/html"}}}]}},
        False, None, "clean HAR",
    ),
    (
        {"log": {"entries": [{"request": {"url": "http://x.com/login", "headers": [], "postData": {"mimeType": "application/x-www-form-urlencoded", "params": [{"name": "password", "value": "mysecret"}]}}, "response": {"headers": []}}]}},
        True, "password", "POST password detected",
    ),
    (
        {"log": {"entries": [{"request": {"url": "http://x.com", "headers": [{"name": "Cookie", "value": "session=abc123"}]}, "response": {"headers": []}}]}},
        True, "Cookie", "cookie header detected",
    ),
]
# fmt: on


@pytest.mark.parametrize(("har_data", "expect_findings", "match_field", "desc"), VALIDATE_HAR_CASES)
def test_validate_har(
    har_data: dict, expect_findings: bool, match_field: str | None, desc: str, tmp_path
) -> None:
    """Test validate_har() with various HAR structures."""
    import json

    har_file = tmp_path / "test.har"
    har_file.write_text(json.dumps(har_data))

    findings = validate_har(har_file)

    if expect_findings:
        assert len(findings) > 0, f"Expected findings for {desc}"
        if match_field:
            assert any(match_field in f.field for f in findings), f"Expected {match_field} in {desc}"
    else:
        assert len(findings) == 0, f"Expected no findings for {desc}"


def test_validate_har_gzipped(tmp_path) -> None:
    """Test validation of gzipped HAR file."""
    import gzip
    import json

    har_data = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "http://example.com",
                        "headers": [{"name": "Cookie", "value": "session=abc123"}],
                    },
                    "response": {"headers": []},
                }
            ]
        }
    }
    har_file = tmp_path / "test.har.gz"
    with gzip.open(har_file, "wt", encoding="utf-8") as f:
        json.dump(har_data, f)

    findings = validate_har(har_file)
    assert len(findings) > 0
