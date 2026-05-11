"""Table-driven tests for the validation/secrets module.

Test data loaded from tests/fixtures/test_secrets.json.
"""

from __future__ import annotations

import json
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Load fixture data
# ---------------------------------------------------------------------------
_FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "test_secrets.json"
_DATA = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def _expand_x_placeholder(s: str) -> str:
    """Expand sentinel placeholders like ``_X40_`` to ``'x' * 40``."""
    import re

    def _repl(m: re.Match) -> str:
        return "x" * int(m.group(1))

    return re.sub(r"_X(\d+)_", _repl, s)


# ---------------------------------------------------------------------------
# Build parametrize tuples from fixture
# ---------------------------------------------------------------------------
REDACTED_CASES = [(c["value"], c["expected"], c["id"]) for c in _DATA["redacted_cases"]]

COOKIE_ATTR_CASES = [(c["value"], c["expected"], c["id"]) for c in _DATA["cookie_attr_cases"]]

PRIVATE_IP_CASES = [(c["ip"], c["expected"], c["id"]) for c in _DATA["private_ip_cases"]]

TRUNCATE_CASES = [
    (
        _expand_x_placeholder(c["value"]),
        c["max_len"],
        _expand_x_placeholder(c["expected"]),
        c["id"],
    )
    for c in _DATA["truncate_cases"]
]

CHECK_JSON_FIELDS_CASES = [
    (c["data"], c["expected_count"], c["id"]) for c in _DATA["check_json_fields_cases"]
]

CHECK_CONTENT_CASES = [
    (c["content"], c["expect_ip"], c["expect_mac"], c["id"]) for c in _DATA["check_content_cases"]
]

CHECK_URL_CASES = [(c["url"], c["expected_count"], c["id"]) for c in _DATA["check_url_cases"]]

COOKIE_ATTR_EXTENDED_CASES = [
    (c["value"], c["expected"], c["id"]) for c in _DATA["cookie_attr_extended_cases"]
]

VALIDATE_HAR_URL_CRED_CASES = [
    (c["url"], c["expect_finding"], c["id"]) for c in _DATA["validate_har_url_cred_cases"]
]

CHECK_POST_DATA_XML_CASES = [
    (c["post_data"], c["expected_finding_count"], c["id"]) for c in _DATA["check_post_data_xml_cases"]
]

VALIDATE_HAR_CASES = [
    (c["har_data"], c["expect_findings"], c["match_field"], c["id"]) for c in _DATA["validate_har_cases"]
]


# ---------------------------------------------------------------------------
# is_redacted()
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("value", "expected", "desc"), REDACTED_CASES)
def test_is_redacted(value: str, expected: bool, desc: str) -> None:
    """Test is_redacted() with various values."""
    result = is_redacted(value)
    assert result == expected, f"Failed for {desc}: {value}"


# ---------------------------------------------------------------------------
# is_cookie_attributes_only()
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("value", "expected", "desc"), COOKIE_ATTR_CASES)
def test_is_cookie_attributes_only(value: str, expected: bool, desc: str) -> None:
    """Test is_cookie_attributes_only() with various values."""
    result = is_cookie_attributes_only(value)
    assert result == expected, f"Failed for {desc}: {value}"


# ---------------------------------------------------------------------------
# is_private_ip()
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("ip", "expected", "desc"), PRIVATE_IP_CASES)
def test_is_private_ip(ip: str, expected: bool, desc: str) -> None:
    """Test is_private_ip() with various IPs."""
    result = is_private_ip(ip)
    assert result == expected, f"Failed for {desc}: {ip}"


# ---------------------------------------------------------------------------
# truncate()
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# check_json_fields()
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("data", "expected_count", "desc"), CHECK_JSON_FIELDS_CASES)
def test_check_json_fields(data: dict | list, expected_count: int, desc: str) -> None:
    """Test check_json_fields() with various JSON structures."""
    findings: list[Finding] = []
    check_json_fields(data, "request.body", findings)
    assert len(findings) == expected_count, f"Failed for {desc}"


# ---------------------------------------------------------------------------
# check_content()
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("content", "expect_ip", "expect_mac", "desc"), CHECK_CONTENT_CASES)
def test_check_content(content: str, expect_ip: bool, expect_mac: bool, desc: str) -> None:
    """Test check_content() with various content strings."""
    findings: list[Finding] = []
    check_content(content, "response.body", findings)

    has_ip = any("ip" in f.reason.lower() for f in findings)
    has_mac = any("mac" in f.reason.lower() for f in findings)

    assert has_ip == expect_ip, f"IP detection failed for {desc}"
    assert has_mac == expect_mac, f"MAC detection failed for {desc}"


# ---------------------------------------------------------------------------
# validate_har()
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("har_data", "expect_findings", "match_field", "desc"), VALIDATE_HAR_CASES)
def test_validate_har(
    har_data: dict, expect_findings: bool, match_field: str | None, desc: str, tmp_path
) -> None:
    """Test validate_har() with various HAR structures."""
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
    import copy
    import gzip
    from pathlib import Path

    fixtures = json.loads((Path(__file__).parent.parent / "fixtures" / "test_secrets.json").read_text())
    har_data = copy.deepcopy(fixtures["validate_har_gzipped"])
    har_file = tmp_path / "test.har.gz"
    with gzip.open(har_file, "wt", encoding="utf-8") as f:
        json.dump(har_data, f)

    findings = validate_har(har_file)
    assert len(findings) > 0


# ---------------------------------------------------------------------------
# check_url()
# ---------------------------------------------------------------------------
class TestCheckURL:
    """Tests for check_url() base64 credential detection."""

    @pytest.mark.parametrize(
        ("url", "expected_count", "desc"),
        CHECK_URL_CASES,
        ids=[c[2] for c in CHECK_URL_CASES],
    )
    def test_check_url(self, url: str, expected_count: int, desc: str) -> None:
        """Test check_url detects base64-encoded credentials in query strings."""
        from har_capture.validation.secrets import check_url

        findings: list[Finding] = []
        check_url(url, "Entry 0", findings)
        assert len(findings) == expected_count, f"{desc}: expected {expected_count} findings"
        if expected_count > 0:
            assert "Base64-encoded credential" in findings[0].reason


# ---------------------------------------------------------------------------
# is_cookie_attributes_only() extended
# ---------------------------------------------------------------------------
class TestCookieAttributesOnlyExtended:
    """Tests for is_cookie_attributes_only with metadata patterns."""

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        COOKIE_ATTR_EXTENDED_CASES,
        ids=[c[2] for c in COOKIE_ATTR_EXTENDED_CASES],
    )
    def test_cookie_attributes_only(self, value: str, expected: bool, desc: str) -> None:
        """Test is_cookie_attributes_only with extended patterns."""
        result = is_cookie_attributes_only(value)
        assert result == expected, f"{desc}: expected {expected}"


# ---------------------------------------------------------------------------
# validate_har URL credential detection
# ---------------------------------------------------------------------------
class TestValidateHarURLCredentials:
    """Test validate_har catches base64 credentials in URLs."""

    @pytest.mark.parametrize(
        ("url", "expect_finding", "desc"),
        VALIDATE_HAR_URL_CRED_CASES,
        ids=[c[2] for c in VALIDATE_HAR_URL_CRED_CASES],
    )
    def test_validate_har_url_credentials(self, url: str, expect_finding: bool, desc: str, tmp_path) -> None:
        """validate_har flags base64(user:pass) in URL query string."""
        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {"url": url, "headers": []},
                        "response": {"headers": [], "content": {"text": "", "mimeType": "text/html"}},
                    }
                ]
            }
        }
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(har_data))

        findings = validate_har(har_file)
        has_base64 = any("Base64-encoded credential" in f.reason for f in findings)
        assert has_base64 == expect_finding, f"{desc}: expected finding={expect_finding}"


class TestCheckURLKeyValueCredential:
    """Tests for check_url detecting base64 creds in key=value params."""

    def test_base64_credential_in_param_value(self) -> None:
        """Test check_url detects base64(user:pass) in a param value."""
        from har_capture.validation.secrets import check_url

        findings: list[Finding] = []
        check_url(
            "https://example.com/api?token=YWRtaW46cGFzc3dvcmQ=",
            "Entry 0",
            findings,
        )
        assert len(findings) == 1
        assert "query param 'token'" in findings[0].field
        assert "Base64-encoded credential" in findings[0].reason


class TestCheckContentSerialInTable:
    """Tests for check_content detecting serial numbers in HTML table cells."""

    def test_serial_in_html_table_cell(self) -> None:
        """Test check_content flags serial numbers in adjacent td cells."""
        html = "<td><strong>Serial Number</strong></td><td>ARRIS99887766ZZ</td>"
        findings: list[Finding] = []
        check_content(html, "Entry 0 (content)", findings)
        serial_findings = [f for f in findings if "serial" in f.reason.lower()]
        assert len(serial_findings) >= 1, "Should flag serial number in table cell"


class TestValidateHarBase64Content:
    """Tests for validate_har with base64-encoded response content."""

    def test_base64_encoded_content_decoded_and_checked(self, tmp_path) -> None:
        """Test that base64-encoded response content is decoded then validated."""
        import base64

        # Encode content containing a real MAC address
        raw_content = "Device MAC: DE:AD:BE:EF:CA:FE"
        b64_content = base64.b64encode(raw_content.encode()).decode()

        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://example.com/page",
                            "headers": [],
                        },
                        "response": {
                            "headers": [],
                            "content": {
                                "text": b64_content,
                                "encoding": "base64",
                                "mimeType": "text/html",
                            },
                        },
                    }
                ]
            }
        }
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(har_data))

        findings = validate_har(har_file)
        mac_findings = [f for f in findings if "MAC" in f.reason]
        assert len(mac_findings) >= 1, "Should detect MAC in base64-decoded content"


class TestCompileSensitiveFields:
    """Tests for _compile_sensitive_fields function."""

    def test_compile_sensitive_fields_returns_compiled_patterns(self) -> None:
        """Verify _compile_sensitive_fields returns compiled regex objects."""
        import re

        from har_capture.validation.secrets import _compile_sensitive_fields

        patterns = _compile_sensitive_fields()
        assert len(patterns) > 0
        assert all(isinstance(p, re.Pattern) for p in patterns)


class TestCheckPostDataXml:
    """Tests for XML POST body validation in check_post_data."""

    @pytest.mark.parametrize(
        ("post_data", "expected_count", "desc"),
        CHECK_POST_DATA_XML_CASES,
        ids=[c[2] for c in CHECK_POST_DATA_XML_CASES],
    )
    def test_xml_post_body_validation(
        self,
        post_data: dict,
        expected_count: int,
        desc: str,
    ) -> None:
        """XML POST bodies are validated: sensitive elements detected, safe elements ignored."""
        findings: list[Finding] = []
        check_post_data(post_data, "Entry 0", findings)
        assert len(findings) == expected_count, (
            f"{desc}: expected {expected_count} findings, got {len(findings)}: {[f.field for f in findings]}"
        )
