"""Table-driven tests for the validation/secrets module.

Test data loaded from tests/fixtures/test_secrets.json.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from har_capture.patterns.loader import resolve_patterns_arg
from har_capture.validation.secrets import (
    Finding,
    check_content,
    check_headers,
    check_json_fields,
    check_post_data,
    is_cookie_attributes_only,
    is_netmask,
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

NETMASK_CASES = [(c["ip"], c["expected"], c["id"]) for c in _DATA["netmask_cases"]]

SERIAL_LABEL_FP_CASES = [
    (c["content"], c["expect_serial_warning"], c["id"]) for c in _DATA["serial_label_fp_cases"]
]

VENDOR_SERIAL_CASES = [(c["content"], c["expected_errors"], c["id"]) for c in _DATA["vendor_serial_cases"]]

FORM_FIELD_SEVERITY_CASES = [
    (c["name"], c["value"], c["expected_severity"], c["id"]) for c in _DATA["form_field_severity_cases"]
]

# Vendor-serial detectors are domain knowledge — resolve the built-in
# network-device domain the way the CLI's --patterns option does.
_NETWORK_DEVICE_PATTERNS = str(resolve_patterns_arg("network-device"))

# YWRtaW46cGFzcw==  = base64("admin:pass")
# aGVsbG8gd29ybGQ= = base64("hello world") — no colon, not a credential
CHECK_CONTENT_BASE64_CASES = [
    # (content, expect_finding, description)
    ("YWRtaW46cGFzcw==", True, "bare_cred"),
    ("  YWRtaW46cGFzcw==  ", True, "bare_cred_with_whitespace"),
    ("aGVsbG8gd29ybGQ=", False, "base64_no_colon"),
    ("[REDACTED]", False, "already_redacted"),
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

    def test_detects_pws_in_params_and_text(self) -> None:
        """The issue #92 capture shape: a leaked pws value errors in both copies."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "pws", "value": "ZXhhbXBsZS1ub3QtcmVhbA=="},
                {"name": "todo", "value": "login"},
            ],
            "text": "pws=ZXhhbXBsZS1ub3QtcmVhbA%3D%3D&todo=login",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        pws_findings = [f for f in findings if f.field == "pws"]
        assert len(pws_findings) == 2, "one finding per copy (params and body)"
        assert all(f.severity == "error" for f in pws_findings)
        locations = {f.location for f in pws_findings}
        assert locations == {"request", "request (body)"}

    def test_form_text_checked_without_params(self) -> None:
        """A form body with no params array still gets field-name validation.

        The bare segment (no '=') exercises the skip branch of the splitter.
        """
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "passwd=example-not-real&todo=login&baresegment",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert len(findings) == 1
        assert findings[0].field == "passwd"
        assert findings[0].location == "request (body)"

    def test_base64_value_in_login_shaped_post_warns(self) -> None:
        """A base64 value in an unrecognized field of a login-shaped POST warns.

        The backstop for vendor credential field names the patterns don't
        know yet.
        """
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "login_user", "value": "admin"},
                {"name": "vendorpw", "value": "ZXhhbXBsZS1ub3QtcmVhbA=="},
            ],
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        warnings = [f for f in findings if f.severity == "warning"]
        assert len(warnings) == 1
        assert warnings[0].field == "vendorpw"
        assert "Base64-decodable" in warnings[0].reason

    def test_base64_value_without_login_context_not_flagged(self) -> None:
        """The same base64 value in a non-login-shaped POST stays silent."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": "payload", "value": "ZXhhbXBsZS1ub3QtcmVhbA=="}],
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert findings == []

    def test_redacted_placeholder_in_login_shaped_post_not_flagged(self) -> None:
        """FIELD_* placeholders are recognized as redacted, not re-flagged."""
        post_data = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "login_user", "value": "admin"},
                {"name": "pws", "value": "FIELD_9f856745"},
            ],
            "text": "login_user=admin&pws=FIELD_9f856745",
        }
        findings: list[Finding] = []
        check_post_data(post_data, "request", findings)
        assert all(f.field != "pws" for f in findings)


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


@pytest.mark.parametrize(
    ("ip", "expected", "desc"),
    NETMASK_CASES,
    ids=[c[2] for c in NETMASK_CASES],
)
def test_is_netmask(ip: str, expected: bool, desc: str) -> None:
    """Test is_netmask() classifies contiguous-bit masks vs host addresses."""
    assert is_netmask(ip) == expected, f"Failed for {desc}"


@pytest.mark.parametrize(
    ("content", "expect_serial_warning", "desc"),
    SERIAL_LABEL_FP_CASES,
    ids=[c[2] for c in SERIAL_LABEL_FP_CASES],
)
def test_check_content_serial_label_false_positives(
    content: str, expect_serial_warning: bool, desc: str
) -> None:
    """Labeled serial detection ignores jquery serialize methods and digitless values.

    Regression for CM2500 round-1 validate noise: jquery's ``serialize:``/
    ``serializeArray:`` methods were reported as potential serial numbers.
    """
    findings: list[Finding] = []
    check_content(content, "response.body", findings)
    serial_findings = [f for f in findings if f.reason == "Potential serial number"]
    assert bool(serial_findings) == expect_serial_warning, f"Failed for {desc}: {findings}"


@pytest.mark.parametrize(
    ("content", "expected_errors", "desc"),
    VENDOR_SERIAL_CASES,
    ids=[c[2] for c in VENDOR_SERIAL_CASES],
)
def test_check_content_vendor_serials(content: str, expected_errors: int, desc: str) -> None:
    """Delimiter-aware vendor-serial detection with network-device detectors.

    Regression for the CM2500 round-1 leak: a Netgear serial inside a
    pipe-delimited tagValueList blob has no label for SERIAL_PATTERNS to
    anchor on, and validate blessed the leak. A vendor-format token match
    is an error — the same detectors the sanitizer auto-redacts with.
    """
    findings: list[Finding] = []
    check_content(content, "response.body", findings, _NETWORK_DEVICE_PATTERNS)
    vendor = [f for f in findings if f.reason.startswith("Vendor-format serial")]
    assert len(vendor) == expected_errors, f"Failed for {desc}: {findings}"
    assert all(f.severity == "error" for f in vendor), f"{desc}: vendor serials must be errors"


def test_check_content_vendor_serials_need_domain_patterns() -> None:
    """Without domain patterns there are no vendor detectors — no findings."""
    findings: list[Finding] = []
    check_content("var tagValueList = '1.01|7ZZ0000FAKE00|1';", "response.body", findings)
    assert not [f for f in findings if f.reason.startswith("Vendor-format serial")]


@pytest.mark.parametrize(
    ("name", "value", "expected_severity", "desc"),
    FORM_FIELD_SEVERITY_CASES,
    ids=[c[3] for c in FORM_FIELD_SEVERITY_CASES],
)
def test_form_field_severity_model(name: str, value: str, expected_severity: str | None, desc: str) -> None:
    """Field-name findings are tiered by pattern tier.

    Credential names error, identity names warn, and factory-default
    usernames are suppressed (CM2500: loginName=admin exited 1 on every
    healthy capture, training contributors to ignore the gate).
    """
    post_data = {
        "mimeType": "application/x-www-form-urlencoded",
        "params": [{"name": name, "value": value}],
    }
    findings: list[Finding] = []
    check_post_data(post_data, "request", findings)
    field_findings = [f for f in findings if f.field == name]
    if expected_severity is None:
        assert not field_findings, f"{desc}: expected no finding, got {field_findings}"
    else:
        assert len(field_findings) == 1, f"{desc}: expected one finding, got {findings}"
        assert field_findings[0].severity == expected_severity, f"{desc}"


def test_field_tiers_legacy_format_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """A legacy patterns file (single `patterns` list) keeps error treatment."""
    from har_capture.validation import secrets as secrets_mod

    monkeypatch.setattr(
        secrets_mod,
        "load_sensitive_patterns",
        lambda _cp=None: {"fields": {"patterns": ["password"]}},
    )
    tiers = secrets_mod._compile_field_tiers()
    assert len(tiers.auto_redact) == 1
    assert not tiers.flag


def test_xml_field_severity_model() -> None:
    """XML element/attribute findings follow the same tier model as form fields."""
    xml = (
        "<login><username>operator7</username><password>hunter2secret</password>"
        "<loginName>admin</loginName><extra loginName='admin'/></login>"
    )
    post_data = {"mimeType": "text/xml", "text": xml}
    findings: list[Finding] = []
    check_post_data(post_data, "request", findings)
    by_field = {f.field: f.severity for f in findings}
    assert by_field.get("password") == "error"
    assert by_field.get("username") == "warning"
    assert "loginName" not in by_field, "default username in XML element and attribute must be suppressed"


def test_json_field_severity_model() -> None:
    """JSON field findings follow the same tier model."""
    findings: list[Finding] = []
    check_json_fields({"username": "operator7", "password": "hunter2secret"}, "body", findings)
    by_field = {f.field: f.severity for f in findings}
    assert by_field.get("password") == "error"
    assert by_field.get("username") == "warning"


@pytest.mark.parametrize(
    ("content", "expect_finding", "desc"),
    CHECK_CONTENT_BASE64_CASES,
    ids=[c[2] for c in CHECK_CONTENT_BASE64_CASES],
)
def test_check_content_base64_credential(content: str, expect_finding: bool, desc: str) -> None:
    """Test check_content detects bare base64 credentials and ignores non-credentials."""
    findings: list[Finding] = []
    check_content(content, "response.body", findings)

    b64_findings = [f for f in findings if "base64" in f.reason.lower()]
    if expect_finding:
        assert len(b64_findings) == 1, f"{desc}: expected one base64 finding"
        assert b64_findings[0].severity == "error", f"{desc}: finding should be error severity"
        assert b64_findings[0].field == "content", f"{desc}: field should be 'content'"
    else:
        assert len(b64_findings) == 0, f"{desc}: expected no base64 findings"


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

    def test_serial_in_table_cell_with_whitespace_between_tags(self) -> None:
        """Test check_content flags serials in td cells with newlines between tags."""
        html = "<td>\n<strong>Serial Number</strong>\n</td>\n<td>\n<b>ARRIS99887766ZZ</b></td>"
        findings: list[Finding] = []
        check_content(html, "Entry 0 (content)", findings)
        serial_findings = [f for f in findings if "serial" in f.reason.lower()]
        assert len(serial_findings) >= 1, "Should flag serial in whitespace-separated table cells"

    def test_serial_in_sibling_spans(self) -> None:
        """Test check_content flags serials split across sibling span elements.

        Technicolor .jst markup — label and value in sibling spans with
        whitespace between the tags (cable_modem_monitor issue #101).
        """
        html = (
            '<span class="readonlyLabel">Serial Number:</span>\n<span class="value">\n1234567890123456</span>'
        )
        findings: list[Finding] = []
        check_content(html, "Entry 0 (content)", findings)
        serial_findings = [f for f in findings if "serial" in f.reason.lower()]
        assert len(serial_findings) >= 1, "Should flag serial number in sibling spans"


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


# =============================================================================
# has_sanitized_url_credential flag on check_content and validate_har
# =============================================================================

# A server token that decodes to "session:abc123" — has a colon so is_base64_credential()
# fires, but it is NOT the user's credential.
_SERVER_TOKEN = base64.b64encode(b"session:abc123").decode()
_ADMIN_PASS = base64.b64encode(b"admin:pass").decode()

# fmt: off
CHECK_CONTENT_SERVER_TOKEN_CASES = [
    # (content, has_sanitized_url_credential, expect_base64_finding, desc)
    (_SERVER_TOKEN, False, True,  "server_token_flagged_without_context"),
    (_SERVER_TOKEN, True,  False, "server_token_suppressed_with_context"),
    (_ADMIN_PASS,   True,  False, "echoed_cred_suppressed_with_context"),  # sanitizer already handled it
    (_ADMIN_PASS,   False, True,  "echoed_cred_flagged_without_context"),
]
# fmt: on


class TestCheckContentServerTokenFlag:
    """Tests for has_sanitized_url_credential flag on check_content."""

    @pytest.mark.parametrize(
        ("content", "has_sanitized_url_credential", "expect_finding", "desc"),
        CHECK_CONTENT_SERVER_TOKEN_CASES,
        ids=[c[3] for c in CHECK_CONTENT_SERVER_TOKEN_CASES],
    )
    def test_check_content_server_token_flag(
        self, content: str, has_sanitized_url_credential: bool, expect_finding: bool, desc: str
    ) -> None:
        findings: list[Finding] = []
        check_content(content, "Entry 0", findings, has_sanitized_url_credential=has_sanitized_url_credential)
        b64_findings = [f for f in findings if "base64" in f.reason.lower()]
        if expect_finding:
            assert len(b64_findings) == 1, f"{desc}: expected one base64 finding"
        else:
            assert len(b64_findings) == 0, f"{desc}: expected no base64 findings"


class TestValidateHarSanitizedCredentials:
    """validate_har uses _sanitized_credentials annotation to suppress server-token false positives."""

    def test_server_token_not_flagged_when_annotated(self, tmp_path) -> None:
        """Response body that looks like a credential is not flagged when the entry had URL creds."""
        har = {
            "log": {
                "_har_capture": {
                    "_sanitized_credentials": [{"entry_index": 0, "location": "url_query_param"}]
                },
                "entries": [
                    {
                        "request": {
                            "url": "https://d.local/login?AUTH_abc12345",
                            "headers": [],
                        },
                        "response": {
                            "headers": [],
                            "content": {"text": _SERVER_TOKEN, "mimeType": "text/plain"},
                        },
                    }
                ],
            }
        }
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(har))
        findings = validate_har(har_file)
        b64_findings = [f for f in findings if "base64" in f.reason.lower()]
        assert len(b64_findings) == 0, "Server token in annotated entry should not be flagged"

    def test_server_token_flagged_when_not_annotated(self, tmp_path) -> None:
        """Response body that looks like a credential IS flagged when entry has no URL cred annotation."""
        har = {
            "log": {
                "_har_capture": {"_sanitized_credentials": []},
                "entries": [
                    {
                        "request": {"url": "https://d.local/status", "headers": []},
                        "response": {
                            "headers": [],
                            "content": {"text": _SERVER_TOKEN, "mimeType": "text/plain"},
                        },
                    }
                ],
            }
        }
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(har))
        findings = validate_har(har_file)
        b64_findings = [f for f in findings if "base64" in f.reason.lower()]
        assert len(b64_findings) == 1, "Server-token-shaped body should be flagged without annotation"

    def test_other_checks_still_run_for_annotated_entry(self, tmp_path) -> None:
        """MAC/IP checks still run for annotated entries; only base64 body check is suppressed."""
        har = {
            "log": {
                "_har_capture": {
                    "_sanitized_credentials": [{"entry_index": 0, "location": "url_query_param"}]
                },
                "entries": [
                    {
                        "request": {"url": "https://d.local/login", "headers": []},
                        "response": {
                            "headers": [],
                            "content": {"text": "device mac: AA:BB:CC:DD:EE:01", "mimeType": "text/plain"},
                        },
                    }
                ],
            }
        }
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(har))
        findings = validate_har(har_file)
        mac_findings = [f for f in findings if "MAC" in f.reason or "mac" in f.reason.lower()]
        assert len(mac_findings) >= 1, "MAC check should still fire for annotated entries"
