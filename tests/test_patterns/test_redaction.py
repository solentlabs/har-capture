"""Tests for consolidated redaction checking.

This module tests the unified redaction checking logic that determines if
a value has already been redacted or sanitized.

Test Coverage:
    - Static placeholder recognition ([REDACTED], XX:XX:XX:XX:XX:XX, etc.)
    - Hash prefix detection (DEVICE_, SERIAL_, TOKEN_, etc.)
    - Format-preserving pattern matching (02:xx MACs, 10.255.x.x IPs)
    - Redaction pattern recognition (***PASSWORD***, 000000, etc.)
    - Case-insensitive matching
    - Custom pattern file support with merging
    - Edge cases (empty strings, partial matches, prefix positioning)
    - Integration with validation.secrets module
    - Error handling for invalid pattern files

Test Strategy:
    - Table-driven tests with parameterized test data
    - Separate tables for redacted vs non-redacted values
    - Integration tests with custom allowlist files
    - Error condition testing (malformed JSON, missing files)
    - Backwards compatibility validation

Dependencies:
    - pytest for test framework and parametrization
    - tempfile for creating test pattern files
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from har_capture.patterns.loader import load_pii_patterns
from har_capture.patterns.redaction import (
    EMAIL_RE,
    IPV6_RE,
    MAC_RE,
    PRIVATE_IP_RE,
    PUBLIC_IP_RE,
    QueryCredential,
    QueryPayload,
    classify_identity_field,
    credential_value_action,
    decode_base64_payload,
    decode_transport_body,
    find_query_credential,
    find_query_payload,
    is_allowlisted,
    is_base64_credential,
    is_constant_mac,
    is_fully_redacted,
    is_ipv6_host_address,
    is_mac_placeholder,
    is_redacted,
    is_text_mime,
    iter_json_strings,
    iter_url_credentials,
    mime_kind,
    parse_json_container,
    route_body,
    split_url_password,
)

# Load test data from fixture
_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_redaction.json").read_text())

REDACTED_VALUES = _FIXTURES["redacted_values"]
NON_REDACTED_VALUES = _FIXTURES["non_redacted_values"]
CASE_INSENSITIVE_PAIRS = [tuple(group) for group in _FIXTURES["case_insensitive_pairs"]]
QUERY_CREDENTIAL_CASES = _FIXTURES["query_credential_cases"]["cases"]
BASE64_CREDENTIAL_PADDING_CASES = _FIXTURES["base64_credential_padding_cases"]["cases"]
MAC_REGEX_CASES = _FIXTURES["mac_regex_cases"]["cases"]
URL_CREDENTIAL_CASES = _FIXTURES["url_credential_cases"]["cases"]
JSON_IDENTITY_KEY_CASES = _FIXTURES["json_identity_key_cases"]["cases"]
TRANSPORT_BODY_CASES = _FIXTURES["transport_body_cases"]["cases"]
BASE64_PAYLOAD_CASES = _FIXTURES["base64_payload_cases"]["cases"]
TEXT_MIME_CASES = _FIXTURES["text_mime_cases"]["cases"]
JSON_CONTAINER_CASES = _FIXTURES["json_container_cases"]["cases"]
CONSTANT_MAC_CASES = _FIXTURES["constant_mac_cases"]["cases"]
QUERY_PAYLOAD_CASES = _FIXTURES["query_payload_cases"]["cases"]
URL_PASSWORD_CASES = _FIXTURES["url_password_cases"]["cases"]
BODY_ROUTE_CASES = _FIXTURES["body_route_cases"]["cases"]
MAC_PLACEHOLDER_CASES = _FIXTURES["mac_placeholder_cases"]["cases"]
NETWORK_VALUE_REGEX_CASES = _FIXTURES["network_value_regex_cases"]["cases"]
ITER_JSON_STRINGS_CASES = _FIXTURES["iter_json_strings_cases"]["cases"]
CREDENTIAL_VALUE_ACTION_CASES = _FIXTURES["credential_value_action_cases"]["cases"]


class TestMacRegex:
    """MAC_RE is the one MAC definition for the sanitizer, the validator and check_for_pii."""

    @pytest.mark.parametrize("case", MAC_REGEX_CASES, ids=[c["id"] for c in MAC_REGEX_CASES])
    def test_matches(self, case: dict) -> None:
        assert [m.group(0) for m in MAC_RE.finditer(case["text"])] == case["matches"]

    def test_pii_json_mirrors_mac_re(self) -> None:
        """check_for_pii reads pii.json; the pattern file must carry MAC_RE verbatim."""
        assert load_pii_patterns()["patterns"]["mac_address"]["regex"] == MAC_RE.pattern


class TestNetworkValueRegexes:
    """One IP, IPv6 and email definition for both engines, validate and check_for_pii."""

    _REGEXES = {"ipv6": IPV6_RE, "private_ip": PRIVATE_IP_RE, "public_ip": PUBLIC_IP_RE, "email": EMAIL_RE}

    @pytest.mark.parametrize(
        "case", NETWORK_VALUE_REGEX_CASES, ids=[c["id"] for c in NETWORK_VALUE_REGEX_CASES]
    )
    def test_matches(self, case: dict) -> None:
        found = [m.group(0) for m in self._REGEXES[case["regex"]].finditer(case["text"])]
        if case["regex"] == "ipv6":
            found = [candidate for candidate in found if is_ipv6_host_address(candidate)]
        assert found == case["matches"]

    @pytest.mark.parametrize("name", ["private_ip", "public_ip", "ipv6", "email"])
    def test_pii_json_mirrors_shared_regex(self, name: str) -> None:
        """check_for_pii reads pii.json; the pattern file must carry the shared regex verbatim."""
        assert load_pii_patterns()["patterns"][name]["regex"] == self._REGEXES[name].pattern


class TestCredentialValueAction:
    """credential_value_action: keep, review or redact a value served under a credential-named key."""

    @pytest.mark.parametrize(
        "case", CREDENTIAL_VALUE_ACTION_CASES, ids=[c["id"] for c in CREDENTIAL_VALUE_ACTION_CASES]
    )
    def test_action(self, case: dict) -> None:
        assert credential_value_action(case["value"]) == case["action"]


class TestIterJsonStrings:
    """iter_json_strings yields the decoded strings both tools' text passes read."""

    @pytest.mark.parametrize("case", ITER_JSON_STRINGS_CASES, ids=[c["id"] for c in ITER_JSON_STRINGS_CASES])
    def test_strings(self, case: dict) -> None:
        assert sorted(iter_json_strings(parse_json_container(case["text"]))) == sorted(case["strings"])


class TestIterUrlCredentials:
    """iter_url_credentials reads a request's whole query with find_query_credential."""

    @pytest.mark.parametrize("case", URL_CREDENTIAL_CASES, ids=[c["id"] for c in URL_CREDENTIAL_CASES])
    def test_credentials(self, case: dict) -> None:
        assert [c.credential for c in iter_url_credentials(case["request"])] == case["credentials"]


class TestClassifyIdentityField:
    """A JSON key naming a serial or MAC, holding a value of that shape."""

    @pytest.mark.parametrize("case", JSON_IDENTITY_KEY_CASES, ids=[c["id"] for c in JSON_IDENTITY_KEY_CASES])
    def test_category(self, case: dict) -> None:
        assert classify_identity_field(case["key"], case["value"]) == case["category"]


class TestDecodeBase64Payload:
    """decode_base64_payload tells a base64-wrapped JSON or URL payload from a credential."""

    @pytest.mark.parametrize("case", BASE64_PAYLOAD_CASES, ids=[c["id"] for c in BASE64_PAYLOAD_CASES])
    def test_decoded(self, case: dict) -> None:
        assert decode_base64_payload(case["value"]) == case["expected"]


class TestMimeKind:
    """mime_kind is the one mime vocabulary; is_text_mime is a kind being named."""

    @pytest.mark.parametrize("case", TEXT_MIME_CASES, ids=[c["id"] for c in TEXT_MIME_CASES])
    def test_kind(self, case: dict) -> None:
        assert mime_kind(case["mime"]) == case["kind"]
        assert is_text_mime(case["mime"]) is (case["kind"] is not None)


class TestParseJsonContainer:
    """parse_json_container accepts objects and arrays and never raises."""

    @pytest.mark.parametrize("case", JSON_CONTAINER_CASES, ids=[c["id"] for c in JSON_CONTAINER_CASES])
    def test_container(self, case: dict) -> None:
        text = "[" * case["nesting"] + "]" * case["nesting"] if "nesting" in case else case["text"]
        assert (parse_json_container(text) is not None) is case["is_container"]


class TestIsConstantMac:
    """is_constant_mac names the broadcast and zero constants in any layout."""

    @pytest.mark.parametrize("case", CONSTANT_MAC_CASES, ids=[c["id"] for c in CONSTANT_MAC_CASES])
    def test_constant(self, case: dict) -> None:
        assert is_constant_mac(case["mac"]) is case["constant"]


class TestBodyRoute:
    """route_body is the one routing decision for the sanitizer and the validator."""

    @pytest.mark.parametrize("case", BODY_ROUTE_CASES, ids=[c["id"] for c in BODY_ROUTE_CASES])
    def test_route(self, case: dict) -> None:
        route, data = route_body(case["mime"], case["text"])
        assert route == case["route"]
        assert (data is not None) is (route == "json")


class TestIsMacPlaceholder:
    """is_mac_placeholder recognizes hash_mac output in every layout."""

    @pytest.mark.parametrize("case", MAC_PLACEHOLDER_CASES, ids=[c["id"] for c in MAC_PLACEHOLDER_CASES])
    def test_placeholder(self, case: dict) -> None:
        assert is_mac_placeholder(case["value"]) is case["placeholder"]


class TestSplitUrlPassword:
    """split_url_password finds a userinfo password and nothing else."""

    @pytest.mark.parametrize("case", URL_PASSWORD_CASES, ids=[c["id"] for c in URL_PASSWORD_CASES])
    def test_parts(self, case: dict) -> None:
        parts = split_url_password(case["url"])
        assert parts == (tuple(case["parts"]) if case["parts"] else None)
        if parts:
            assert "".join(parts) == case["url"]


class TestFindQueryPayload:
    """find_query_payload locates a base64 JSON or URL payload in one raw query segment."""

    @pytest.mark.parametrize("case", QUERY_PAYLOAD_CASES, ids=[c["id"] for c in QUERY_PAYLOAD_CASES])
    def test_payload(self, case: dict) -> None:
        found = find_query_payload(case["segment"])
        if case["encoded"] is None:
            assert found is None
        else:
            assert found is not None
            assert found == QueryPayload(case["prefix"], case["encoded"], found.text, case["quoted"])
            assert found.text == decode_base64_payload(case["encoded"])


class TestDecodeTransportBody:
    """decode_transport_body returns a body's text, or None for binary."""

    @pytest.mark.parametrize("case", TRANSPORT_BODY_CASES, ids=[c["id"] for c in TRANSPORT_BODY_CASES])
    def test_decoded(self, case: dict) -> None:
        assert decode_transport_body(case["content"]) == case["expected"]


class TestBase64CredentialPadding:
    """Credential recognition does not depend on the interpreter's base64 strictness."""

    @pytest.mark.parametrize(
        "case", BASE64_CREDENTIAL_PADDING_CASES, ids=[c["id"] for c in BASE64_CREDENTIAL_PADDING_CASES]
    )
    def test_padding(self, case: dict) -> None:
        assert is_base64_credential(case["value"]) is case["expected"]


class TestFindQueryCredential:
    """find_query_credential locates base64(user:pass) in one raw query segment."""

    @pytest.mark.parametrize("case", QUERY_CREDENTIAL_CASES, ids=[c["id"] for c in QUERY_CREDENTIAL_CASES])
    def test_find_query_credential(self, case: dict) -> None:
        expected = (
            None
            if case["credential"] is None
            else QueryCredential(prefix=case["prefix"], credential=case["credential"], keyed=case["keyed"])
        )
        assert find_query_credential(case["segment"]) == expected


class TestIsRedacted:
    """Tests for is_redacted function."""

    @pytest.mark.parametrize("value", REDACTED_VALUES)
    def test_redacted_values(self, value: str) -> None:
        """Test values that should be recognized as redacted."""
        assert is_redacted(value), f"Expected {value!r} to be redacted"

    @pytest.mark.parametrize("value", NON_REDACTED_VALUES)
    def test_non_redacted_values(self, value: str) -> None:
        """Test that normal values are not considered redacted."""
        assert not is_redacted(value), f"Expected {value!r} to NOT be redacted"

    @pytest.mark.parametrize("variants", CASE_INSENSITIVE_PAIRS)
    def test_case_insensitive_matching(self, variants: tuple[str, ...]) -> None:
        """Test that pattern matching is case-insensitive."""
        for variant in variants:
            assert is_redacted(variant), f"Expected {variant!r} to be redacted (case-insensitive)"

    @pytest.mark.parametrize(
        "value,expected",
        [
            # Exact matches
            ("[REDACTED]", True),
            ("DEVICE_test", True),
            # Partial matches in context
            ("This value is REDACTED", True),
            ("Value: [REDACTED]", True),
            # Prefix matching
            ("DEVICE_test", True),
            ("MY_DEVICE_test", False),  # Not at start
            # Edge cases
            ("", False),
            ("   ", False),
        ],
    )
    def test_edge_cases(self, value: str, expected: bool) -> None:
        """Test edge cases and boundary conditions."""
        assert is_redacted(value) == expected

    def test_custom_patterns(self) -> None:
        """Test custom patterns file works correctly."""
        custom_allowlist = {
            "static_placeholders": {
                "values": [
                    "XX:XX:XX:XX:XX:XX",
                    "0.0.0.0",
                    "::",
                    "x@x.invalid",
                    "[REDACTED]",
                    "CUSTOM_REDACTED",
                ]
            },
            "hash_prefixes": {
                "values": [
                    "SERIAL_",
                    "ACCOUNT_",
                    "PASS_",
                    "TOKEN_",
                    "CSRF_",
                    "CONFIG_",
                    "WIFI_",
                    "DEVICE_",
                    "FIELD_",
                    "AUTH_",
                    "COOKIE_",
                    "CUSTOM_",
                ]
            },
            "format_preserving_patterns": {
                "mac": {
                    "pattern": "^02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$",
                    "description": "Locally administered MAC",
                },
                "private_ip": {
                    "pattern": "^10\\.255\\.\\d{1,3}\\.\\d{1,3}$",
                    "description": "Redacted private IP",
                },
                "public_ip": {
                    "pattern": "^192\\.0\\.2\\.\\d{1,3}$",
                    "description": "TEST-NET-1",
                },
                "ipv6": {
                    "pattern": "^2001:db8::",
                    "description": "IPv6 documentation",
                },
                "email": {
                    "pattern": "@redacted\\.invalid$",
                    "description": "Reserved .invalid TLD",
                },
            },
            "redaction_patterns": {
                "values": [
                    "\\[REDACTED\\]",
                    "REDACTED",
                    "XXX+",
                    "0{6,}",
                    "\\*\\*\\*[A-Z]+\\*\\*\\*",
                    "COOKIE_[a-f0-9]{8}",
                    "MAC_[a-f0-9]{8}",
                    "PASS_[a-f0-9]{8}",
                    "TOKEN_[a-f0-9]{8}",
                    "FIELD_[a-f0-9]{8}",
                    "^MYAPP_.*",
                ]
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_allowlist, f)
            custom_path = f.name

        try:
            # Test custom patterns
            assert is_redacted("CUSTOM_REDACTED", custom_patterns=custom_path)
            assert is_redacted("CUSTOM_abc123", custom_patterns=custom_path)
            assert is_redacted("MYAPP_secret", custom_patterns=custom_path)
            # Standard patterns should still work
            assert is_redacted("[REDACTED]", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)

    def test_backwards_compatibility_with_secrets_module(self) -> None:
        """Test that the function works as a drop-in replacement."""
        result = is_redacted("[REDACTED]")
        assert isinstance(result, bool)
        assert result is True

        result = is_redacted("my_password_value")
        assert isinstance(result, bool)
        assert result is False


class TestIsAllowlisted:
    """Tests for is_allowlisted function (backward compatibility wrapper)."""

    @pytest.mark.parametrize(
        "value,allowlist,expected",
        [
            # None allowlist (loads default)
            ("[REDACTED]", None, True),
            ("DEVICE_test", None, True),
            ("my_value", None, False),
            # Explicit allowlist - static placeholders
            ("EXPLICIT_VALUE", {"static_placeholders": {"values": ["EXPLICIT_VALUE"]}}, True),
            ("other", {"static_placeholders": {"values": ["EXPLICIT_VALUE"]}}, False),
            # Explicit allowlist - hash prefixes
            ("PREFIX_abc123", {"hash_prefixes": {"values": ["PREFIX_"]}}, True),
            ("other_abc123", {"hash_prefixes": {"values": ["PREFIX_"]}}, False),
        ],
    )
    def test_allowlist_checking(self, value: str, allowlist: dict | None, expected: bool) -> None:
        """Test is_allowlisted with various allowlist configurations."""
        assert is_allowlisted(value, allowlist) == expected

    def test_format_preserving_patterns_in_allowlist(self) -> None:
        """Test that format-preserving patterns work with explicit allowlist."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "format_preserving_patterns": {"test_pattern": {"pattern": "^TEST_\\d+$", "description": "Test"}},
        }

        assert is_allowlisted("TEST_123", allowlist)
        assert is_allowlisted("TEST_999", allowlist)
        assert not is_allowlisted("TEST_abc", allowlist)

    def test_redaction_patterns_in_allowlist(self) -> None:
        """Test that redaction_patterns work with explicit allowlist."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "redaction_patterns": {"values": ["SANITIZED", "\\*\\*\\*"]},
        }

        assert is_allowlisted("SANITIZED", allowlist)
        assert is_allowlisted("***", allowlist)
        assert is_allowlisted("***VALUE***", allowlist)
        assert not is_allowlisted("normal_value", allowlist)


class TestIntegrationWithValidationModule:
    """Test integration with validation.secrets module."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("[REDACTED]", True),
            ("DEVICE_test", True),
            ("my_password", False),
        ],
    )
    def test_validation_secrets_uses_new_module(self, value: str, expected: bool) -> None:
        """Test that validation.secrets.is_redacted uses the new module."""
        from har_capture.validation.secrets import is_redacted as secrets_is_redacted

        assert secrets_is_redacted(value) == expected

    def test_custom_patterns_with_validation_module(self) -> None:
        """Test custom patterns work through validation.secrets."""
        from har_capture.validation.secrets import is_redacted as secrets_is_redacted

        custom_allowlist = {
            "static_placeholders": {"values": ["CUSTOM_VAL"]},
            "hash_prefixes": {"values": []},
            "redaction_patterns": {"values": []},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_allowlist, f)
            custom_path = f.name

        try:
            assert secrets_is_redacted("CUSTOM_VAL", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)


class TestMalformedRegexHandling:
    """Tests that malformed regex patterns in allowlist are handled gracefully."""

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        [
            ("[invalid(regex", "unclosed_bracket"),
            ("*bad", "quantifier_at_start"),
            ("(?P<dup>a)(?P<dup>b)", "duplicate_group_name"),
        ],
    )
    def test_malformed_regex_in_allowlist_is_skipped(self, pattern: str, desc: str) -> None:
        """Test that invalid regex patterns in redaction_patterns are skipped."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "redaction_patterns": {"values": [pattern, "VALID_PATTERN"]},
        }

        # Should not raise, and should still match the valid pattern
        assert is_allowlisted("VALID_PATTERN", allowlist), f"{desc}: valid pattern should still match"
        # Should not crash on the invalid pattern
        assert not is_allowlisted("unmatched_value", allowlist), f"{desc}: should return False for non-match"


class TestFormatPreservingInvalidRegex:
    """Tests for invalid regex in format_preserving_patterns."""

    def test_invalid_format_preserving_regex_is_skipped(self) -> None:
        """Test that invalid regex in format_preserving_patterns is skipped gracefully."""
        allowlist = {
            "static_placeholders": {"values": []},
            "hash_prefixes": {"values": []},
            "format_preserving_patterns": {
                "bad_regex": {
                    "pattern": "[invalid(regex",
                    "description": "broken regex",
                },
                "good_regex": {
                    "pattern": "^GOOD_\\d+$",
                    "description": "valid regex",
                },
            },
        }
        # Should not raise; bad pattern is skipped, good pattern still works
        assert is_allowlisted("GOOD_123", allowlist)
        assert not is_allowlisted("random_value", allowlist)


class TestCookieAttributeMetadataDetection:
    """Tests for is_cookie_attribute_metadata helper."""

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        [
            ("HttpOnly: true, Secure: true", True, "standard_metadata"),
            ("SameSite=Lax", True, "samesite_attr"),
            ("session=abc123", False, "normal_cookie"),
            ("", False, "empty_string"),
            ("   ", False, "whitespace_only"),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else "",
    )
    def test_cookie_attribute_metadata(self, value: str, expected: bool, desc: str) -> None:
        """Test is_cookie_attribute_metadata with various inputs."""
        from har_capture.patterns.redaction import is_cookie_attribute_metadata

        assert is_cookie_attribute_metadata(value) == expected, desc


class TestCookieAttributeNameDetection:
    """Tests for is_cookie_attribute_name helper.

    Names the reserved words of the Set-Cookie attribute position
    (RFC 6265 sec. 4.1.1). Matching is case-insensitive per sec. 5.2.
    """

    @pytest.mark.parametrize(
        ("name", "expected", "desc"),
        [
            ("Path", True, "path"),
            ("path", True, "path_lowercase"),
            ("PATH", True, "path_uppercase"),
            (" Path", True, "leading_whitespace_ignored"),
            ("Domain", True, "domain"),
            ("Expires", True, "expires"),
            ("Max-Age", True, "max_age"),
            ("SameSite", True, "samesite"),
            ("Secure", True, "secure_valueless"),
            ("HttpOnly", True, "httponly_valueless"),
            ("Partitioned", True, "partitioned"),
            ("Priority", True, "priority"),
            ("csrfp_token", False, "cookie_name"),
            ("Path_token", False, "attribute_prefix_is_not_an_attribute"),
            ("", False, "empty_string"),
            ("   ", False, "whitespace_only"),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else "",
    )
    def test_cookie_attribute_name(self, name: str, expected: bool, desc: str) -> None:
        """Test is_cookie_attribute_name with reserved and non-reserved keys."""
        from har_capture.patterns.redaction import is_cookie_attribute_name

        assert is_cookie_attribute_name(name) == expected, desc


class TestIsBase64DecodableText:
    """Tests for the is_base64_decodable_text heuristic helper."""

    @pytest.mark.parametrize(
        ("value", "expected", "desc"),
        [
            ("ZXhhbXBsZS1ub3QtcmVhbA==", True, "base64_bare_password"),
            ("YWRtaW46aHVudGVyMg==", True, "base64_userpass_also_matches"),
            ("aGVsbG8gd29ybGQ=", True, "base64_text_with_space"),
            ("admin", False, "plain_word_invalid_length"),
            ("login", False, "plain_word_invalid_length_2"),
            ("test", False, "valid_b64_but_nonprintable_bytes"),
            ("1234", False, "digits_decode_to_nonprintable"),
            ("FIELD_9f856745", False, "placeholder_not_base64_charset"),
            ("not-base64!", False, "invalid_charset"),
            ("Zg==", False, "decoded_too_short"),
            ("", False, "empty_string"),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else "",
    )
    def test_is_base64_decodable_text(self, value: str, expected: bool, desc: str) -> None:
        from har_capture.patterns.redaction import is_base64_decodable_text

        assert is_base64_decodable_text(value) == expected, desc


class TestErrorHandling:
    """Test error handling in redaction checking."""

    def test_invalid_custom_patterns_file(self) -> None:
        """Test handling of invalid custom patterns file."""
        with pytest.raises(Exception):  # PatternLoadError
            is_redacted("test", custom_patterns="/nonexistent/file.json")

    def test_malformed_custom_patterns_json(self) -> None:
        """Test handling of malformed JSON in custom patterns."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            custom_path = f.name

        try:
            with pytest.raises(Exception):  # JSON decode error
                is_redacted("test", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)

    def test_empty_custom_patterns_file(self) -> None:
        """Test handling of empty custom patterns file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            custom_path = f.name

        try:
            # Should not crash, just return False for non-redacted values
            assert not is_redacted("test_value", custom_patterns=custom_path)
            # Standard patterns should still work
            assert is_redacted("[REDACTED]", custom_patterns=custom_path)
        finally:
            Path(custom_path).unlink(missing_ok=True)


class TestIsFullyRedactedInvalidPatterns:
    """A malformed allowlist regex must be skipped, not crash the scan.

    ``is_fully_redacted`` compiles every allowlist family at call time; a bad
    pattern in a user-supplied ``--patterns`` file would otherwise abort the
    whole-body guard and take ``check_content`` down with it.
    """

    # Passed flat: load_allowlist() merges a dict straight onto the builtin
    # allowlist. Nesting it under an "allowlist" key silently contributes
    # nothing and the test would pass without reaching either handler.
    BAD_ALLOWLIST = {
        "format_preserving_patterns": {"bad": {"pattern": "[unterminated"}},
        "redaction_patterns": {"values": ["(also-unterminated"]},
    }

    def test_invalid_patterns_are_skipped_not_raised(self) -> None:
        """Test malformed regexes in both families are skipped gracefully."""
        assert is_fully_redacted("SomeValue", self.BAD_ALLOWLIST) is False

    def test_valid_patterns_still_match_alongside_invalid_ones(self) -> None:
        """Test a good pattern still matches when a bad one precedes it."""
        allowlist = {
            "format_preserving_patterns": {"bad": {"pattern": "[unterminated"}},
            "redaction_patterns": {"values": ["(bad"]},
        }
        assert is_fully_redacted("[REDACTED]", allowlist) is True
