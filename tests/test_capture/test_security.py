"""Security tests for capture module."""

from __future__ import annotations

import pytest

from har_capture.capture.browser import _sanitize_error_message

# =============================================================================
# Test Data Tables
# =============================================================================

# ┌──────────────────────────────────────────┬───────────────────────────┬────────────────────────┬──────────────────┬─────────────────────────┐
# │ error_message                            │ credentials               │ must_not_contain       │ must_contain     │ description             │
# ├──────────────────────────────────────────┼───────────────────────────┼────────────────────────┼──────────────────┼─────────────────────────┤
# │ Original error message                   │ Dict or None              │ Strings that must be   │ Placeholders     │ Test case name          │
# │                                          │                           │ removed from output    │ expected         │                         │
# └──────────────────────────────────────────┴───────────────────────────┴────────────────────────┴──────────────────┴─────────────────────────┘
#
# fmt: off
CREDENTIAL_SANITIZATION_CASES = [
    # Username sanitization
    (
        "Authentication failed for user admin123",
        {"username": "admin123", "password": "secret"},
        ["admin123"],
        ["[USERNAME]"],
        "sanitizes_username",
    ),
    # Password sanitization
    (
        "Invalid credentials: password=MySecret123",
        {"username": "user", "password": "MySecret123"},
        ["MySecret123"],
        ["[PASSWORD]"],
        "sanitizes_password",
    ),
    # Both username and password
    (
        "Login failed for admin with password hunter2",
        {"username": "admin", "password": "hunter2"},
        ["admin", "hunter2"],
        ["[USERNAME]", "[PASSWORD]"],
        "sanitizes_both",
    ),
    # None credentials - unchanged
    (
        "Connection timeout",
        None,
        [],
        [],
        "none_credentials_unchanged",
    ),
    # Empty credentials dict - unchanged
    (
        "Connection refused",
        {},
        [],
        [],
        "empty_credentials_unchanged",
    ),
    # Partial credentials (only username)
    (
        "Failed for admin",
        {"username": "admin"},
        ["admin"],
        ["[USERNAME]"],
        "partial_username_only",
    ),
    # Partial credentials (only password)
    (
        "Bad password secret456",
        {"password": "secret456"},
        ["secret456"],
        ["[PASSWORD]"],
        "partial_password_only",
    ),
    # Multiple occurrences of same credential
    (
        "User admin tried admin/secret123 and failed",
        {"username": "admin", "password": "secret123"},
        ["admin", "secret123"],
        ["[USERNAME]"],  # Should appear twice but we check at least once
        "multiple_occurrences",
    ),
    # Special regex characters in password
    (
        "Auth failed with p@ss.word+123",
        {"username": "user", "password": "p@ss.word+123"},
        ["p@ss.word+123"],
        ["[PASSWORD]"],
        "regex_special_chars_password",
    ),
    # Special regex characters in username
    (
        "User test+user@domain.com denied",
        {"username": "test+user@domain.com", "password": "pass"},
        ["test+user@domain.com"],
        ["[USERNAME]"],
        "regex_special_chars_username",
    ),
    # Empty string credentials (edge case)
    (
        "Error occurred",
        {"username": "", "password": ""},
        [],
        [],
        "empty_string_credentials",
    ),
    # Credential is substring of another word
    (
        "administrator access denied for admin",
        {"username": "admin", "password": "test"},
        [],  # "admin" in "administrator" - tricky case
        ["[USERNAME]"],
        "credential_as_substring",
    ),
    # Very long credentials
    (
        "Failed with password: " + "x" * 100,
        {"username": "u", "password": "x" * 100},
        ["x" * 100],
        ["[PASSWORD]"],
        "long_credentials",
    ),
    # Unicode in credentials
    (
        "User 用户名 failed",
        {"username": "用户名", "password": "密码"},
        ["用户名"],
        ["[USERNAME]"],
        "unicode_credentials",
    ),
    # Credentials with newlines (edge case)
    (
        "Error: bad\npassword",
        {"username": "user", "password": "bad\npassword"},
        ["bad\npassword"],
        ["[PASSWORD]"],
        "newline_in_credentials",
    ),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestCredentialSanitization:
    """Tests for credential sanitization in error messages."""

    @pytest.mark.parametrize(
        ("error", "creds", "must_not_contain", "must_contain", "desc"),
        CREDENTIAL_SANITIZATION_CASES,
        ids=[c[4] for c in CREDENTIAL_SANITIZATION_CASES],
    )
    def test_credential_sanitization(
        self,
        error: str,
        creds: dict[str, str] | None,
        must_not_contain: list[str],
        must_contain: list[str],
        desc: str,
    ) -> None:
        """Test credential sanitization in error messages."""
        result = _sanitize_error_message(error, creds)

        # Check sensitive values are removed
        for value in must_not_contain:
            assert value not in result, f"{desc}: '{value}' should be removed from result"

        # Check placeholders are present
        for placeholder in must_contain:
            assert placeholder in result, f"{desc}: '{placeholder}' should be in result"

        # If no changes expected, result should match original
        if not must_not_contain and not must_contain:
            assert result == error, f"{desc}: result should be unchanged"

    def test_multiple_username_occurrences_count(self) -> None:
        """Test all occurrences of username are replaced."""
        error = "User admin tried admin/secret123 and failed"
        creds = {"username": "admin", "password": "secret123"}

        result = _sanitize_error_message(error, creds)

        # Should have 2 [USERNAME] placeholders
        assert result.count("[USERNAME]") == 2
