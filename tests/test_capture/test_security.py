"""Security tests for capture module."""

from __future__ import annotations

from har_capture.capture.browser import _sanitize_error_message


class TestCredentialSanitization:
    """Tests for credential sanitization in error messages."""

    def test_sanitizes_username(self) -> None:
        """Test username is removed from error message."""
        error = "Authentication failed for user admin123"
        creds = {"username": "admin123", "password": "secret"}

        result = _sanitize_error_message(error, creds)

        assert "admin123" not in result
        assert "[USERNAME]" in result

    def test_sanitizes_password(self) -> None:
        """Test password is removed from error message."""
        error = "Invalid credentials: password=MySecret123"
        creds = {"username": "user", "password": "MySecret123"}

        result = _sanitize_error_message(error, creds)

        assert "MySecret123" not in result
        assert "[PASSWORD]" in result

    def test_sanitizes_both(self) -> None:
        """Test both username and password are sanitized."""
        error = "Login failed for admin with password hunter2"
        creds = {"username": "admin", "password": "hunter2"}

        result = _sanitize_error_message(error, creds)

        assert "admin" not in result
        assert "hunter2" not in result
        assert "[USERNAME]" in result
        assert "[PASSWORD]" in result

    def test_no_credentials_returns_unchanged(self) -> None:
        """Test None credentials returns unchanged error."""
        error = "Connection timeout"

        result = _sanitize_error_message(error, None)

        assert result == "Connection timeout"

    def test_empty_credentials_returns_unchanged(self) -> None:
        """Test empty credentials dict returns unchanged error."""
        error = "Connection refused"
        creds: dict[str, str] = {}

        result = _sanitize_error_message(error, creds)

        assert result == "Connection refused"

    def test_partial_credentials(self) -> None:
        """Test only provided credentials are sanitized."""
        error = "Failed for admin"
        creds = {"username": "admin"}  # No password

        result = _sanitize_error_message(error, creds)

        assert "admin" not in result
        assert "[USERNAME]" in result

    def test_multiple_occurrences(self) -> None:
        """Test all occurrences are sanitized."""
        error = "User admin tried admin/secret123 and failed"
        creds = {"username": "admin", "password": "secret123"}

        result = _sanitize_error_message(error, creds)

        # All occurrences should be replaced
        assert "admin" not in result
        assert "secret123" not in result
        assert result.count("[USERNAME]") == 2

    def test_special_regex_characters_in_credentials(self) -> None:
        """Test credentials with regex special chars are handled safely."""
        # Password contains regex special characters
        error = "Auth failed with p@ss.word+123"
        creds = {"username": "user", "password": "p@ss.word+123"}

        result = _sanitize_error_message(error, creds)

        assert "p@ss.word+123" not in result
        assert "[PASSWORD]" in result
