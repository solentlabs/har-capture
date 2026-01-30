"""Tests for capture command CLI helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestDisplayHeader:
    """Tests for _display_header function."""

    def test_displays_target_and_browser(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test header displays target and browser."""
        from har_capture.cli.capture import _display_header

        _display_header("192.168.1.1", "chromium", None)

        captured = capsys.readouterr()
        assert "HAR CAPTURE" in captured.out
        assert "192.168.1.1" in captured.out
        assert "chromium" in captured.out

    def test_displays_output_when_provided(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test header displays output path when provided."""
        from har_capture.cli.capture import _display_header

        _display_header("example.com", "firefox", Path("output/test.har"))

        captured = capsys.readouterr()
        assert "output/test.har" in captured.out

    def test_omits_output_when_none(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test header omits output line when None."""
        from har_capture.cli.capture import _display_header

        _display_header("example.com", "webkit", None)

        captured = capsys.readouterr()
        assert "Output:" not in captured.out


class TestDisplayInstructions:
    """Tests for _display_instructions function."""

    def test_displays_instructions(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test instructions are displayed."""
        from har_capture.cli.capture import _display_instructions

        _display_instructions()

        captured = capsys.readouterr()
        assert "Instructions:" in captured.out
        assert "browser" in captured.out.lower()
        assert "Close" in captured.out


class TestDisplayResults:
    """Tests for _display_results function."""

    def test_displays_har_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test results display HAR path."""
        from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
        from har_capture.cli.capture import _display_results

        result = CaptureWorkflowResult(
            capture=CaptureResult(
                success=True,
                har_path=Path("output/capture.har"),
            )
        )

        _display_results(result)

        captured = capsys.readouterr()
        assert "CAPTURE COMPLETE" in captured.out
        assert "output/capture.har" in captured.out

    def test_displays_compressed_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test results display compressed path."""
        from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
        from har_capture.cli.capture import _display_results

        result = CaptureWorkflowResult(
            capture=CaptureResult(
                success=True,
                compressed_path=Path("output/capture.har.gz"),
            )
        )

        _display_results(result)

        captured = capsys.readouterr()
        assert "Compressed:" in captured.out
        assert "output/capture.har.gz" in captured.out

    def test_displays_sanitized_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test results display sanitized path."""
        from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
        from har_capture.cli.capture import _display_results

        result = CaptureWorkflowResult(
            capture=CaptureResult(
                success=True,
                sanitized_path=Path("output/capture.sanitized.har"),
            )
        )

        _display_results(result)

        captured = capsys.readouterr()
        assert "Sanitized:" in captured.out
        assert "output/capture.sanitized.har" in captured.out

    def test_displays_stats(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test results display capture stats."""
        from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
        from har_capture.cli.capture import _display_results

        result = CaptureWorkflowResult(
            capture=CaptureResult(
                success=True,
                har_path=Path("output/capture.har"),
                stats={
                    "removed_entries": 50,
                    "original_entries": 100,
                    "filtered_entries": 50,
                },
            )
        )

        _display_results(result)

        captured = capsys.readouterr()
        assert "Removed 50" in captured.out
        assert "100 -> 50" in captured.out

    def test_next_steps_with_sanitized(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test next steps mentions sanitized file when available."""
        from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
        from har_capture.cli.capture import _display_results

        result = CaptureWorkflowResult(
            capture=CaptureResult(
                success=True,
                sanitized_path=Path("output/capture.sanitized.har"),
            )
        )

        _display_results(result)

        captured = capsys.readouterr()
        assert "Next steps:" in captured.out
        assert "PII removed" in captured.out

    def test_next_steps_without_sanitized(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test next steps suggests sanitization when not sanitized."""
        from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
        from har_capture.cli.capture import _display_results

        result = CaptureWorkflowResult(
            capture=CaptureResult(
                success=True,
                har_path=Path("output/capture.har"),
            )
        )

        _display_results(result)

        captured = capsys.readouterr()
        assert "Next steps:" in captured.out
        assert "har-capture sanitize" in captured.out


class TestHandleAuth:
    """Tests for _handle_auth function."""

    def test_returns_none_when_no_auth_required(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test returns None when no auth is required."""
        from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
        from har_capture.cli.capture import _handle_auth

        result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=False))

        creds = _handle_auth(result, None, None)

        assert creds is None
        captured = capsys.readouterr()
        assert "Form-based or no auth" in captured.out

    def test_returns_provided_credentials(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test returns provided credentials when auth required."""
        from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
        from har_capture.cli.capture import _handle_auth

        result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=True, realm="Router"))

        creds = _handle_auth(result, "admin", "password123")

        assert creds == {"username": "admin", "password": "password123"}
        captured = capsys.readouterr()
        assert "HTTP Basic Auth" in captured.out
        assert "Router" in captured.out

    @patch("har_capture.cli.capture.typer.prompt")
    def test_prompts_for_credentials_when_not_provided(
        self,
        mock_prompt: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test prompts for credentials when not provided."""
        from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
        from har_capture.cli.capture import _handle_auth

        mock_prompt.side_effect = ["testuser", "testpass"]

        result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=True, realm="Modem"))

        creds = _handle_auth(result, None, None)

        assert creds == {"username": "testuser", "password": "testpass"}
        assert mock_prompt.call_count == 2

    @patch("har_capture.cli.capture.typer.prompt")
    def test_prompts_without_realm(
        self,
        mock_prompt: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test prompts work when realm is not set."""
        from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
        from har_capture.cli.capture import _handle_auth

        mock_prompt.side_effect = ["user", "pass"]

        result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=True, realm=None))

        creds = _handle_auth(result, None, None)

        assert creds == {"username": "user", "password": "pass"}
        captured = capsys.readouterr()
        assert "requires HTTP Basic Authentication" in captured.out

    @patch("har_capture.cli.capture.typer.prompt")
    def test_handles_empty_password(
        self,
        mock_prompt: MagicMock,
    ) -> None:
        """Test handles empty password input."""
        from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
        from har_capture.cli.capture import _handle_auth

        mock_prompt.side_effect = ["admin", ""]

        result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=True))

        creds = _handle_auth(result, None, None)

        assert creds == {"username": "admin", "password": ""}
