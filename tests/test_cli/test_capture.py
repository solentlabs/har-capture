"""Tests for capture command CLI helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# =============================================================================
# _display_header() test cases
# =============================================================================
#
# ┌─────────────────┬──────────┬───────────────────┬─────────────────────────────┐
# │ target          │ browser  │ output            │ description                 │
# ├─────────────────┼──────────┼───────────────────┼─────────────────────────────┤
# │ 192.168.1.1     │ chromium │ None              │ basic usage, no output path │
# │ example.com     │ firefox  │ output/test.har   │ with output path            │
# │ router.local    │ webkit   │ None              │ different browser           │
# └─────────────────┴──────────┴───────────────────┴─────────────────────────────┘
#
# fmt: off
DISPLAY_HEADER_CASES = [
    # (target,          browser,    output,                   expected_strs,                        not_expected,   desc)
    ("192.168.1.1",     "chromium", None,                     ["HAR CAPTURE", "192.168.1.1", "chromium"], ["Output:"], "basic usage no output"),
    ("example.com",     "firefox",  Path("output/test.har"),  ["example.com", "firefox", "output/test.har"], [],      "with output path"),
    ("router.local",    "webkit",   None,                     ["router.local", "webkit"],           ["Output:"],     "webkit browser"),
]
# fmt: on


@pytest.mark.parametrize(
    ("target", "browser", "output", "expected_strs", "not_expected", "desc"),
    DISPLAY_HEADER_CASES,
)
def test_display_header(
    target: str,
    browser: str,
    output: Path | None,
    expected_strs: list[str],
    not_expected: list[str],
    desc: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test _display_header output contains expected strings."""
    from har_capture.cli.capture import _display_header

    _display_header(target, browser, output)

    captured = capsys.readouterr()
    for s in expected_strs:
        assert s in captured.out, f"{desc}: expected '{s}' in output"
    for s in not_expected:
        assert s not in captured.out, f"{desc}: did not expect '{s}' in output"


# =============================================================================
# _display_instructions() test
# =============================================================================


def test_display_instructions(capsys: pytest.CaptureFixture[str]) -> None:
    """Test _display_instructions shows usage guidance."""
    from har_capture.cli.capture import _display_instructions

    _display_instructions()

    captured = capsys.readouterr()
    assert "Instructions:" in captured.out
    assert "browser" in captured.out.lower()
    assert "Close" in captured.out


# =============================================================================
# _display_results() test cases
# =============================================================================
#
# ┌──────────────────────┬────────────────────┬──────────────────┬─────────────────────────┐
# │ har_path             │ compressed_path    │ sanitized_path   │ description             │
# ├──────────────────────┼────────────────────┼──────────────────┼─────────────────────────┤
# │ output/capture.har   │ None               │ None             │ raw HAR only            │
# │ None                 │ output/c.har.gz    │ None             │ compressed only         │
# │ None                 │ None               │ output/c.san.har │ sanitized only          │
# │ output/capture.har   │ output/c.har.gz    │ output/c.san.har │ all paths               │
# └──────────────────────┴────────────────────┴──────────────────┴─────────────────────────┘
#
# fmt: off
DISPLAY_RESULTS_CASES = [
    # (har_path,               compressed_path,            sanitized_path,                   stats,                                                    expected_strs,                                       desc)
    (Path("output/capture.har"), None,                     None,                             {},                                                       ["CAPTURE COMPLETE", "output/capture.har", "har-capture sanitize"], "raw HAR only"),
    (None,                     Path("output/c.har.gz"),    None,                             {},                                                       ["Compressed:", "output/c.har.gz"],                  "compressed only"),
    (None,                     None,                       Path("output/c.sanitized.har"),   {},                                                       ["Sanitized:", "output/c.sanitized.har", "PII removed"], "sanitized only"),
    (Path("output/c.har"),     Path("output/c.har.gz"),    Path("output/c.sanitized.har"),   {},                                                       ["output/c.har", "output/c.har.gz", "output/c.sanitized.har"], "all paths"),
    (Path("output/c.har"),     None,                       None,                             {"removed_entries": 50, "original_entries": 100, "filtered_entries": 50}, ["Removed 50", "100 -> 50"], "with stats"),
]
# fmt: on


@pytest.mark.parametrize(
    ("har_path", "compressed_path", "sanitized_path", "stats", "expected_strs", "desc"),
    DISPLAY_RESULTS_CASES,
)
def test_display_results(
    har_path: Path | None,
    compressed_path: Path | None,
    sanitized_path: Path | None,
    stats: dict[str, Any],
    expected_strs: list[str],
    desc: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test _display_results shows expected output."""
    from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
    from har_capture.cli.capture import _display_results

    result = CaptureWorkflowResult(
        capture=CaptureResult(
            success=True,
            har_path=har_path,
            compressed_path=compressed_path,
            sanitized_path=sanitized_path,
            stats=stats,
        )
    )

    _display_results(result)

    captured = capsys.readouterr()
    for s in expected_strs:
        assert s in captured.out, f"{desc}: expected '{s}' in output"


# =============================================================================
# _handle_auth() test cases
# =============================================================================
#
# ┌───────────────┬─────────┬──────────┬──────────┬──────────────────────────────┐
# │ requires_auth │ realm   │ username │ password │ description                  │
# ├───────────────┼─────────┼──────────┼──────────┼──────────────────────────────┤
# │ False         │ None    │ None     │ None     │ no auth required             │
# │ True          │ Router  │ admin    │ pass123  │ auth with provided creds     │
# │ True          │ None    │ admin    │ pass123  │ auth without realm           │
# └───────────────┴─────────┴──────────┴──────────┴──────────────────────────────┘
#
# fmt: off
HANDLE_AUTH_CASES = [
    # (requires_auth, realm,    username, password,   expected_creds,                          expected_output,              desc)
    (False,           None,     None,     None,       None,                                    ["Form-based or no auth"],    "no auth required"),
    (True,            "Router", "admin",  "pass123",  {"username": "admin", "password": "pass123"}, ["HTTP Basic Auth", "Router"], "auth with creds and realm"),
    (True,            None,     "admin",  "pass123",  {"username": "admin", "password": "pass123"}, ["HTTP Basic Auth"],          "auth with creds no realm"),
]
# fmt: on


@pytest.mark.parametrize(
    ("requires_auth", "realm", "username", "password", "expected_creds", "expected_output", "desc"),
    HANDLE_AUTH_CASES,
)
def test_handle_auth(
    requires_auth: bool,
    realm: str | None,
    username: str | None,
    password: str | None,
    expected_creds: dict[str, str] | None,
    expected_output: list[str],
    desc: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test _handle_auth returns correct credentials."""
    from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
    from har_capture.cli.capture import _handle_auth

    result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=requires_auth, realm=realm))

    creds = _handle_auth(result, username, password)

    assert creds == expected_creds, f"{desc}: unexpected credentials"
    captured = capsys.readouterr()
    for s in expected_output:
        assert s in captured.out, f"{desc}: expected '{s}' in output"


# =============================================================================
# _handle_auth() prompt tests (require mocking)
# =============================================================================
#
# ┌─────────────┬────────────────┬────────────────┬──────────────────────────────┐
# │ realm       │ prompt_returns │ expected_creds │ description                  │
# ├─────────────┼────────────────┼────────────────┼──────────────────────────────┤
# │ Modem       │ [user, pass]   │ user/pass      │ prompts with realm           │
# │ None        │ [user, pass]   │ user/pass      │ prompts without realm        │
# │ Router      │ [admin, ""]    │ admin/""       │ empty password allowed       │
# └─────────────┴────────────────┴────────────────┴──────────────────────────────┘
#
# fmt: off
HANDLE_AUTH_PROMPT_CASES = [
    # (realm,    prompt_returns,       expected_creds,                              expected_output,                         desc)
    ("Modem",    ["testuser", "testpass"], {"username": "testuser", "password": "testpass"}, ["Modem"],                              "prompts with realm"),
    (None,       ["user", "pass"],         {"username": "user", "password": "pass"},         ["requires HTTP Basic Authentication"], "prompts without realm"),
    ("Router",   ["admin", ""],            {"username": "admin", "password": ""},            ["Router"],                             "empty password allowed"),
]
# fmt: on


@pytest.mark.parametrize(
    ("realm", "prompt_returns", "expected_creds", "expected_output", "desc"),
    HANDLE_AUTH_PROMPT_CASES,
)
@patch("har_capture.cli.capture.typer.prompt")
def test_handle_auth_prompts(
    mock_prompt: MagicMock,
    realm: str | None,
    prompt_returns: list[str],
    expected_creds: dict[str, str],
    expected_output: list[str],
    desc: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test _handle_auth prompts for credentials when not provided."""
    from har_capture.capture.workflow import AuthResult, CaptureWorkflowResult
    from har_capture.cli.capture import _handle_auth

    mock_prompt.side_effect = prompt_returns

    result = CaptureWorkflowResult(auth=AuthResult(requires_basic_auth=True, realm=realm))

    creds = _handle_auth(result, None, None)

    assert creds == expected_creds, f"{desc}: unexpected credentials"
    assert mock_prompt.call_count == 2, f"{desc}: expected 2 prompts"
    captured = capsys.readouterr()
    for s in expected_output:
        assert s in captured.out, f"{desc}: expected '{s}' in output"
