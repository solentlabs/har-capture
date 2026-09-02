"""Pytest configuration and fixtures for har-capture tests."""

from __future__ import annotations

import builtins
import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_har_file():
    """Create a temporary HAR file for testing."""

    def _create_har(entries: list[dict] | None = None) -> Path:
        if entries is None:
            entries = []

        har_data = {"log": {"version": "1.2", "entries": entries}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
            json.dump(har_data, f)
            return Path(f.name)

    return _create_har


@pytest.fixture
def sample_har_entry():
    """Create a sample HAR entry for testing."""

    def _create_entry(
        method: str = "GET",
        url: str = "http://example.com/",
        status: int = 200,
        content: str = "",
        mime_type: str = "text/html",
        headers: list[dict] | None = None,
        post_data: dict | None = None,
    ) -> dict:
        entry = {
            "request": {
                "method": method,
                "url": url,
                "headers": headers or [],
                "cookies": [],
            },
            "response": {
                "status": status,
                "statusText": "OK",
                "headers": [],
                "content": {"text": content, "mimeType": mime_type},
            },
        }
        if post_data:
            entry["request"]["postData"] = post_data
        return entry

    return _create_entry


@pytest.fixture
def windows_text_mode(monkeypatch):
    r"""Make text-mode writes translate ``\n`` to ``\r\n``, as Windows does.

    Python's text mode writes ``os.linesep`` when ``newline`` is left unset,
    so a writer that does not pin ``newline="\n"`` emits CRLF on Windows and
    LF everywhere else — the same capture, byte-different per platform.
    Downstream repos commit sanitized HARs as immutable evidence and enforce
    LF, so this fixture reproduces the Windows behavior on any platform and
    lets the line-ending tests fail on Linux CI when a pin is dropped.

    Only writes are affected, and only those that did not pin ``newline``.

    Scope limit: this patches ``builtins.open``, and ``pathlib`` holds its own
    reference to the same function via ``io.open``, so ``Path.write_text`` is
    **not** covered — a writer switched to it would default to
    ``newline=None`` (CRLF on Windows) and still pass these tests. Keep the
    HAR/report writers on bare ``open()``, or extend this fixture with them.
    """
    real_open = builtins.open

    def translating_open(file, mode="r", *args, **kwargs):
        if "b" not in mode and any(c in mode for c in "wax+") and "newline" not in kwargs:
            kwargs["newline"] = "\r\n"
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", translating_open)
