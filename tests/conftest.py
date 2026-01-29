"""Pytest configuration and fixtures for har-capture tests."""

from __future__ import annotations

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
