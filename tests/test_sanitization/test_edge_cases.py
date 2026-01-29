"""Tests for edge cases in sanitization."""

from __future__ import annotations

import json

import pytest

from har_capture.sanitization.har import (
    _MAX_RECURSION_DEPTH,
    _sanitize_json_recursive,
    sanitize_entry,
    sanitize_har,
)
from har_capture.sanitization.html import sanitize_html


class TestRecursionDepthLimit:
    """Tests for recursion depth limits."""

    def test_deeply_nested_json_limited(self) -> None:
        """Test deeply nested JSON doesn't cause stack overflow."""
        # Create deeply nested structure (deeper than limit)
        depth = _MAX_RECURSION_DEPTH + 10
        data: dict = {}
        current = data
        for i in range(depth):
            current["nested"] = {}
            current["password"] = f"secret_{i}"
            current = current["nested"]
        current["password"] = "deepest_secret"

        # Should not raise RecursionError
        result = _sanitize_json_recursive(data)

        # Verify function completed without crashing
        assert "nested" in result

    def test_recursion_limit_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test recursion limit logs a warning."""
        # Create structure at exactly the limit + 1
        depth = _MAX_RECURSION_DEPTH + 5
        data: dict = {}
        current = data
        for _ in range(depth):
            current["nested"] = {}
            current = current["nested"]

        with caplog.at_level("WARNING"):
            _sanitize_json_recursive(data)

        assert "Max recursion depth exceeded" in caplog.text

    def test_shallow_json_fully_sanitized(self) -> None:
        """Test shallow JSON is fully sanitized."""
        data = {"level1": {"level2": {"level3": {"password": "secret123"}}}}

        result = _sanitize_json_recursive(data)

        assert result["level1"]["level2"]["level3"]["password"] == "[REDACTED]"


class TestMalformedInput:
    """Tests for malformed input handling."""

    def test_missing_request_key(self) -> None:
        """Test entry without request key."""
        entry = {
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": "test", "mimeType": "text/html"},
            }
        }

        # Should not raise
        result = sanitize_entry(entry)
        assert "response" in result

    def test_missing_response_key(self) -> None:
        """Test entry without response key."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://test/",
                "headers": [],
            }
        }

        # Should not raise
        result = sanitize_entry(entry)
        assert "request" in result

    def test_null_content_text(self) -> None:
        """Test response with null content text."""
        entry = {
            "request": {"method": "GET", "url": "http://test/", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": None, "mimeType": "text/html"},
            },
        }

        # Should not raise
        result = sanitize_entry(entry)
        assert result["response"]["content"]["text"] is None

    def test_empty_har_log(self) -> None:
        """Test HAR with empty log."""
        har_data = {"log": {}}

        result = sanitize_har(har_data)
        assert result == {"log": {}}

    def test_har_missing_log_key(self) -> None:
        """Test HAR without log key."""
        har_data = {"version": "1.2"}

        # Should return unchanged but log warning
        result = sanitize_har(har_data)
        assert result == {"version": "1.2"}

    def test_invalid_entries_type(self) -> None:
        """Test HAR with non-list entries."""
        har_data = {"log": {"entries": "not a list"}}

        # Should return unchanged
        result = sanitize_har(har_data)
        assert result["log"]["entries"] == "not a list"

    def test_headers_not_list(self) -> None:
        """Test request with non-list headers."""
        entry = {
            "request": {
                "method": "GET",
                "url": "http://test/",
                "headers": "not a list",
            },
            "response": {"status": 200, "headers": [], "content": {}},
        }

        # Should not raise
        result = sanitize_entry(entry)
        assert result["request"]["headers"] == "not a list"


class TestLargeInputs:
    """Tests for large input handling."""

    def test_large_html_content(self) -> None:
        """Test large HTML content doesn't timeout."""
        # Create large HTML with many PII items
        parts = ["<html><body>"]
        for i in range(1000):
            parts.append(f"<div>MAC: AA:BB:CC:DD:EE:{i:02X}</div>")
            parts.append(f"<div>Email: user{i}@example.com</div>")
        parts.append("</body></html>")
        large_html = "".join(parts)

        # Should complete without timeout
        result = sanitize_html(large_html, salt=None)

        # Verify sanitization happened
        assert "AA:BB:CC:DD:EE:00" not in result
        assert "user0@example.com" not in result

    def test_many_har_entries(self) -> None:
        """Test HAR with many entries."""
        entries = []
        for i in range(500):
            entries.append(
                {
                    "request": {
                        "method": "GET",
                        "url": f"http://test/{i}",
                        "headers": [{"name": "Cookie", "value": f"session=secret{i}"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"text": f"MAC: AA:BB:CC:DD:EE:{i:02X}", "mimeType": "text/html"},
                    },
                }
            )

        har_data = {"log": {"version": "1.2", "entries": entries}}

        # Should complete without timeout
        result = sanitize_har(har_data, salt=None)

        # Verify sanitization happened
        assert len(result["log"]["entries"]) == 500
        first_cookie = result["log"]["entries"][0]["request"]["headers"][0]["value"]
        assert "secret0" not in first_cookie


class TestJsonContentSanitization:
    """Tests for JSON content in responses."""

    def test_invalid_json_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test invalid JSON in response content logs warning."""
        entry = {
            "request": {"method": "GET", "url": "http://test/", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "text": "{ not valid json }",
                    "mimeType": "application/json",
                },
            },
        }

        with caplog.at_level("WARNING"):
            result = sanitize_entry(entry)

        assert "Invalid JSON" in caplog.text
        # Original text should be preserved
        assert result["response"]["content"]["text"] == "{ not valid json }"

    def test_json_array_content(self) -> None:
        """Test JSON array content is sanitized."""
        entry = {
            "request": {"method": "GET", "url": "http://test/", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {
                    "text": '[{"password": "secret1"}, {"password": "secret2"}]',
                    "mimeType": "application/json",
                },
            },
        }

        result = sanitize_entry(entry, salt=None)
        parsed = json.loads(result["response"]["content"]["text"])

        assert parsed[0]["password"] == "[REDACTED]"
        assert parsed[1]["password"] == "[REDACTED]"
