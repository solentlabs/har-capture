"""Driver-mode capture against a local server, in a real browser.

The server plays the modem: pages that redirect at once, a confirm() dialog,
an error status, a connection reset and a request that never answers. The
driver must come away with all of it in the sanitized HAR.
"""

from __future__ import annotations

import contextlib
import json
import socket
import struct
import threading
import time
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright", reason="Playwright not installed")

from har_capture.capture import capture_device_har, settle
from har_capture.capture.deps import check_browser_installed

_HANG_SECONDS = 6
_CREDENTIAL = "YWRtaW46aHVudGVyMnBhc3M="  # base64("admin:hunter2pass")


class _ModemHandler(BaseHTTPRequestHandler):
    """The device under capture."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress server logging during tests."""

    def _html(self, body: str, status: int = 200) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._html("<html><body>device home</body></html>")
        elif path == "/chain0":
            self._html('<html><head><meta http-equiv="refresh" content="0;url=/chain1"></head></html>')
        elif path == "/chain1":
            self._html('<html><head><meta http-equiv="refresh" content="0;url=/chain2"></head></html>')
        elif path == "/chain2":
            self._html("<html><body>chain end</body></html>")
        elif path == "/error":
            self._html("<html><body>internal error</body></html>", status=500)
        elif path == "/reset":
            # SO_LINGER 0 makes close() send RST: a connection reset
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.connection.close()
        elif path == "/hang":
            time.sleep(_HANG_SECONDS)
        else:
            self._html("<html><body>not found</body></html>", status=404)


@pytest.fixture(scope="module")
def modem() -> Generator[str, None, None]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ModemHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _browser_available() -> bool:
    try:
        return check_browser_installed("chromium")
    except Exception:
        return False


pytestmark = [
    pytest.mark.slow,
    pytest.mark.integration,
    pytest.mark.skipif(not _browser_available(), reason="Chromium not installed"),
]


def _capture(modem: str, tmp_path: Path, driver: Any) -> Any:
    return capture_device_har(
        ip=modem,
        output=str(tmp_path / "capture.har"),
        target_url=f"{modem}/",
        headless=True,
        compress=False,
        interactive=False,
        driver=driver,
    )


def _entries(result: Any) -> dict[str, dict[str, Any]]:
    """The sanitized entries by URL path."""
    assert result.sanitized_path is not None and result.sanitized_path.exists()
    har = json.loads(result.sanitized_path.read_text())
    return {e["request"]["url"].split("?", 1)[0].rsplit("/", 1)[-1] or "/": e for e in har["log"]["entries"]}


def _navigate_tolerantly(page: Any, url: str, timeout_ms: int = 1500) -> None:
    """Visit ``url``; a device that fails or hangs is evidence, not an error."""
    with contextlib.suppress(Exception):
        page.goto(url, timeout=timeout_ms)


class TestDriverCapture:
    """A driver runs headless, with no timeout, and ends the capture by returning."""

    def test_modem_failures_are_kept_in_the_har(self, modem: str, tmp_path: Path) -> None:
        def driver(page: Any) -> None:
            for path in ("error", "reset", "hang"):
                _navigate_tolerantly(page, f"{modem}/{path}")

        result = _capture(modem, tmp_path, driver)

        assert result.success, result.error
        entries = _entries(result)
        assert entries["error"]["response"]["status"] == 500
        assert "internal error" in entries["error"]["response"]["content"]["text"]
        reset = entries["reset"]["response"]
        assert reset["status"] == -1
        assert "ERR_CONNECTION_RESET" in reset["_failureText"]
        assert entries["hang"]["response"]["status"] == -1, "a request that never answered was dropped"

    def test_meta_refresh_chain_settles_with_every_page_recorded(self, modem: str, tmp_path: Path) -> None:
        landed: list[str] = []

        def driver(page: Any) -> None:
            page.goto(f"{modem}/chain0")
            landed.append(str(settle(page, quiescence_s=1.0)))
            landed.append(page.url)

        result = _capture(modem, tmp_path, driver)

        assert result.success, result.error
        assert landed == ["True", f"{modem}/chain2"]
        entries = _entries(result)
        for name in ("chain0", "chain1", "chain2"):
            assert name in entries, f"{name} missing from the HAR"
            assert entries[name]["response"]["content"].get("text"), f"{name} lost its body"

    def test_driver_exception_still_writes_the_capture(self, modem: str, tmp_path: Path) -> None:
        def driver(page: Any) -> None:
            page.goto(f"{modem}/chain2")
            raise RuntimeError(f"step failed at {modem}/login?arg={_CREDENTIAL}")

        result = _capture(modem, tmp_path, driver)

        assert result.success is False
        assert isinstance(result.driver_exception, RuntimeError)
        assert result.error is not None
        assert _CREDENTIAL not in result.error
        assert "step failed" in result.error
        assert "chain2" in _entries(result), "the capture so far was not written"

    def test_dialogs_are_recorded_separately_with_their_outcome(self, modem: str, tmp_path: Path) -> None:
        answers: list[Any] = []

        def driver(page: Any) -> None:
            # the restart confirm: accepted once (ok path), then dismissed (cancel path)
            page.on("dialog", lambda dialog: dialog.dismiss() if answers else dialog.accept())
            page.goto(f"{modem}/chain2")
            answers.append(page.evaluate("confirm('restart?')"))
            answers.append(page.evaluate("confirm('restart?')"))

        result = _capture(modem, tmp_path, driver)

        assert result.success, result.error
        assert answers == [True, False]
        har = json.loads(result.sanitized_path.read_text())
        dialogs = har["log"]["_solentlabs"]["dialogs"]
        assert [(d["message"], d["action"], d["resolved_by"]) for d in dialogs] == [
            ("restart?", "accept", "driver"),
            ("restart?", "dismiss", "driver"),
        ]

    def test_dialog_with_no_driver_listener_is_dismissed_and_recorded(
        self, modem: str, tmp_path: Path
    ) -> None:
        answers: list[Any] = []

        def driver(page: Any) -> None:
            page.goto(f"{modem}/chain2")
            answers.append(page.evaluate("confirm('restart?')"))

        result = _capture(modem, tmp_path, driver)

        assert answers == [False]
        dialogs = json.loads(result.sanitized_path.read_text())["log"]["_solentlabs"]["dialogs"]
        assert [(d["action"], d["resolved_by"]) for d in dialogs] == [("dismiss", "auto_dismiss")]

    def test_state_is_snapshot_after_the_driver(self, modem: str, tmp_path: Path) -> None:
        def driver(page: Any) -> None:
            page.goto(f"{modem}/chain2")
            page.context.add_cookies([{"name": "credential", "value": "abc123def456", "url": modem}])

        result = _capture(modem, tmp_path, driver)

        har = json.loads(result.sanitized_path.read_text())
        names = [c["name"] for c in har["log"]["_har_capture"]["browser_cookies"]]
        assert "credential" in names, "cookies were read before the driver ran"
