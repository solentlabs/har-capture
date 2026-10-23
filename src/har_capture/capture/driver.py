"""Driver mode: a script drives the page while har-capture records it.

``capture_device_har(..., driver=fn)`` sets up the capture exactly as an
interactive run does (fresh context, body capture, HAR recording), then hands
the page to ``fn``. The capture ends when ``fn`` returns. This module holds the
pieces that only driver mode needs: the mode checks, the settle helper a driver
calls between steps, the dialog record, and the scrub for a driver's exception.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

_LOGGER = logging.getLogger(__name__)

DriverFn = Callable[[Any], None]
"""A capture driver: receives the Playwright ``Page`` once capture is recording."""

# Seconds without activity before settle() returns, and its overall cap.
SETTLE_QUIESCENCE_S = 2.0
SETTLE_TIMEOUT_S = 30.0
_SETTLE_POLL_S = 0.2

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_ERROR_MAX_CHARS = 2000


def require_valid_driver_mode(browser: str, timeout: int | None, driver: DriverFn | None) -> None:
    """Reject the settings a driver run cannot honor.

    Args:
        browser: Browser engine name
        timeout: Interactive-mode timeout in seconds
        driver: The driver function, or None for a normal capture

    Raises:
        ValueError: A driver with ``timeout`` (the driver's own Playwright
            timeouts are its clock), or with a browser other than chromium
            (the network-level body read that keeps a page the browser leaves
            at once exists only there)
    """
    if driver is None:
        return
    if timeout is not None:
        raise ValueError("driver cannot be combined with timeout: the capture ends when the driver returns")
    if browser != "chromium":
        raise ValueError(
            f"driver needs chromium, not {browser}: only chromium reads a response before the page leaves"
        )


def settle(
    page: Any,
    quiescence_s: float = SETTLE_QUIESCENCE_S,
    timeout_s: float = SETTLE_TIMEOUT_S,
) -> bool:
    """Wait until the page has stopped loading, navigating and fetching.

    Returns once, for ``quiescence_s`` seconds, the document was fully loaded,
    its URL did not change, and no XHR/fetch was in flight. A navigation
    (a 0-second meta refresh, a script setting ``location``) is activity, which
    the in-flight request count alone cannot see. A page that never settles
    within ``timeout_s`` is not an error: the modem's behavior is the evidence,
    so the call returns False and the capture goes on.

    Script that acts after a delay (a timer setting a cookie) still needs the
    driver to wait on its own condition.

    Args:
        page: Playwright page
        quiescence_s: Seconds of no activity before returning
        timeout_s: Longest wait overall

    Returns:
        True when the page settled, False when ``timeout_s`` ran out or the
        page closed
    """
    start = time.monotonic()
    last_url: str | None = None
    last_active = start
    while time.monotonic() - start < timeout_s:
        if page.is_closed():
            return False
        now = time.monotonic()
        try:
            url = page.url
            state = page.evaluate("() => [document.readyState, window.__harCapturePendingRequests || 0]")
            busy = state[0] != "complete" or state[1] > 0
        except Exception:
            # The document is being replaced: its script context is gone.
            url, busy = last_url, True
        if busy or url != last_url:
            last_active = now
        elif now - last_active >= quiescence_s:
            return True
        last_url = url
        page.wait_for_timeout(int(_SETTLE_POLL_S * 1000))
    _LOGGER.debug("settle() gave up after %.1fs", timeout_s)
    return False


def attach_dialog_recording(context: Any, records: list[dict[str, Any]]) -> None:
    """Record every dialog on the context, with how it was resolved.

    One record per dialog, in the order they open, so two dialogs on one page
    are two records. The driver resolves a dialog by registering its own
    ``dialog`` listener and calling ``accept()`` or ``dismiss()``; the record
    notes which. A dialog no listener of the driver's will see is dismissed
    here, as Playwright does when nothing listens, and recorded
    ``resolved_by="auto_dismiss"``.

    Args:
        context: Playwright browser context
        records: List the dialog records are appended to
    """

    def _on_dialog(dialog: Any) -> None:
        record: dict[str, Any] = {
            "type": getattr(dialog, "type", None),
            "message": getattr(dialog, "message", None),
            "default_value": getattr(dialog, "default_value", None),
            "opened_at": datetime.now().isoformat(timespec="seconds"),
            "action": "unresolved",
            "resolved_by": "driver",
        }
        records.append(record)

        original_accept, original_dismiss = dialog.accept, dialog.dismiss

        def accept(*args: Any, **kwargs: Any) -> Any:
            record["action"] = "accept"
            record["prompt_text_provided"] = bool(args or kwargs)
            return original_accept(*args, **kwargs)

        def dismiss(*args: Any, **kwargs: Any) -> Any:
            record["action"] = "dismiss"
            return original_dismiss(*args, **kwargs)

        dialog.accept, dialog.dismiss = accept, dismiss
        _LOGGER.info("Dialog opened: type=%s message=%r", record["type"], record["message"])

        if not _has_other_dialog_listener(dialog, context):
            record["resolved_by"] = "auto_dismiss"
            dismiss()

    context.on("dialog", _on_dialog)


def _has_other_dialog_listener(dialog: Any, context: Any) -> bool:
    """Whether a listener besides the recorder will see this dialog.

    Playwright dismisses a dialog itself only when nothing listens, and the
    recorder's listener makes something listen, so the recorder takes over that
    default. Playwright's public API cannot count listeners; the underlying
    emitter can. If that is unavailable, assume the driver handles it: a
    dialog left open waits for the driver, which is what its own listener
    would have meant.
    """
    try:
        count = len(context._impl_obj.listeners("dialog"))  # noqa: SLF001 — see docstring
        page = dialog.page
        if page is not None:
            count += len(page._impl_obj.listeners("dialog"))  # noqa: SLF001
    except Exception:
        return True
    return count > 1


def scrub_driver_error(exc: BaseException) -> str:
    """Describe a driver's exception without the credentials its text may carry.

    Playwright's errors name the URL being loaded, and a login URL can carry a
    credential. Every URL in the text goes through the sanitizer's URL rules.

    Args:
        exc: The exception the driver raised

    Returns:
        ``ExceptionType: message``, URLs sanitized, cut to a bounded length
    """
    from har_capture.sanitization.har import _sanitize_url

    text = f"{type(exc).__name__}: {exc}"
    text = _URL_RE.sub(lambda m: _sanitize_url(m.group(0)), text)
    if len(text) > _ERROR_MAX_CHARS:
        text = text[:_ERROR_MAX_CHARS] + "…"
    return text
