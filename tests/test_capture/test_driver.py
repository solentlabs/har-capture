"""Unit tests for driver mode: mode checks, settle, dialog record, error scrub, wiring.

The browser-backed behavior is in ``test_driver_integration.py``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.browser import (
    BrowserSessionResult,
    _run_driver,
    require_timeout_when_headless,
)
from har_capture.capture.driver import (
    attach_dialog_recording,
    require_valid_driver_mode,
    scrub_driver_error,
    settle,
)
from har_capture.capture.workflow import run_capture_phase

_FIXTURE = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "test_driver.json").read_text())


def _noop_driver(page: Any) -> None:
    """A driver that does nothing."""


class TestModeChecks:
    """A driver run rejects the settings it cannot honor."""

    @pytest.mark.parametrize("case", _FIXTURE["mode_cases"], ids=lambda c: c["id"])
    def test_driver_mode(self, case: dict) -> None:
        driver = _noop_driver if case["driver"] else None
        if case["error"] is None:
            require_valid_driver_mode(case["browser"], case["timeout"], driver)
            return
        with pytest.raises(ValueError, match=case["error"]):
            require_valid_driver_mode(case["browser"], case["timeout"], driver)

    @pytest.mark.parametrize("case", _FIXTURE["headless_cases"], ids=lambda c: c["id"])
    def test_headless_needs_timeout_unless_driver(self, case: dict) -> None:
        driver = _noop_driver if case["driver"] else None
        if case["error"]:
            with pytest.raises(ValueError, match="timeout"):
                require_timeout_when_headless(case["headless"], case["timeout"], driver)
        else:
            require_timeout_when_headless(case["headless"], case["timeout"], driver)


class TestScrubDriverError:
    """A driver's exception text carries no URL credential."""

    @pytest.mark.parametrize("case", _FIXTURE["scrub_cases"], ids=lambda c: c["id"])
    def test_scrub(self, case: dict) -> None:
        text = scrub_driver_error(RuntimeError(case["message"]))

        assert text.startswith("RuntimeError: ")
        for secret in case["absent"]:
            assert secret not in text, "credential survived the scrub"
        for kept in case["present"]:
            assert kept in text, f"{kept!r} was lost"

    def test_long_message_is_cut(self) -> None:
        text = scrub_driver_error(RuntimeError("x" * 5000))

        assert len(text) < 2100
        assert text.endswith("…")


class _FakeDialog:
    """A Playwright dialog with a page whose listener count the test sets."""

    def __init__(self, page: Any) -> None:
        self.type = "confirm"
        self.message = "restart?"
        self.default_value = ""
        self.page = page
        self.calls: list[str] = []

    def accept(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append("accept")

    def dismiss(self) -> None:
        self.calls.append("dismiss")


def _context_with_listeners(listeners: int | None) -> tuple[Any, Any]:
    """A context and page whose emitters report ``listeners`` in total (None: no emitter)."""
    context, page = MagicMock(), MagicMock()
    if listeners is None:
        del context._impl_obj
    else:
        context._impl_obj.listeners.return_value = ["a"] * listeners
        page._impl_obj.listeners.return_value = []
    return context, page


class TestDialogRecording:
    """Each dialog is its own record, resolved by the driver or dismissed here."""

    @pytest.mark.parametrize("case", _FIXTURE["dialog_cases"], ids=lambda c: c["id"])
    def test_record(self, case: dict) -> None:
        context, page = _context_with_listeners(case["listeners"])
        records: list[dict[str, Any]] = []
        attach_dialog_recording(context, records)
        handler = context.on.call_args.args[1]
        dialog = _FakeDialog(page)

        handler(dialog)

        assert len(records) == 1
        assert records[0]["resolved_by"] == case["resolved_by"]
        assert records[0]["action"] == case["action"]
        assert (dialog.calls == ["dismiss"]) is case["auto_dismissed"]

    def test_driver_outcome_is_recorded_per_dialog(self) -> None:
        context, page = _context_with_listeners(2)
        records: list[dict[str, Any]] = []
        attach_dialog_recording(context, records)
        handler = context.on.call_args.args[1]
        first, second = _FakeDialog(page), _FakeDialog(page)

        handler(first)
        handler(second)
        first.dismiss()
        second.accept("typed")

        assert [r["action"] for r in records] == ["dismiss", "accept"]
        assert records[1]["prompt_text_provided"] is True
        assert (first.calls, second.calls) == (["dismiss"], ["accept"])

    def test_dialog_without_a_page_counts_the_context_only(self) -> None:
        context, _ = _context_with_listeners(2)
        records: list[dict[str, Any]] = []
        attach_dialog_recording(context, records)
        handler = context.on.call_args.args[1]

        handler(_FakeDialog(None))

        assert records[0]["resolved_by"] == "driver"


class _FakePage:
    """A page that answers settle()'s polls from a case's script."""

    def __init__(self, case: dict) -> None:
        self._states = case["states"]
        self._urls = case["urls"]
        self._closed = case["closed"]
        self._polls = 0

    def is_closed(self) -> bool:
        return self._closed

    @property
    def url(self) -> str:
        return self._urls[min(self._polls, len(self._urls) - 1)]

    def evaluate(self, _script: str) -> Any:
        state = self._states[min(self._polls, len(self._states) - 1)]
        self._polls += 1
        if state == "raise":
            raise RuntimeError("Execution context was destroyed")
        return state

    def wait_for_timeout(self, ms: int) -> None:
        time.sleep(ms / 1000)


class TestSettle:
    """settle() returns True only for a page that has stopped."""

    @pytest.mark.parametrize("case", _FIXTURE["settle_cases"], ids=lambda c: c["id"])
    def test_settle(self, case: dict) -> None:
        assert settle(_FakePage(case), quiescence_s=0.05, timeout_s=0.7) is case["expect"]


class TestRunDriver:
    """_run_driver keeps a driver's exception instead of losing the capture."""

    def test_exception_is_kept_and_scrubbed(self) -> None:
        def broken(page: Any) -> None:
            raise RuntimeError("boom at http://192.168.100.1/login?arg=YWRtaW46aHVudGVyMnBhc3M=")

        result = BrowserSessionResult()
        with patch("har_capture.capture.browser._wait_for_network_quiescence") as quiescence:
            _run_driver(broken, MagicMock(), result, wait_for_data=True)

        assert isinstance(result.driver_exception, RuntimeError)
        assert result.driver_error is not None
        assert "YWRtaW46aHVudGVyMnBhc3M=" not in result.driver_error
        quiescence.assert_called_once()

    def test_clean_driver_leaves_no_error(self) -> None:
        result = BrowserSessionResult()
        _run_driver(_noop_driver, MagicMock(), result, wait_for_data=False)

        assert result.driver_exception is None
        assert result.driver_error is None

    def test_interrupt_is_not_swallowed(self) -> None:
        def interrupted(page: Any) -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            _run_driver(interrupted, MagicMock(), BrowserSessionResult(), wait_for_data=False)


class TestWorkflowWiring:
    """The workflow hands the driver down and carries its exception back."""

    def test_driver_is_passed_and_exception_returned(self) -> None:
        boom = RuntimeError("driver bug")
        captured = MagicMock(
            success=False,
            error="Capture driver raised RuntimeError: driver bug",
            stats=None,
            downloads=[],
            driver_exception=boom,
        )
        with patch("har_capture.capture.browser.capture_device_har", return_value=captured) as capture:
            result = run_capture_phase("http://10.0.0.1", driver=_noop_driver, headless=True)

        assert capture.call_args.kwargs["driver"] is _noop_driver
        assert result.capture is not None
        assert result.capture.driver_exception is boom
        assert result.capture_success is False
