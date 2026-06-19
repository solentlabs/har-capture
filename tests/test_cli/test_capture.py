"""Tests for capture command CLI helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def test_display_results_suggestions_include_patterns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Next-steps suggestions echo the --patterns used so they are copy-paste ready."""
    from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
    from har_capture.cli.capture import _display_results

    result = CaptureWorkflowResult(capture=CaptureResult(success=True, har_path=Path("output/capture.har")))

    _display_results(result, ["network-device", "./extras.json"])

    out = capsys.readouterr().out
    assert "har-capture sanitize output/capture.har --patterns network-device --patterns ./extras.json" in out
    assert "har-capture validate output/capture.har --patterns network-device --patterns ./extras.json" in out


def test_display_results_suggestions_placeholder_when_no_patterns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With no patterns supplied, suggestions fall back to a <domain> placeholder."""
    from har_capture.capture.workflow import CaptureResult, CaptureWorkflowResult
    from har_capture.cli.capture import _display_results

    result = CaptureWorkflowResult(capture=CaptureResult(success=True, har_path=Path("output/capture.har")))

    _display_results(result)

    assert "--patterns <domain>" in capsys.readouterr().out


# =============================================================================
# _run_interactive_review() — branches over a CaptureWorkflowResult
# =============================================================================
#
# This helper has four early-return branches and one full-review path.
# The branches are purely structural (does the workflow result carry
# enough data to run review?), so they're testable by constructing
# small workflow-result fixtures rather than driving an end-to-end
# capture.


class TestRunInteractiveReview:
    """Direct unit tests for ``_run_interactive_review``.

    Each branch is exercised by a workflow result that's missing one
    piece of data, except the full-review path which patches
    ``cli/interactive`` at its module boundary so we don't drive a real
    interactive prompt loop.
    """

    @staticmethod
    def _make_result(
        capture: Any,
    ) -> Any:
        from har_capture.capture.workflow import CaptureWorkflowResult

        return CaptureWorkflowResult(capture=capture)

    @staticmethod
    def _make_report(
        flagged: list[Any] | None = None,
        salt: bool = True,
        total_user_redacted: int = 0,
    ) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(
            flagged=flagged or [],
            salt=salt,
            total_user_redacted=total_user_redacted,
        )

    def test_no_capture_data_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        from har_capture.cli.capture import _run_interactive_review

        result = self._make_result(capture=None)
        _run_interactive_review(result)

        captured = capsys.readouterr()
        assert "No capture data available" in captured.err

    def test_missing_report_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        from har_capture.capture.workflow import CaptureResult
        from har_capture.cli.capture import _run_interactive_review

        cap = CaptureResult(
            success=True,
            sanitized_path=Path("/test/x.har"),
            sanitization_report=None,
        )
        _run_interactive_review(self._make_result(capture=cap))

        captured = capsys.readouterr()
        assert "Missing sanitization data" in captured.err

    def test_missing_sanitized_path_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        from har_capture.capture.workflow import CaptureResult
        from har_capture.cli.capture import _run_interactive_review

        cap = CaptureResult(
            success=True,
            sanitized_path=None,
            sanitization_report=self._make_report(flagged=[object()]),
        )
        _run_interactive_review(self._make_result(capture=cap))

        captured = capsys.readouterr()
        assert "Missing sanitization data" in captured.err

    def test_no_flagged_short_circuits(self, capsys: pytest.CaptureFixture[str]) -> None:
        from har_capture.capture.workflow import CaptureResult
        from har_capture.cli.capture import _run_interactive_review

        cap = CaptureResult(
            success=True,
            sanitized_path=Path("/test/x.har"),
            sanitization_report=self._make_report(flagged=[]),
        )
        _run_interactive_review(self._make_result(capture=cap))

        captured = capsys.readouterr()
        assert "No suspicious values found" in captured.out

    def test_full_review_with_no_user_redactions(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Review runs, user redacts nothing -> apply path is NOT called."""
        from har_capture.capture.workflow import CaptureResult
        from har_capture.cli import interactive as interactive_mod
        from har_capture.cli.capture import _run_interactive_review

        review_calls: list[dict[str, Any]] = []
        summary_calls: list[Any] = []

        def fake_review(report: Any, **kwargs: Any) -> bool:
            review_calls.append(kwargs)
            return True

        def fail_apply(*a: Any, **k: Any) -> None:
            pytest.fail("apply must not run when total_user_redacted == 0")

        monkeypatch.setattr(interactive_mod, "run_interactive_review", fake_review)
        monkeypatch.setattr(interactive_mod, "display_summary", summary_calls.append)
        monkeypatch.setattr(interactive_mod, "apply_reviewed_redactions", fail_apply)

        cap = CaptureResult(
            success=True,
            har_path=Path("/test/raw.har"),
            sanitized_path=Path("/test/clean.har"),
            sanitization_report=self._make_report(flagged=[object()], salt=True, total_user_redacted=0),
        )
        _run_interactive_review(self._make_result(capture=cap))

        assert review_calls
        assert summary_calls
        kwargs = review_calls[0]
        assert kwargs["input_path"] == "/test/raw.har"
        assert kwargs["output_path"] == "/test/clean.har"
        assert "random" in kwargs["salt_mode"]

    def test_full_review_applies_when_user_redacted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """User redacts >=1 value -> apply_reviewed_redactions runs."""
        from har_capture.capture.workflow import CaptureResult
        from har_capture.cli import interactive as interactive_mod
        from har_capture.cli.capture import _run_interactive_review

        apply_calls: list[tuple[Any, ...]] = []

        monkeypatch.setattr(
            interactive_mod,
            "run_interactive_review",
            lambda report, **kwargs: True,
        )
        monkeypatch.setattr(
            interactive_mod,
            "apply_reviewed_redactions",
            lambda r, p: apply_calls.append((r, p)),
        )
        monkeypatch.setattr(
            interactive_mod,
            "display_summary",
            lambda r: None,
        )

        cap = CaptureResult(
            success=True,
            har_path=None,  # exercises the input_display fallback to sanitized_path
            sanitized_path=Path("/test/clean.har"),
            sanitization_report=self._make_report(
                flagged=[object()],
                salt=False,
                total_user_redacted=3,
            ),
        )
        _run_interactive_review(self._make_result(capture=cap))

        assert len(apply_calls) == 1
        assert apply_calls[0][1] == Path("/test/clean.har")

    def test_static_salt_mode_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``report.salt is False`` -> "static placeholders" label."""
        from har_capture.capture.workflow import CaptureResult
        from har_capture.cli import interactive as interactive_mod
        from har_capture.cli.capture import _run_interactive_review

        captured_salt_mode: list[str] = []

        def capture_kwargs(report: Any, **kwargs: Any) -> bool:
            captured_salt_mode.append(kwargs["salt_mode"])
            return False

        monkeypatch.setattr(interactive_mod, "run_interactive_review", capture_kwargs)
        monkeypatch.setattr(interactive_mod, "display_summary", lambda r: None)
        monkeypatch.setattr(interactive_mod, "apply_reviewed_redactions", lambda r, p: None)

        cap = CaptureResult(
            success=True,
            sanitized_path=Path("/test/x.har"),
            sanitization_report=self._make_report(flagged=[object()], salt=False),
        )
        _run_interactive_review(self._make_result(capture=cap))
        assert captured_salt_mode == ["static placeholders"]


# =============================================================================
# capture() — orchestration via CliRunner with workflow phases mocked
# =============================================================================
#
# The phase functions live in ``har_capture.capture.workflow`` and are
# imported inside ``capture()`` itself. Patching them on the workflow
# module reaches the CLI's call sites because the import resolves the
# name from the patched module object at call time.
#
# We mock at this single boundary rather than mocking deep Playwright
# internals — the workflow module already extracted the pure phase
# logic (see workflow.py), so the CLI just needs each phase to return a
# CaptureWorkflowResult shaped to drive a particular branch.


@pytest.fixture
def workflow_module() -> Any:
    """Convenience fixture for monkeypatching workflow phase functions."""
    from har_capture.capture import workflow as wf

    return wf


def _make_browser_result(needs_install: bool = False) -> Any:
    from har_capture.capture.workflow import (
        BrowserCheckResult,
        CaptureWorkflowResult,
    )

    return CaptureWorkflowResult(browser=BrowserCheckResult(needs_install=needs_install))


def _make_connected_result(target_url: str = "http://10.0.0.1/") -> Any:
    from har_capture.capture.workflow import (
        BrowserCheckResult,
        CaptureWorkflowResult,
        ConnectivityResult,
    )

    return CaptureWorkflowResult(
        browser=BrowserCheckResult(),
        connectivity=ConnectivityResult(ok=True, target_url=target_url),
    )


def _make_full_session_result(
    contaminated: bool = False,
    target_url: str = "http://10.0.0.1/",
) -> Any:
    from har_capture.capture.workflow import (
        BrowserCheckResult,
        CaptureWorkflowResult,
        ConnectivityResult,
        SessionCheckResult,
    )

    return CaptureWorkflowResult(
        browser=BrowserCheckResult(),
        connectivity=ConnectivityResult(ok=True, target_url=target_url),
        session=SessionCheckResult(contaminated=contaminated),
    )


def _make_capture_result(
    success: bool = True,
    sanitization_report: Any | None = None,
) -> Any:
    from har_capture.capture.workflow import (
        BrowserCheckResult,
        CaptureResult,
        CaptureWorkflowResult,
        ConnectivityResult,
        SessionCheckResult,
    )

    return CaptureWorkflowResult(
        browser=BrowserCheckResult(),
        connectivity=ConnectivityResult(ok=True, target_url="http://10.0.0.1/"),
        session=SessionCheckResult(contaminated=False),
        capture=CaptureResult(
            success=success,
            error=None if success else "boom",
            har_path=Path("/test/x.har"),
            sanitized_path=(Path("/test/x.sanitized.har") if sanitization_report else None),
            sanitization_report=sanitization_report,
        ),
    )


class TestCaptureCommand:
    """CliRunner tests with workflow phases mocked at the module boundary.

    Each test pins down one branch of ``capture()`` by shaping the
    phase return values.
    """

    def test_capture_happy_path_minimal_mode(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
        tmp_path: Path,
    ) -> None:
        """``--minimal`` skips connectivity + session phases."""
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "run_capture_phase",
            lambda **kwargs: _make_capture_result(success=True),
        )
        # Connectivity / session phases must NOT be called in minimal mode.
        monkeypatch.setattr(
            workflow_module,
            "check_connectivity_phase",
            lambda *a, **k: pytest.fail("connectivity must be skipped in minimal mode"),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_session_phase",
            lambda *a, **k: pytest.fail("session must be skipped in minimal mode"),
        )

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "10.0.0.1", "--minimal", "--output", str(tmp_path / "x.har"), "--patterns", "base"],
        )
        assert result.exit_code == 0
        assert "HAR CAPTURE" in result.output
        assert "CAPTURE COMPLETE" in result.output

    def test_capture_browser_install_declined_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """User declines browser install -> exit 1 with manual instructions."""
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(needs_install=True),
        )

        runner = CliRunner()
        # Answer "n" to the install prompt.
        result = runner.invoke(app, ["get", "10.0.0.1", "--minimal", "--patterns", "base"], input="n\n")
        assert result.exit_code == 1
        assert "Run manually" in result.output

    def test_capture_browser_install_accepted_succeeds(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """User accepts install, install succeeds -> capture proceeds."""
        from typer.testing import CliRunner

        from har_capture.capture import deps
        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(needs_install=True),
        )
        monkeypatch.setattr(
            workflow_module,
            "run_capture_phase",
            lambda **kwargs: _make_capture_result(success=True),
        )
        monkeypatch.setattr(deps, "install_browser", lambda b: True)

        runner = CliRunner()
        result = runner.invoke(app, ["get", "10.0.0.1", "--minimal", "--patterns", "base"], input="y\n")
        assert result.exit_code == 0
        assert "installed successfully" in result.output

    def test_capture_browser_install_failed_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """install_browser returns False -> exit 1 with failure message."""
        from typer.testing import CliRunner

        from har_capture.capture import deps
        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(needs_install=True),
        )
        monkeypatch.setattr(deps, "install_browser", lambda b: False)

        runner = CliRunner()
        result = runner.invoke(app, ["get", "10.0.0.1", "--minimal", "--patterns", "base"], input="y\n")
        assert result.exit_code == 1
        assert "Failed to install" in result.output

    def test_capture_connectivity_failure_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """``connectivity_ok=False`` -> exit 1 with the error from the phase."""
        from typer.testing import CliRunner

        from har_capture.capture.workflow import (
            BrowserCheckResult,
            CaptureWorkflowResult,
            ConnectivityResult,
        )
        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_connectivity_phase",
            lambda target, result: CaptureWorkflowResult(
                browser=BrowserCheckResult(),
                connectivity=ConnectivityResult(ok=False, error="connection refused"),
            ),
        )

        runner = CliRunner()
        result = runner.invoke(app, ["get", "10.0.0.1", "--patterns", "base"])
        assert result.exit_code == 1
        assert "connection refused" in result.output

    def test_capture_session_contamination_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """Live session detected -> exit 1 with the warning."""
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_connectivity_phase",
            lambda target, result: _make_connected_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_session_phase",
            lambda target_url, result: _make_full_session_result(
                contaminated=True,
                target_url=target_url,
            )._replace_session_message("device has live session"),
        )

        runner = CliRunner()
        # We need a properly-formed contaminated result.
        from har_capture.capture.workflow import (
            BrowserCheckResult,
            CaptureWorkflowResult,
            ConnectivityResult,
            SessionCheckResult,
        )

        monkeypatch.setattr(
            workflow_module,
            "check_session_phase",
            lambda target_url, r: CaptureWorkflowResult(
                browser=BrowserCheckResult(),
                connectivity=ConnectivityResult(ok=True, target_url=target_url),
                session=SessionCheckResult(contaminated=True, message="live session detected"),
            ),
        )

        result = runner.invoke(app, ["get", "10.0.0.1", "--patterns", "base"])
        assert result.exit_code == 1
        assert "live session detected" in result.output

    def test_capture_with_credentials_runs_auth_probe(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """``--username`` + ``--password`` -> auth probe runs pre-capture."""
        from typer.testing import CliRunner

        from har_capture.capture.workflow import (
            BrowserCheckResult,
            CaptureWorkflowResult,
            ConnectivityResult,
            ProbeResult,
            SessionCheckResult,
        )
        from har_capture.cli.main import app

        probe_calls: list[Any] = []

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_connectivity_phase",
            lambda target, result: _make_connected_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_session_phase",
            lambda target_url, r: _make_full_session_result(target_url=target_url),
        )

        def fake_probes(target_url: str, result: Any) -> Any:
            probe_calls.append(target_url)
            return CaptureWorkflowResult(
                browser=BrowserCheckResult(),
                connectivity=ConnectivityResult(ok=True, target_url=target_url),
                session=SessionCheckResult(contaminated=False),
                probes=ProbeResult(data={"auth_challenge": {"status_code": 401}}),
            )

        monkeypatch.setattr(workflow_module, "run_probes_phase", fake_probes)

        capture_kwargs: list[dict[str, Any]] = []

        def fake_capture(**kwargs: Any) -> Any:
            capture_kwargs.append(kwargs)
            return _make_capture_result(success=True)

        monkeypatch.setattr(workflow_module, "run_capture_phase", fake_capture)

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "10.0.0.1", "--username", "alice", "--password", "s3cret", "--patterns", "base"],
        )
        assert result.exit_code == 0
        assert probe_calls, "auth probe must run when credentials are provided"
        assert "Auth status: 401" in result.output
        # Credentials threaded through to the capture phase.
        assert capture_kwargs[0]["http_credentials"] == {
            "username": "alice",
            "password": "s3cret",
        }

    def test_capture_failure_exits_with_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """``capture_success=False`` -> exit 1 with the phase error."""
        from typer.testing import CliRunner

        from har_capture.cli.main import app

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "run_capture_phase",
            lambda **kwargs: _make_capture_result(success=False),
        )

        runner = CliRunner()
        result = runner.invoke(app, ["get", "10.0.0.1", "--minimal", "--patterns", "base"])
        assert result.exit_code == 1
        assert "Capture failed: boom" in result.output

    def test_capture_with_sanitization_report_runs_review(
        self,
        monkeypatch: pytest.MonkeyPatch,
        workflow_module: Any,
    ) -> None:
        """Non-empty sanitization_report triggers the post-capture review."""
        from types import SimpleNamespace

        from typer.testing import CliRunner

        from har_capture.cli.main import app

        report = SimpleNamespace(flagged=[], salt=True, total_user_redacted=0)

        monkeypatch.setattr(
            workflow_module,
            "check_browser_phase",
            lambda b: _make_browser_result(),
        )
        monkeypatch.setattr(
            workflow_module,
            "run_capture_phase",
            lambda **kwargs: _make_capture_result(
                success=True,
                sanitization_report=report,
            ),
        )

        runner = CliRunner()
        result = runner.invoke(app, ["get", "10.0.0.1", "--minimal", "--patterns", "base"])
        # The report is empty so review short-circuits with the
        # "No suspicious values found" message.
        assert result.exit_code == 0
        assert "No suspicious values found" in result.output
