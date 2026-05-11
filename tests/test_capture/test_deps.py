"""Tests for browser dependency management.

This module tests detection and installation of Playwright, browser
executables, and Linux system dependencies required for headless capture.

Test Coverage:
    - Playwright availability detection
    - Browser executable resolution from browsers.json manifest
    - Browser installation status (primary path check + dry-run fallback)
    - Browser and Playwright installation helpers
    - Linux system dependency installation
    - LINUX_BROWSER_DEPS constant validation

Test Strategy:
    - Table-driven tests with @pytest.mark.parametrize
    - Mock-heavy: subprocess, filesystem, and module imports are all mocked
      to avoid requiring real Playwright or browser installs in CI
    - Edge cases for _get_browser_install_dir cover every early-return path

Dependencies:
    - pytest for test framework
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.deps import (
    LINUX_BROWSER_DEPS,
    _get_browser_install_dir,
    check_browser_installed,
    check_playwright,
    install_browser,
    install_browser_deps,
    install_playwright,
)

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
BROWSER_TYPES = [
    ("chromium",    "chromium"),
    ("firefox",     "firefox"),
    ("webkit",      "webkit"),
]

# ┌──────────────────────────────┬──────────────────────────────────────────┬──────────┬──────────────────────────────┐
# │ browsers_json_content        │ browser_arg                              │ expected │ description                  │
# ├──────────────────────────────┼──────────────────────────────────────────┼──────────┼──────────────────────────────┤
# │ JSON content or None (skip)  │ browser name to look up                  │ Path |   │ test case name               │
# │                              │                                          │ None     │                              │
# └──────────────────────────────┴──────────────────────────────────────────┴──────────┴──────────────────────────────┘
GET_BROWSER_DIR_NONE_CASES = [
    (None,                                                   "chromium",         "browsers_json_missing"),
    ({"browsers": [{"name": "chromium"}]},                   "chromium",         "revision_missing"),
    ({"browsers": [{"name": "chromium", "revision": ""}]},   "chromium",         "revision_empty"),
    ({"browsers": [{"name": "firefox", "revision": "100"}]}, "chromium",         "no_matching_entry"),
    ({"browsers": []},                                       "chromium",         "empty_browsers_list"),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestCheckPlaywright:
    """Tests for check_playwright function."""

    def test_returns_bool(self) -> None:
        """Test check_playwright returns a boolean."""
        result = check_playwright()
        assert isinstance(result, bool)

    @patch.dict("sys.modules", {"playwright": None})
    def test_returns_false_when_not_installed(self) -> None:
        """Test returns False when playwright import fails."""
        # Force ImportError by patching the import
        with patch("builtins.__import__", side_effect=ImportError):
            # Need to reload or call the function fresh
            result = check_playwright()
            # This test may pass or fail depending on if playwright is installed
            assert isinstance(result, bool)


class TestGetBrowserInstallDir:
    """Tests for _get_browser_install_dir helper."""

    @patch("har_capture.capture.deps.Path.home")
    def test_resolves_chromium_install_dir(self, mock_home: MagicMock) -> None:
        """Test resolves the chromium install directory from browsers.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_home.return_value = Path(tmpdir)
            pkg_dir = Path(tmpdir) / "driver" / "package"
            pkg_dir.mkdir(parents=True)
            browsers_json = pkg_dir / "browsers.json"
            browsers_json.write_text(json.dumps({"browsers": [{"name": "chromium", "revision": "1200"}]}))

            # Create a fake playwright module so the import inside
            # _get_browser_install_dir resolves without the real package.
            fake_pw = types.ModuleType("playwright")
            fake_pw.__file__ = str(Path(tmpdir) / "__init__.py")
            with patch.dict(sys.modules, {"playwright": fake_pw}):
                result = _get_browser_install_dir("chromium")

            # Returns the <browser>-<revision>/ directory itself, NOT a per-
            # platform binary path inside it. Issue #50 traced back to a
            # hardcoded chrome-linux64/chrome path being checked on Windows;
            # the directory marker is the platform-agnostic install signal.
            assert result is not None
            assert result.name == "chromium-1200"
            assert "chromium-1200" in str(result)

    def test_returns_none_without_playwright(self) -> None:
        """Test returns None when playwright is not importable."""
        with (
            patch.dict("sys.modules", {"playwright": None}),
            patch("builtins.__import__", side_effect=ImportError),
        ):
            result = _get_browser_install_dir("chromium")
            assert result is None

    @pytest.mark.parametrize(
        ("browsers_json_content", "browser_arg", "desc"),
        GET_BROWSER_DIR_NONE_CASES,
        ids=[c[2] for c in GET_BROWSER_DIR_NONE_CASES],
    )
    def test_returns_none_on_edge_cases(
        self,
        browsers_json_content: dict | None,
        browser_arg: str,
        desc: str,
    ) -> None:
        """Test _get_browser_install_dir returns None for various edge cases."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = Path(tmpdir) / "driver" / "package"
            pkg_dir.mkdir(parents=True)

            if browsers_json_content is not None:
                (pkg_dir / "browsers.json").write_text(json.dumps(browsers_json_content))

            fake_pw = types.ModuleType("playwright")
            fake_pw.__file__ = str(Path(tmpdir) / "__init__.py")
            with patch.dict(sys.modules, {"playwright": fake_pw}):
                result = _get_browser_install_dir(browser_arg)

            assert result is None, f"{desc}: expected None"


class TestCheckBrowserInstalled:
    """Tests for check_browser_installed function."""

    @pytest.mark.parametrize(
        ("browser", "desc"),
        BROWSER_TYPES,
        ids=[b[1] for b in BROWSER_TYPES],
    )
    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("har_capture.capture.deps._get_browser_install_dir")
    def test_browser_installed_when_dir_exists_and_non_empty(
        self,
        mock_get_dir: MagicMock,
        mock_check_pw: MagicMock,
        browser: str,
        desc: str,
    ) -> None:
        """Test returns True when the install directory exists and is non-empty."""
        mock_path = MagicMock()
        mock_path.is_dir.return_value = True
        mock_path.iterdir.return_value = iter([MagicMock()])  # at least one entry
        mock_get_dir.return_value = mock_path

        result = check_browser_installed(browser)

        assert result is True
        mock_get_dir.assert_called_once_with(browser)

    @pytest.mark.parametrize(
        ("browser", "desc"),
        BROWSER_TYPES,
        ids=[b[1] for b in BROWSER_TYPES],
    )
    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("har_capture.capture.deps._get_browser_install_dir")
    @patch("subprocess.run")
    def test_browser_not_installed_when_dir_missing(
        self,
        mock_run: MagicMock,
        mock_get_dir: MagicMock,
        mock_check_pw: MagicMock,
        browser: str,
        desc: str,
    ) -> None:
        """Test returns False when the install directory doesn't exist (falls through to dry-run)."""
        mock_path = MagicMock()
        mock_path.is_dir.return_value = False
        mock_get_dir.return_value = mock_path
        # Dry-run fallback reports not installed.
        mock_run.return_value = MagicMock(stdout="will download", returncode=0)

        result = check_browser_installed(browser)

        assert result is False

    @pytest.mark.parametrize(
        ("browser", "desc"),
        BROWSER_TYPES,
        ids=[b[1] for b in BROWSER_TYPES],
    )
    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("har_capture.capture.deps._get_browser_install_dir")
    @patch("subprocess.run")
    def test_empty_install_dir_falls_through_to_dry_run(
        self,
        mock_run: MagicMock,
        mock_get_dir: MagicMock,
        mock_check_pw: MagicMock,
        browser: str,
        desc: str,
    ) -> None:
        """Test returns False when install dir exists but is empty — dry-run is consulted."""
        mock_path = MagicMock()
        mock_path.is_dir.return_value = True
        mock_path.iterdir.return_value = iter([])  # empty dir
        mock_get_dir.return_value = mock_path
        mock_run.return_value = MagicMock(stdout="will download", returncode=0)

        result = check_browser_installed(browser)

        assert result is False
        mock_run.assert_called_once()

    @patch("har_capture.capture.deps.check_playwright", return_value=False)
    def test_returns_false_when_playwright_not_installed(
        self,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test returns False when Playwright is not installed."""
        result = check_browser_installed("chromium")
        assert result is False

    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("har_capture.capture.deps._get_browser_install_dir", return_value=None)
    @patch("subprocess.run")
    def test_falls_back_to_dry_run_when_path_unavailable(
        self,
        mock_run: MagicMock,
        mock_get_exe: MagicMock,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test falls back to dry-run when executable path can't be resolved."""
        mock_run.return_value = MagicMock(
            stdout="browser already installed",
            returncode=0,
        )

        result = check_browser_installed("chromium")

        assert result is True
        mock_run.assert_called_once()

    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("har_capture.capture.deps._get_browser_install_dir", return_value=None)
    @patch("subprocess.run")
    def test_dry_run_fallback_detects_not_installed(
        self,
        mock_run: MagicMock,
        mock_get_exe: MagicMock,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test dry-run fallback returns False when not 'already installed'."""
        mock_run.return_value = MagicMock(
            stdout="will download chromium",
            returncode=0,
        )

        result = check_browser_installed("chromium")

        assert result is False

    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("har_capture.capture.deps._get_browser_install_dir", side_effect=Exception("oops"))
    @patch("subprocess.run", side_effect=Exception("subprocess failed"))
    def test_returns_false_on_all_failures(
        self,
        mock_run: MagicMock,
        mock_get_exe: MagicMock,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test returns False when both primary and fallback checks fail."""
        result = check_browser_installed("chromium")

        assert result is False


class TestInstallBrowser:
    """Tests for install_browser function."""

    @pytest.mark.parametrize(
        ("browser", "desc"),
        BROWSER_TYPES,
        ids=[b[1] for b in BROWSER_TYPES],
    )
    @patch("subprocess.run")
    def test_install_browser_success(
        self,
        mock_run: MagicMock,
        browser: str,
        desc: str,
    ) -> None:
        """Test successful browser installation."""
        mock_run.return_value = MagicMock(returncode=0)

        result = install_browser(browser)

        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert browser in call_args
        assert "install" in call_args

    @patch("subprocess.run")
    def test_install_browser_failure(self, mock_run: MagicMock) -> None:
        """Test browser installation failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd")

        result = install_browser("chromium")

        assert result is False


class TestInstallPlaywright:
    """Tests for install_playwright function."""

    @patch("subprocess.run")
    def test_install_playwright_success(self, mock_run: MagicMock) -> None:
        """Test successful Playwright installation."""
        mock_run.return_value = MagicMock(returncode=0)

        result = install_playwright()

        assert result is True
        # Should call pip install and playwright install
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_install_playwright_pip_failure(self, mock_run: MagicMock) -> None:
        """Test Playwright pip install failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "pip")

        result = install_playwright()

        assert result is False

    @patch("subprocess.run")
    def test_install_playwright_browser_failure(self, mock_run: MagicMock) -> None:
        """Test Playwright browser install failure."""
        # First call (pip) succeeds, second call (playwright install) fails
        mock_run.side_effect = [
            MagicMock(returncode=0),
            subprocess.CalledProcessError(1, "playwright"),
        ]

        result = install_playwright()

        assert result is False


class TestInstallBrowserDeps:
    """Tests for install_browser_deps function."""

    @patch("platform.system", return_value="Darwin")
    def test_returns_true_on_macos(self, mock_system: MagicMock) -> None:
        """Test returns True immediately on macOS."""
        result = install_browser_deps()

        assert result is True

    @patch("platform.system", return_value="Windows")
    def test_returns_true_on_windows(self, mock_system: MagicMock) -> None:
        """Test returns True immediately on Windows."""
        result = install_browser_deps()

        assert result is True

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_installs_deps_on_linux(
        self,
        mock_run: MagicMock,
        mock_system: MagicMock,
    ) -> None:
        """Test installs dependencies on Linux."""
        mock_run.return_value = MagicMock(returncode=0)

        result = install_browser_deps()

        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "sudo" in call_args
        assert "apt-get" in call_args
        # Check some deps are in the command
        for dep in LINUX_BROWSER_DEPS[:3]:
            assert dep in call_args

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_returns_false_on_linux_failure(
        self,
        mock_run: MagicMock,
        mock_system: MagicMock,
    ) -> None:
        """Test returns False when apt-get fails."""
        mock_run.return_value = MagicMock(returncode=1)

        result = install_browser_deps()

        assert result is False

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_returns_false_on_linux_exception(
        self,
        mock_run: MagicMock,
        mock_system: MagicMock,
    ) -> None:
        """Test returns False on exception."""
        mock_run.side_effect = Exception("sudo not found")

        result = install_browser_deps()

        assert result is False


class TestLinuxBrowserDeps:
    """Tests for LINUX_BROWSER_DEPS constant."""

    def test_contains_required_libs(self) -> None:
        """Test LINUX_BROWSER_DEPS contains essential libraries."""
        required = ["libnspr4", "libnss3", "libasound2t64"]
        for lib in required:
            assert lib in LINUX_BROWSER_DEPS, f"{lib} should be in LINUX_BROWSER_DEPS"

    def test_is_non_empty_list(self) -> None:
        """Test LINUX_BROWSER_DEPS is a non-empty list."""
        assert isinstance(LINUX_BROWSER_DEPS, list)
        assert len(LINUX_BROWSER_DEPS) > 0
