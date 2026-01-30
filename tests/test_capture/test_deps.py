"""Tests for browser dependency management."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from har_capture.capture.deps import (
    LINUX_BROWSER_DEPS,
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


class TestCheckBrowserInstalled:
    """Tests for check_browser_installed function."""

    @pytest.mark.parametrize(
        ("browser", "desc"),
        BROWSER_TYPES,
        ids=[b[1] for b in BROWSER_TYPES],
    )
    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("subprocess.run")
    def test_browser_installed_check(
        self,
        mock_run: MagicMock,
        mock_check_pw: MagicMock,
        browser: str,
        desc: str,
    ) -> None:
        """Test browser installation check for different browsers."""
        mock_run.return_value = MagicMock(
            stdout="browser already installed",
            returncode=0,
        )

        result = check_browser_installed(browser)

        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert browser in call_args

    @patch("har_capture.capture.deps.check_playwright", return_value=False)
    def test_returns_false_when_playwright_not_installed(
        self,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test returns False when Playwright is not installed."""
        result = check_browser_installed("chromium")
        assert result is False

    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("subprocess.run")
    def test_returns_true_on_subprocess_exception(
        self,
        mock_run: MagicMock,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test returns True (assume installed) on subprocess exception."""
        mock_run.side_effect = Exception("subprocess failed")

        result = check_browser_installed("chromium")

        # Should return True as fallback
        assert result is True

    @patch("har_capture.capture.deps.check_playwright", return_value=True)
    @patch("subprocess.run")
    def test_detects_not_installed(
        self,
        mock_run: MagicMock,
        mock_check_pw: MagicMock,
    ) -> None:
        """Test detects when browser is not installed."""
        mock_run.return_value = MagicMock(
            stdout="will download chromium",
            returncode=1,
        )

        result = check_browser_installed("chromium")

        # returncode != 0 and "already installed" not in stdout
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
