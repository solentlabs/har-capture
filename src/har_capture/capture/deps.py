"""Playwright and browser dependency management.

This module provides functions to check and install Playwright and
browser system dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

# Mapping from Playwright browser name to executable relative path
_BROWSER_EXECUTABLES: dict[str, str] = {
    "chromium": "chrome-linux64/chrome",
    "firefox": "firefox/firefox",
    "webkit": "minibrowser-wpe/MiniBrowser",
}


def _get_browser_executable(browser: str = "chromium") -> Path | None:
    """Resolve the expected browser executable path from Playwright's manifest.

    Reads browsers.json from the Playwright package to determine the
    expected revision, then checks the standard cache directory.

    Args:
        browser: Browser name ("chromium", "firefox", "webkit")

    Returns:
        Path to the expected executable, or None if resolution fails
    """
    try:
        import playwright

        pkg_dir = Path(playwright.__file__).parent / "driver" / "package"
    except (ImportError, AttributeError):
        return None

    browsers_json = pkg_dir / "browsers.json"
    if not browsers_json.exists():
        return None

    data = json.loads(browsers_json.read_text())
    for entry in data.get("browsers", []):
        if entry.get("name") == browser:
            revision = entry.get("revision")
            if not revision:
                return None
            cache_dir = Path(
                os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "") or Path.home() / ".cache" / "ms-playwright"
            )
            rel_path = _BROWSER_EXECUTABLES.get(browser)
            if not rel_path:
                return None
            return cache_dir / f"{browser}-{revision}" / rel_path

    return None


def check_playwright() -> bool:
    """Check if Playwright is installed.

    Returns:
        True if Playwright is available
    """
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


def check_browser_installed(browser: str = "chromium") -> bool:
    """Check if Playwright browser is installed.

    Verifies the actual browser executable exists on disk by reading
    Playwright's browsers.json manifest and checking the expected path.
    Falls back to a dry-run heuristic if the manifest is unavailable.

    Args:
        browser: Browser to check ("chromium", "firefox", "webkit")

    Returns:
        True if browser is installed and ready
    """
    if not check_playwright():
        return False

    # Primary check: verify the executable exists on disk
    try:
        executable = _get_browser_executable(browser)
        if executable is not None:
            return executable.exists()
    except Exception:
        _LOGGER.debug("Failed to resolve browser executable path, falling back to dry-run")

    # Fallback: dry-run check (unreliable — always returns rc=0)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run", browser],
            capture_output=True,
            text=True,
            check=False,
        )
        return "already installed" in result.stdout.lower()
    except Exception:
        return False


def install_browser(browser: str = "chromium") -> bool:
    """Install Playwright browser.

    Args:
        browser: Browser to install ("chromium", "firefox", "webkit")

    Returns:
        True if installation succeeded
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", browser],
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def install_playwright() -> bool:
    """Install Playwright and Chromium browser automatically.

    Returns:
        True if installation succeeded
    """
    _LOGGER.info("Installing Playwright...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "playwright"],
            check=True,
            capture_output=True,
        )
        _LOGGER.info("Installing Chromium browser...")
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
            capture_output=True,
        )
        _LOGGER.info("Installation complete!")
        return True
    except subprocess.CalledProcessError as e:
        _LOGGER.error("Installation failed: %s", e)
        return False


# Linux browser dependencies (apt packages)
LINUX_BROWSER_DEPS: list[str] = [
    "libnspr4",
    "libnss3",
    "libatk1.0-0",
    "libatk-bridge2.0-0",
    "libcups2",
    "libdrm2",
    "libxkbcommon0",
    "libxcomposite1",
    "libxdamage1",
    "libxfixes3",
    "libxrandr2",
    "libgbm1",
    "libpango-1.0-0",
    "libcairo2",
    "libasound2t64",
]


def install_browser_deps() -> bool:
    """Install browser system dependencies (requires sudo on Linux).

    Returns:
        True if installation succeeded
    """
    if platform.system() != "Linux":
        return True  # Not needed on macOS/Windows

    _LOGGER.info("Installing browser dependencies...")
    try:
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y"] + LINUX_BROWSER_DEPS,
            check=False,
        )
        return result.returncode == 0
    except Exception as e:
        _LOGGER.error("Failed: %s", e)
        return False
