"""Playwright and browser dependency management.

This module provides functions to check and install Playwright and
browser system dependencies.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys

_LOGGER = logging.getLogger(__name__)


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

    Args:
        browser: Browser to check ("chromium", "firefox", "webkit")

    Returns:
        True if browser is installed and ready
    """
    if not check_playwright():
        return False

    try:
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run", browser],
            capture_output=True,
            text=True,
            check=False,
        )
        # If dry-run says nothing to install, browser is installed
        return "already installed" in result.stdout.lower() or result.returncode == 0
    except Exception:
        # Fall back to trying to launch - will fail fast if not installed
        return True  # Assume installed, let launch fail with clear error


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
