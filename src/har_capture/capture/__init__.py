"""Browser-based HAR capture using Playwright.

This module provides Playwright-based browser capture for HAR files.
Requires the 'capture' optional dependency: pip install har-capture[capture]

Exports:
    - capture_device_har: Main capture function
    - CaptureResult: Result dataclass from capture
    - CaptureOptions: Options for filtering (fonts, images, media)
    - check_playwright: Check if Playwright is available
    - install_playwright: Install Playwright and browser
"""

from __future__ import annotations

from har_capture.capture.browser import (
    CaptureOptions,
    CaptureResult,
    capture_device_har,
    filter_and_compress_har,
)
from har_capture.capture.connectivity import (
    check_basic_auth,
    check_device_connectivity,
)
from har_capture.capture.deps import (
    check_browser_installed,
    check_playwright,
    install_browser,
    install_browser_deps,
    install_playwright,
)

__all__ = [
    # Core capture
    "capture_device_har",
    "filter_and_compress_har",
    "CaptureResult",
    "CaptureOptions",
    # Connectivity checks
    "check_device_connectivity",
    "check_basic_auth",
    # Dependency management
    "check_playwright",
    "check_browser_installed",
    "install_playwright",
    "install_browser",
    "install_browser_deps",
]
