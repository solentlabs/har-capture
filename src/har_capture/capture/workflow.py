"""Capture workflow orchestration.

This module provides the business logic for the capture workflow,
separated from CLI concerns for testability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# =============================================================================
# Phase-specific result types
# =============================================================================


@dataclass
class BrowserCheckResult:
    """Result of browser installation check.

    Attributes:
        browser: Browser name (chromium, firefox, webkit)
        needs_install: True if browser needs to be installed
    """

    browser: str = "chromium"
    needs_install: bool = False


@dataclass
class ConnectivityResult:
    """Result of connectivity check.

    Attributes:
        ok: True if target is reachable
        scheme: Detected scheme (http/https)
        target_url: Full URL to target
        error: Error message if not reachable
    """

    ok: bool = False
    scheme: str = "http"
    target_url: str = ""
    error: str | None = None


@dataclass
class AuthResult:
    """Result of authentication detection.

    Attributes:
        requires_basic_auth: True if HTTP Basic Auth is required
        realm: Realm name if Basic Auth is required
    """

    requires_basic_auth: bool = False
    realm: str | None = None


@dataclass
class CaptureResult:
    """Result of the capture operation.

    Attributes:
        success: True if capture completed successfully
        error: Error message if capture failed
        har_path: Path to raw HAR file
        compressed_path: Path to compressed HAR file
        sanitized_path: Path to sanitized HAR file
        stats: Capture statistics
    """

    success: bool = False
    error: str | None = None
    har_path: Path | None = None
    compressed_path: Path | None = None
    sanitized_path: Path | None = None
    stats: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Workflow context - composes phase results
# =============================================================================


@dataclass
class CaptureWorkflowResult:
    """Result of a capture workflow execution.

    Composes results from each phase. Check the phase field to determine
    how far the workflow progressed.

    Attributes:
        phase: Current phase of the workflow
        browser: Result of browser check phase
        connectivity: Result of connectivity check phase (None if not reached)
        auth: Result of auth detection phase (None if not reached)
        capture: Result of capture phase (None if not reached)
    """

    phase: str = "init"
    browser: BrowserCheckResult = field(default_factory=BrowserCheckResult)
    connectivity: ConnectivityResult | None = None
    auth: AuthResult | None = None
    capture: CaptureResult | None = None

    # Convenience properties for backwards compatibility and cleaner access
    @property
    def needs_browser_install(self) -> bool:
        """True if browser needs installation."""
        return self.browser.needs_install

    @property
    def connectivity_ok(self) -> bool:
        """True if target is reachable."""
        return self.connectivity.ok if self.connectivity else False

    @property
    def connectivity_error(self) -> str | None:
        """Error message if not reachable."""
        return self.connectivity.error if self.connectivity else None

    @property
    def target_url(self) -> str:
        """Full URL to target."""
        return self.connectivity.target_url if self.connectivity else ""

    @property
    def scheme(self) -> str:
        """Detected scheme (http/https)."""
        return self.connectivity.scheme if self.connectivity else "http"

    @property
    def requires_basic_auth(self) -> bool:
        """True if HTTP Basic Auth is required."""
        return self.auth.requires_basic_auth if self.auth else False

    @property
    def auth_realm(self) -> str | None:
        """Realm name if Basic Auth is required."""
        return self.auth.realm if self.auth else None

    @property
    def capture_success(self) -> bool:
        """True if capture completed successfully."""
        return self.capture.success if self.capture else False

    @property
    def capture_error(self) -> str | None:
        """Error message if capture failed."""
        return self.capture.error if self.capture else None

    @property
    def har_path(self) -> Path | None:
        """Path to raw HAR file."""
        return self.capture.har_path if self.capture else None

    @property
    def compressed_path(self) -> Path | None:
        """Path to compressed HAR file."""
        return self.capture.compressed_path if self.capture else None

    @property
    def sanitized_path(self) -> Path | None:
        """Path to sanitized HAR file."""
        return self.capture.sanitized_path if self.capture else None

    @property
    def stats(self) -> dict[str, Any]:
        """Capture statistics."""
        return self.capture.stats if self.capture else {}


# =============================================================================
# Phase functions
# =============================================================================


def check_browser_phase(browser: str = "chromium") -> CaptureWorkflowResult:
    """Check if browser is installed.

    Args:
        browser: Browser to check (chromium, firefox, webkit)

    Returns:
        CaptureWorkflowResult with browser check status
    """
    from har_capture.capture.deps import check_browser_installed

    browser_result = BrowserCheckResult(
        browser=browser,
        needs_install=not check_browser_installed(browser),
    )
    return CaptureWorkflowResult(phase="browser_check", browser=browser_result)


def check_connectivity_phase(
    target: str,
    result: CaptureWorkflowResult | None = None,
) -> CaptureWorkflowResult:
    """Check connectivity to target.

    Args:
        target: URL, hostname, or IP to check
        result: Existing result to update, or None to create new

    Returns:
        CaptureWorkflowResult with connectivity status
    """
    from har_capture.capture.connectivity import (
        _parse_target,
        check_device_connectivity,
    )

    if result is None:
        result = CaptureWorkflowResult()
    result.phase = "connectivity_check"

    reachable, scheme, error = check_device_connectivity(target)

    target_url = ""
    if reachable:
        host, _ = _parse_target(target)
        target_url = f"{scheme}://{host}/"

    result.connectivity = ConnectivityResult(
        ok=reachable,
        scheme=scheme,
        target_url=target_url,
        error=error,
    )

    return result


def check_auth_phase(
    target_url: str,
    result: CaptureWorkflowResult | None = None,
) -> CaptureWorkflowResult:
    """Check if target requires Basic Auth.

    Args:
        target_url: Full URL to check
        result: Existing result to update, or None to create new

    Returns:
        CaptureWorkflowResult with auth detection status
    """
    from har_capture.capture.connectivity import check_basic_auth

    if result is None:
        result = CaptureWorkflowResult()
    result.phase = "auth_check"

    requires_auth, realm = check_basic_auth(target_url)
    result.auth = AuthResult(requires_basic_auth=requires_auth, realm=realm)

    return result


def run_capture_phase(
    target: str,
    output: Path | None = None,
    browser: str = "chromium",
    http_credentials: dict[str, str] | None = None,
    sanitize: bool = True,
    compress: bool = True,
    keep_raw: bool = False,
    include_fonts: bool = False,
    include_images: bool = False,
    include_media: bool = False,
    headless: bool = False,
    timeout: int | None = None,
    result: CaptureWorkflowResult | None = None,
) -> CaptureWorkflowResult:
    """Run the actual capture.

    Args:
        target: URL, hostname, or IP to capture
        output: Output HAR filename
        browser: Browser to use
        http_credentials: Optional Basic Auth credentials
        sanitize: Whether to sanitize the HAR
        compress: Whether to compress the HAR
        keep_raw: Whether to keep the raw HAR
        include_fonts: Include font files
        include_images: Include image files
        include_media: Include media files
        headless: Run browser in headless mode
        timeout: Timeout in seconds (None = wait for user to close)
        result: Existing result to update, or None to create new

    Returns:
        CaptureWorkflowResult with capture status
    """
    from har_capture.capture.browser import capture_device_har

    if result is None:
        result = CaptureWorkflowResult()
    result.phase = "capture"

    capture_result = capture_device_har(
        ip=target,
        output=output,
        browser=browser,
        http_credentials=http_credentials,
        sanitize=sanitize,
        compress=compress,
        keep_raw=keep_raw,
        include_fonts=include_fonts,
        include_images=include_images,
        include_media=include_media,
        headless=headless,
        timeout=timeout,
    )

    result.capture = CaptureResult(
        success=capture_result.success,
        error=capture_result.error,
        har_path=capture_result.har_path,
        compressed_path=capture_result.compressed_path,
        sanitized_path=capture_result.sanitized_path,
        stats=capture_result.stats or {},
    )

    if capture_result.success:
        result.phase = "complete"

    return result


def run_capture_workflow(
    target: str,
    output: Path | None = None,
    browser: str = "chromium",
    http_credentials: dict[str, str] | None = None,
    sanitize: bool = True,
    compress: bool = True,
    keep_raw: bool = False,
    include_fonts: bool = False,
    include_images: bool = False,
    include_media: bool = False,
    headless: bool = False,
    timeout: int | None = None,
    skip_browser_check: bool = False,
) -> CaptureWorkflowResult:
    """Run the complete capture workflow.

    This function orchestrates all phases of the capture workflow:
    1. Check if browser is installed
    2. Check connectivity to target
    3. Detect authentication requirements
    4. Run the capture

    Args:
        target: URL, hostname, or IP to capture
        output: Output HAR filename
        browser: Browser to use (chromium, firefox, webkit)
        http_credentials: Optional Basic Auth credentials
        sanitize: Whether to sanitize the HAR
        compress: Whether to compress the HAR
        keep_raw: Whether to keep the raw HAR
        include_fonts: Include font files
        include_images: Include image files
        include_media: Include media files
        headless: Run browser in headless mode
        timeout: Timeout in seconds (None = wait for user to close)
        skip_browser_check: Skip browser installation check

    Returns:
        CaptureWorkflowResult with workflow status

    Example:
        >>> result = run_capture_workflow("192.168.1.1", headless=True, timeout=10)
        >>> if result.needs_browser_install:
        ...     install_browser(result.browser.browser)
        ...     result = run_capture_workflow(...)  # retry
        >>> if not result.connectivity_ok:
        ...     print(f"Cannot connect: {result.connectivity_error}")
        >>> if result.requires_basic_auth and not http_credentials:
        ...     # Prompt user for credentials
        ...     pass
        >>> if result.capture_success:
        ...     print(f"Captured: {result.sanitized_path}")
    """
    # Phase 1: Browser check
    if not skip_browser_check:
        result = check_browser_phase(browser)
        if result.needs_browser_install:
            return result
    else:
        result = CaptureWorkflowResult(browser=BrowserCheckResult(browser=browser, needs_install=False))

    # Phase 2: Connectivity check
    result = check_connectivity_phase(target, result)
    if not result.connectivity_ok:
        return result

    # Phase 3: Auth detection
    result = check_auth_phase(result.target_url, result)
    if result.requires_basic_auth and not http_credentials:
        # Return early so CLI can prompt for credentials
        return result

    # Phase 4: Capture
    result = run_capture_phase(
        target=target,
        output=output,
        browser=browser,
        http_credentials=http_credentials,
        sanitize=sanitize,
        compress=compress,
        keep_raw=keep_raw,
        include_fonts=include_fonts,
        include_images=include_images,
        include_media=include_media,
        headless=headless,
        timeout=timeout,
        result=result,
    )

    return result
