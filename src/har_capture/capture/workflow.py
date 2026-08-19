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
class SessionCheckResult:
    """Result of pre-capture session contamination check.

    Attributes:
        contaminated: True if device has a live session (no login required)
        message: Warning message if contaminated
    """

    contaminated: bool = False
    message: str | None = None


@dataclass
class ProbeResult:
    """Result of pre-capture diagnostic probes.

    Attributes:
        data: Probe data dict from ``run_probes()``
    """

    data: dict[str, Any] = field(default_factory=dict)


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
        sanitization_report: Report from sanitization (for interactive review)
        completeness: What the capture contains and any gaps found in it
        downloads: Browser downloads saved during the session (raw device
            output — NOT sanitized)
    """

    success: bool = False
    error: str | None = None
    har_path: Path | None = None
    compressed_path: Path | None = None
    sanitized_path: Path | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    sanitization_report: Any | None = None  # SanitizationReport when available
    completeness: Any | None = None  # CaptureCompletenessReport when available
    downloads: list[dict[str, Any]] = field(default_factory=list)


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
    session: SessionCheckResult | None = None
    probes: ProbeResult | None = None
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
    def session_contaminated(self) -> bool:
        """True if target has a live session (no login required)."""
        return self.session.contaminated if self.session else False

    @property
    def session_message(self) -> str | None:
        """Warning message if session is contaminated."""
        return self.session.message if self.session else None

    @property
    def probe_data(self) -> dict[str, Any]:
        """Probe data dict from pre-capture probes."""
        return self.probes.data if self.probes else {}

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
    def downloads(self) -> list[dict[str, Any]]:
        """Browser downloads saved during the session (NOT sanitized)."""
        return self.capture.downloads if self.capture else []

    @property
    def stats(self) -> dict[str, Any]:
        """Capture statistics."""
        return self.capture.stats if self.capture else {}

    @property
    def completeness(self) -> Any | None:
        """Capture-completeness report (None if capture did not run)."""
        return self.capture.completeness if self.capture else None


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
        target: URL with scheme (http:// or https://)
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


def check_session_phase(
    target_url: str,
    result: CaptureWorkflowResult | None = None,
) -> CaptureWorkflowResult:
    """Check for session contamination before capture.

    Detects whether the target has a live session that would cause the
    capture to miss the login flow.

    Args:
        target_url: Full URL to check
        result: Existing result to update, or None to create new

    Returns:
        CaptureWorkflowResult with session check status
    """
    from har_capture.capture.connectivity import check_session_contamination

    if result is None:
        result = CaptureWorkflowResult()
    result.phase = "session_check"

    contaminated, message = check_session_contamination(target_url)
    result.session = SessionCheckResult(contaminated=contaminated, message=message)

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


def run_probes_phase(
    target_url: str,
    timeout: int = 10,
    result: CaptureWorkflowResult | None = None,
) -> CaptureWorkflowResult:
    """Run pre-capture diagnostic probes.

    Args:
        target_url: Full URL to probe
        timeout: Timeout for HTTP probes
        result: Existing result to update, or None to create new

    Returns:
        CaptureWorkflowResult with probe data
    """
    from har_capture.capture.probes import run_probes

    if result is None:
        result = CaptureWorkflowResult()
    result.phase = "probes"

    probe_data = run_probes(target_url, timeout=timeout)
    result.probes = ProbeResult(data=probe_data)

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
    interactive: bool = True,
    result: CaptureWorkflowResult | None = None,
    custom_patterns: str | dict[str, Any] | None = None,
    wait_for_data: bool = True,
    target_url: str | None = None,
    page_load_strategy: str = "networkidle",
) -> CaptureWorkflowResult:
    """Run the actual capture.

    Args:
        target: URL with scheme (http:// or https://)
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
        interactive: Flag suspicious values for interactive review
        result: Existing result to update, or None to create new
        custom_patterns: Domain pattern name, file path, or pre-loaded dict
        wait_for_data: Wait for async data fetches before navigating
        target_url: Pre-computed URL from connectivity check (skips dup check)
        page_load_strategy: Playwright wait_until for page.goto

    Returns:
        CaptureWorkflowResult with capture status
    """
    from har_capture.capture.browser import capture_device_har

    if result is None:
        result = CaptureWorkflowResult()
    result.phase = "capture"

    probe_data = result.probe_data or None

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
        interactive=interactive,
        probes=probe_data,
        custom_patterns=custom_patterns,
        wait_for_data=wait_for_data,
        target_url=target_url,
        page_load_strategy=page_load_strategy,
    )

    result.capture = CaptureResult(
        success=capture_result.success,
        error=capture_result.error,
        har_path=capture_result.har_path,
        compressed_path=capture_result.compressed_path,
        sanitized_path=capture_result.sanitized_path,
        stats=capture_result.stats or {},
        sanitization_report=capture_result.sanitization_report,
        completeness=capture_result.completeness,
        downloads=capture_result.downloads,
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
    wait_for_data: bool = True,
    skip_probes: bool = False,
    skip_session_check: bool = False,
    skip_auth_check: bool = False,
    page_load_strategy: str = "networkidle",
) -> CaptureWorkflowResult:
    """Run the complete capture workflow.

    This function orchestrates all phases of the capture workflow:
    1. Check if browser is installed
    2. Check connectivity to target
    3. Check for session contamination
    4. Run pre-capture diagnostic probes
    5. Detect authentication requirements
    6. Run the capture

    Args:
        target: URL with scheme (http:// or https://)
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
        wait_for_data: Wait for async data fetches before navigating
        skip_probes: Skip pre-capture diagnostic probes (Phase 4)
        skip_session_check: Skip session contamination check (Phase 3)
        skip_auth_check: Skip Basic Auth detection (Phase 5)
        page_load_strategy: Playwright wait_until for page.goto

    Returns:
        CaptureWorkflowResult with workflow status

    Example:
        >>> result = run_capture_workflow("http://192.168.1.1", headless=True, timeout=10)
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

    # Phase 3: Session contamination check
    if not skip_session_check:
        result = check_session_phase(result.target_url, result)
        if result.session_contaminated:
            return result

    # Phase 4: Pre-capture diagnostic probes (skippable for single-session devices)
    if not skip_probes:
        result = run_probes_phase(result.target_url, result=result)

    # Phase 5: Auth detection (skippable for single-session devices)
    if not skip_auth_check:
        result = check_auth_phase(result.target_url, result)
        if result.requires_basic_auth and not http_credentials:
            # Return early so CLI can prompt for credentials
            return result

    # Phase 6: Capture — pass pre-computed target_url to avoid duplicate connectivity check
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
        wait_for_data=wait_for_data,
        target_url=result.target_url,
        page_load_strategy=page_load_strategy,
    )

    return result
