"""Browser-based HAR capture using Playwright.

This module provides Playwright-based browser capture for HAR files.
Requires the 'capture' optional dependency: pip install har-capture[capture]

Exports:
    - capture_device_har: Main capture function
    - CaptureResult: Result dataclass from capture
    - CaptureOptions: Options for filtering (fonts, images, media)
    - check_playwright: Check if Playwright is available
    - install_playwright: Install Playwright and browser
    - CaptureWorkflowResult: Result dataclass from workflow
    - run_capture_workflow: Run the complete capture workflow
"""

from __future__ import annotations

from har_capture.capture.browser import (
    BrowserSessionResult,
    CaptureOptions,
    CapturePathInfo,
    CaptureResult,
    _inject_har_metadata,
    _resolve_capture_paths,
    _run_browser_session,
    _run_post_capture_pipeline,
    capture_device_har,
    filter_and_compress_har,
)
from har_capture.capture.connectivity import (
    check_basic_auth,
    check_device_connectivity,
    check_session_contamination,
)
from har_capture.capture.deps import (
    check_browser_installed,
    check_playwright,
    install_browser,
    install_browser_deps,
    install_playwright,
)
from har_capture.capture.probes import (
    probe_auth_challenge,
    probe_head_support,
    probe_icmp,
    run_probes,
)
from har_capture.capture.workflow import (
    AuthResult,
    BrowserCheckResult,
    CaptureWorkflowResult,
    ConnectivityResult,
    ProbeResult,
    SessionCheckResult,
    check_auth_phase,
    check_browser_phase,
    check_connectivity_phase,
    check_session_phase,
    run_capture_phase,
    run_capture_workflow,
    run_probes_phase,
)
from har_capture.capture.workflow import CaptureResult as WorkflowCaptureResult

__all__ = [
    # Core capture
    "capture_device_har",
    "filter_and_compress_har",
    "CaptureResult",
    "CaptureOptions",
    "CapturePathInfo",
    "BrowserSessionResult",
    # Internal (testable units)
    "_resolve_capture_paths",
    "_run_browser_session",
    "_inject_har_metadata",
    "_run_post_capture_pipeline",
    # Connectivity checks
    "check_device_connectivity",
    "check_basic_auth",
    "check_session_contamination",
    # Dependency management
    "check_playwright",
    "check_browser_installed",
    "install_playwright",
    "install_browser",
    "install_browser_deps",
    # Probes
    "run_probes",
    "probe_auth_challenge",
    "probe_head_support",
    "probe_icmp",
    "ProbeResult",
    "run_probes_phase",
    # Workflow orchestration
    "CaptureWorkflowResult",
    "BrowserCheckResult",
    "ConnectivityResult",
    "SessionCheckResult",
    "AuthResult",
    "WorkflowCaptureResult",
    "check_browser_phase",
    "check_connectivity_phase",
    "check_session_phase",
    "check_auth_phase",
    "run_capture_phase",
    "run_capture_workflow",
]
