"""Tests for capture workflow orchestration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from har_capture.capture.workflow import (
    AuthResult,
    BrowserCheckResult,
    CaptureResult,
    CaptureWorkflowResult,
    ConnectivityResult,
    check_auth_phase,
    check_browser_phase,
    check_connectivity_phase,
    run_capture_phase,
    run_capture_workflow,
)

# =============================================================================
# Test Phase-specific Result Types
# =============================================================================


class TestBrowserCheckResult:
    """Tests for BrowserCheckResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        result = BrowserCheckResult()
        assert result.browser == "chromium"
        assert result.needs_install is False

    def test_custom_values(self) -> None:
        """Test custom values."""
        result = BrowserCheckResult(browser="firefox", needs_install=True)
        assert result.browser == "firefox"
        assert result.needs_install is True


class TestConnectivityResult:
    """Tests for ConnectivityResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        result = ConnectivityResult()
        assert result.ok is False
        assert result.scheme == "http"
        assert result.target_url == ""
        assert result.error is None

    def test_successful_connection(self) -> None:
        """Test successful connection result."""
        result = ConnectivityResult(ok=True, scheme="https", target_url="https://example.com/", error=None)
        assert result.ok is True
        assert result.scheme == "https"
        assert result.target_url == "https://example.com/"

    def test_failed_connection(self) -> None:
        """Test failed connection result."""
        result = ConnectivityResult(ok=False, error="Connection refused")
        assert result.ok is False
        assert result.error == "Connection refused"


class TestAuthResult:
    """Tests for AuthResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        result = AuthResult()
        assert result.requires_basic_auth is False
        assert result.realm is None

    def test_auth_required(self) -> None:
        """Test auth required result."""
        result = AuthResult(requires_basic_auth=True, realm="Router Admin")
        assert result.requires_basic_auth is True
        assert result.realm == "Router Admin"


class TestCaptureResult:
    """Tests for CaptureResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        result = CaptureResult()
        assert result.success is False
        assert result.error is None
        assert result.har_path is None
        assert result.stats == {}

    def test_successful_capture(self, tmp_path: Path) -> None:
        """Test successful capture result."""
        result = CaptureResult(
            success=True,
            har_path=tmp_path / "test.har",
            stats={"entries": 10},
        )
        assert result.success is True
        assert result.har_path == tmp_path / "test.har"
        assert result.stats == {"entries": 10}


# =============================================================================
# Test CaptureWorkflowResult
# =============================================================================


class TestCaptureWorkflowResult:
    """Tests for CaptureWorkflowResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        result = CaptureWorkflowResult()

        assert result.phase == "init"
        assert result.browser.browser == "chromium"
        assert result.browser.needs_install is False
        assert result.connectivity is None
        assert result.auth is None
        assert result.capture is None

    def test_convenience_properties_with_none(self) -> None:
        """Test convenience properties return safe defaults when phase not reached."""
        result = CaptureWorkflowResult()

        # Should return safe defaults, not raise
        assert result.needs_browser_install is False
        assert result.connectivity_ok is False
        assert result.connectivity_error is None
        assert result.target_url == ""
        assert result.scheme == "http"
        assert result.requires_basic_auth is False
        assert result.auth_realm is None
        assert result.capture_success is False
        assert result.capture_error is None
        assert result.har_path is None
        assert result.compressed_path is None
        assert result.sanitized_path is None
        assert result.stats == {}

    def test_convenience_properties_with_values(self, tmp_path: Path) -> None:
        """Test convenience properties return composed values."""
        result = CaptureWorkflowResult(
            phase="complete",
            browser=BrowserCheckResult(browser="firefox", needs_install=False),
            connectivity=ConnectivityResult(ok=True, scheme="https", target_url="https://test/", error=None),
            auth=AuthResult(requires_basic_auth=True, realm="Admin"),
            capture=CaptureResult(
                success=True,
                har_path=tmp_path / "test.har",
                stats={"entries": 5},
            ),
        )

        assert result.needs_browser_install is False
        assert result.connectivity_ok is True
        assert result.target_url == "https://test/"
        assert result.scheme == "https"
        assert result.requires_basic_auth is True
        assert result.auth_realm == "Admin"
        assert result.capture_success is True
        assert result.har_path == tmp_path / "test.har"
        assert result.stats == {"entries": 5}


# =============================================================================
# Test check_browser_phase
# =============================================================================


class TestCheckBrowserPhase:
    """Tests for check_browser_phase function."""

    @patch("har_capture.capture.deps.check_browser_installed")
    def test_browser_installed(self, mock_check: MagicMock) -> None:
        """Test when browser is already installed."""
        mock_check.return_value = True

        result = check_browser_phase("chromium")

        assert result.phase == "browser_check"
        assert result.browser.browser == "chromium"
        assert result.browser.needs_install is False
        mock_check.assert_called_once_with("chromium")

    @patch("har_capture.capture.deps.check_browser_installed")
    def test_browser_not_installed(self, mock_check: MagicMock) -> None:
        """Test when browser needs installation."""
        mock_check.return_value = False

        result = check_browser_phase("firefox")

        assert result.phase == "browser_check"
        assert result.browser.browser == "firefox"
        assert result.browser.needs_install is True

    @patch("har_capture.capture.deps.check_browser_installed")
    def test_default_browser_is_chromium(self, mock_check: MagicMock) -> None:
        """Test default browser is chromium."""
        mock_check.return_value = True

        result = check_browser_phase()

        assert result.browser.browser == "chromium"
        mock_check.assert_called_once_with("chromium")


# =============================================================================
# Test check_connectivity_phase
# =============================================================================


class TestCheckConnectivityPhase:
    """Tests for check_connectivity_phase function."""

    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    def test_successful_connection(self, mock_conn: MagicMock, mock_parse: MagicMock) -> None:
        """Test successful connectivity check."""
        mock_conn.return_value = (True, "http", None)
        mock_parse.return_value = ("192.168.1.1", None)

        result = check_connectivity_phase("192.168.1.1")

        assert result.phase == "connectivity_check"
        assert result.connectivity is not None
        assert result.connectivity.ok is True
        assert result.connectivity.scheme == "http"
        assert result.connectivity.error is None
        assert result.connectivity.target_url == "http://192.168.1.1/"

    @patch("har_capture.capture.connectivity.check_device_connectivity")
    def test_failed_connection(self, mock_conn: MagicMock) -> None:
        """Test failed connectivity check."""
        mock_conn.return_value = (False, "http", "Connection refused")

        result = check_connectivity_phase("192.168.1.1")

        assert result.phase == "connectivity_check"
        assert result.connectivity is not None
        assert result.connectivity.ok is False
        assert result.connectivity.error == "Connection refused"
        assert result.connectivity.target_url == ""

    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    def test_https_connection(self, mock_conn: MagicMock, mock_parse: MagicMock) -> None:
        """Test HTTPS connectivity check."""
        mock_conn.return_value = (True, "https", None)
        mock_parse.return_value = ("example.com", None)

        result = check_connectivity_phase("example.com")

        assert result.connectivity is not None
        assert result.connectivity.scheme == "https"
        assert result.connectivity.target_url == "https://example.com/"

    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    def test_updates_existing_result(self, mock_conn: MagicMock, mock_parse: MagicMock) -> None:
        """Test existing result is updated, not replaced."""
        mock_conn.return_value = (True, "http", None)
        mock_parse.return_value = ("192.168.1.1", None)

        existing = CaptureWorkflowResult(browser=BrowserCheckResult(browser="firefox", needs_install=False))
        result = check_connectivity_phase("192.168.1.1", existing)

        # Should preserve browser from existing result
        assert result.browser.browser == "firefox"
        assert result.connectivity is not None
        assert result.connectivity.ok is True

    @patch("har_capture.capture.connectivity.check_device_connectivity")
    def test_creates_new_result_if_none(self, mock_conn: MagicMock) -> None:
        """Test new result is created if None passed."""
        mock_conn.return_value = (False, "http", "error")

        result = check_connectivity_phase("192.168.1.1", None)

        assert result is not None
        assert result.phase == "connectivity_check"


# =============================================================================
# Test check_auth_phase
# =============================================================================


class TestCheckAuthPhase:
    """Tests for check_auth_phase function."""

    @patch("har_capture.capture.connectivity.check_basic_auth")
    def test_no_auth_required(self, mock_auth: MagicMock) -> None:
        """Test when no auth is required."""
        mock_auth.return_value = (False, None)

        result = check_auth_phase("http://example.com/")

        assert result.phase == "auth_check"
        assert result.auth is not None
        assert result.auth.requires_basic_auth is False
        assert result.auth.realm is None

    @patch("har_capture.capture.connectivity.check_basic_auth")
    def test_basic_auth_required(self, mock_auth: MagicMock) -> None:
        """Test when Basic Auth is required."""
        mock_auth.return_value = (True, "Router Admin")

        result = check_auth_phase("http://192.168.1.1/")

        assert result.phase == "auth_check"
        assert result.auth is not None
        assert result.auth.requires_basic_auth is True
        assert result.auth.realm == "Router Admin"

    @patch("har_capture.capture.connectivity.check_basic_auth")
    def test_basic_auth_without_realm(self, mock_auth: MagicMock) -> None:
        """Test Basic Auth without realm."""
        mock_auth.return_value = (True, None)

        result = check_auth_phase("http://192.168.1.1/")

        assert result.auth is not None
        assert result.auth.requires_basic_auth is True
        assert result.auth.realm is None

    @patch("har_capture.capture.connectivity.check_basic_auth")
    def test_updates_existing_result(self, mock_auth: MagicMock) -> None:
        """Test existing result is updated."""
        mock_auth.return_value = (True, "Admin")

        existing = CaptureWorkflowResult(
            browser=BrowserCheckResult(browser="firefox", needs_install=False),
            connectivity=ConnectivityResult(ok=True, target_url="http://test/", scheme="http"),
        )
        result = check_auth_phase("http://test/", existing)

        # Should preserve existing fields
        assert result.browser.browser == "firefox"
        assert result.connectivity is not None
        assert result.connectivity.ok is True
        # And update auth fields
        assert result.auth is not None
        assert result.auth.requires_basic_auth is True
        assert result.auth.realm == "Admin"


# =============================================================================
# Test run_capture_phase
# =============================================================================


class TestRunCapturePhase:
    """Tests for run_capture_phase function."""

    @patch("har_capture.capture.browser.capture_device_har")
    def test_successful_capture(self, mock_capture: MagicMock, tmp_path: Path) -> None:
        """Test successful capture."""
        har_path = tmp_path / "test.har"
        compressed_path = tmp_path / "test.har.gz"
        sanitized_path = tmp_path / "test.sanitized.har.gz"

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = har_path
        mock_result.compressed_path = compressed_path
        mock_result.sanitized_path = sanitized_path
        mock_result.stats = {"entries": 10}
        mock_capture.return_value = mock_result

        result = run_capture_phase(target="192.168.1.1")

        assert result.phase == "complete"
        assert result.capture is not None
        assert result.capture.success is True
        assert result.capture.error is None
        assert result.capture.har_path == har_path
        assert result.capture.compressed_path == compressed_path
        assert result.capture.sanitized_path == sanitized_path
        assert result.capture.stats == {"entries": 10}

    @patch("har_capture.capture.browser.capture_device_har")
    def test_failed_capture(self, mock_capture: MagicMock) -> None:
        """Test failed capture."""
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error = "Browser crashed"
        mock_result.har_path = None
        mock_result.compressed_path = None
        mock_result.sanitized_path = None
        mock_result.stats = None
        mock_capture.return_value = mock_result

        result = run_capture_phase(target="192.168.1.1")

        assert result.phase == "capture"  # Not complete
        assert result.capture is not None
        assert result.capture.success is False
        assert result.capture.error == "Browser crashed"

    @patch("har_capture.capture.browser.capture_device_har")
    def test_passes_options_to_capture(self, mock_capture: MagicMock, tmp_path: Path) -> None:
        """Test options are passed through to capture_device_har."""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = None
        mock_result.compressed_path = None
        mock_result.sanitized_path = None
        mock_result.stats = {}
        mock_capture.return_value = mock_result

        output_path = tmp_path / "out.har"
        run_capture_phase(
            target="192.168.1.1",
            output=output_path,
            browser="firefox",
            http_credentials={"username": "admin", "password": "pass"},
            sanitize=False,
            compress=False,
            keep_raw=True,
            include_fonts=True,
            include_images=True,
            include_media=True,
            headless=True,
            timeout=30,
        )

        mock_capture.assert_called_once_with(
            ip="192.168.1.1",
            output=output_path,
            browser="firefox",
            http_credentials={"username": "admin", "password": "pass"},
            sanitize=False,
            compress=False,
            keep_raw=True,
            include_fonts=True,
            include_images=True,
            include_media=True,
            headless=True,
            timeout=30,
        )

    @patch("har_capture.capture.browser.capture_device_har")
    def test_updates_existing_result(self, mock_capture: MagicMock) -> None:
        """Test existing result is updated."""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = None
        mock_result.compressed_path = None
        mock_result.sanitized_path = None
        mock_result.stats = {}
        mock_capture.return_value = mock_result

        existing = CaptureWorkflowResult(
            browser=BrowserCheckResult(browser="firefox", needs_install=False),
            connectivity=ConnectivityResult(ok=True, target_url="http://test/"),
            auth=AuthResult(requires_basic_auth=True),
        )
        result = run_capture_phase(target="test", result=existing)

        # Should preserve existing fields
        assert result.browser.browser == "firefox"
        assert result.connectivity is not None
        assert result.connectivity.target_url == "http://test/"
        assert result.auth is not None
        assert result.auth.requires_basic_auth is True
        # And update capture fields
        assert result.capture is not None
        assert result.capture.success is True


# =============================================================================
# Test run_capture_workflow (integration)
# =============================================================================


class TestRunCaptureWorkflow:
    """Tests for run_capture_workflow function."""

    @patch("har_capture.capture.browser.capture_device_har")
    @patch("har_capture.capture.connectivity.check_basic_auth")
    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    @patch("har_capture.capture.deps.check_browser_installed")
    def test_full_workflow_success(
        self,
        mock_browser: MagicMock,
        mock_conn: MagicMock,
        mock_parse: MagicMock,
        mock_auth: MagicMock,
        mock_capture: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test complete workflow success."""
        # Setup mocks
        mock_browser.return_value = True
        mock_parse.return_value = ("192.168.1.1", None)
        mock_conn.return_value = (True, "http", None)
        mock_auth.return_value = (False, None)

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = tmp_path / "test.har"
        mock_result.compressed_path = tmp_path / "test.har.gz"
        mock_result.sanitized_path = tmp_path / "test.sanitized.har.gz"
        mock_result.stats = {"entries": 5}
        mock_capture.return_value = mock_result

        result = run_capture_workflow("192.168.1.1")

        assert result.phase == "complete"
        assert result.capture_success is True
        assert result.har_path == tmp_path / "test.har"

    @patch("har_capture.capture.deps.check_browser_installed")
    def test_stops_if_browser_not_installed(self, mock_browser: MagicMock) -> None:
        """Test workflow stops if browser needs installation."""
        mock_browser.return_value = False

        result = run_capture_workflow("192.168.1.1")

        assert result.phase == "browser_check"
        assert result.needs_browser_install is True
        assert result.capture_success is False

    @patch("har_capture.capture.connectivity.check_device_connectivity")
    @patch("har_capture.capture.deps.check_browser_installed")
    def test_stops_if_not_reachable(self, mock_browser: MagicMock, mock_conn: MagicMock) -> None:
        """Test workflow stops if target not reachable."""
        mock_browser.return_value = True
        mock_conn.return_value = (False, "http", "Connection refused")

        result = run_capture_workflow("192.168.1.1")

        assert result.phase == "connectivity_check"
        assert result.connectivity_ok is False
        assert result.connectivity_error == "Connection refused"
        assert result.capture_success is False

    @patch("har_capture.capture.connectivity.check_basic_auth")
    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    @patch("har_capture.capture.deps.check_browser_installed")
    def test_stops_if_auth_required_without_creds(
        self,
        mock_browser: MagicMock,
        mock_conn: MagicMock,
        mock_parse: MagicMock,
        mock_auth: MagicMock,
    ) -> None:
        """Test workflow stops if auth required but no credentials."""
        mock_browser.return_value = True
        mock_parse.return_value = ("192.168.1.1", None)
        mock_conn.return_value = (True, "http", None)
        mock_auth.return_value = (True, "Router Admin")

        result = run_capture_workflow("192.168.1.1")

        assert result.phase == "auth_check"
        assert result.requires_basic_auth is True
        assert result.auth_realm == "Router Admin"
        assert result.capture_success is False

    @patch("har_capture.capture.browser.capture_device_har")
    @patch("har_capture.capture.connectivity.check_basic_auth")
    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    @patch("har_capture.capture.deps.check_browser_installed")
    def test_continues_if_auth_required_with_creds(
        self,
        mock_browser: MagicMock,
        mock_conn: MagicMock,
        mock_parse: MagicMock,
        mock_auth: MagicMock,
        mock_capture: MagicMock,
    ) -> None:
        """Test workflow continues if auth required and credentials provided."""
        mock_browser.return_value = True
        mock_parse.return_value = ("192.168.1.1", None)
        mock_conn.return_value = (True, "http", None)
        mock_auth.return_value = (True, "Router Admin")

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = None
        mock_result.compressed_path = None
        mock_result.sanitized_path = None
        mock_result.stats = {}
        mock_capture.return_value = mock_result

        result = run_capture_workflow(
            "192.168.1.1",
            http_credentials={"username": "admin", "password": "password"},
        )

        assert result.phase == "complete"
        assert result.capture_success is True

    @patch("har_capture.capture.browser.capture_device_har")
    @patch("har_capture.capture.connectivity.check_basic_auth")
    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    @patch("har_capture.capture.deps.check_browser_installed")
    def test_skip_browser_check(
        self,
        mock_browser: MagicMock,
        mock_conn: MagicMock,
        mock_parse: MagicMock,
        mock_auth: MagicMock,
        mock_capture: MagicMock,
    ) -> None:
        """Test skip_browser_check option."""
        mock_parse.return_value = ("192.168.1.1", None)
        mock_conn.return_value = (True, "http", None)
        mock_auth.return_value = (False, None)

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = None
        mock_result.compressed_path = None
        mock_result.sanitized_path = None
        mock_result.stats = {}
        mock_capture.return_value = mock_result

        run_capture_workflow("192.168.1.1", skip_browser_check=True)

        # Browser check should be skipped
        mock_browser.assert_not_called()

    @patch("har_capture.capture.browser.capture_device_har")
    @patch("har_capture.capture.connectivity.check_basic_auth")
    @patch("har_capture.capture.connectivity._parse_target")
    @patch("har_capture.capture.connectivity.check_device_connectivity")
    @patch("har_capture.capture.deps.check_browser_installed")
    def test_passes_all_options(
        self,
        mock_browser: MagicMock,
        mock_conn: MagicMock,
        mock_parse: MagicMock,
        mock_auth: MagicMock,
        mock_capture: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test all options are passed through to capture."""
        mock_browser.return_value = True
        mock_parse.return_value = ("192.168.1.1", None)
        mock_conn.return_value = (True, "http", None)
        mock_auth.return_value = (False, None)

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.error = None
        mock_result.har_path = None
        mock_result.compressed_path = None
        mock_result.sanitized_path = None
        mock_result.stats = {}
        mock_capture.return_value = mock_result

        output_path = tmp_path / "test.har"
        run_capture_workflow(
            target="192.168.1.1",
            output=output_path,
            browser="firefox",
            sanitize=False,
            compress=False,
            keep_raw=True,
            include_fonts=True,
            include_images=True,
            include_media=True,
            headless=True,
            timeout=60,
        )

        mock_capture.assert_called_once()
        call_kwargs = mock_capture.call_args[1]
        assert call_kwargs["ip"] == "192.168.1.1"
        assert call_kwargs["output"] == output_path
        assert call_kwargs["browser"] == "firefox"
        assert call_kwargs["sanitize"] is False
        assert call_kwargs["compress"] is False
        assert call_kwargs["keep_raw"] is True
        assert call_kwargs["include_fonts"] is True
        assert call_kwargs["include_images"] is True
        assert call_kwargs["include_media"] is True
        assert call_kwargs["headless"] is True
        assert call_kwargs["timeout"] == 60
