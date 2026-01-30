"""Tests for __main__.py entry point."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestMainEntryPoint:
    """Tests for the __main__.py entry point."""

    @patch("har_capture.cli.main.app")
    def test_main_calls_app(self, mock_app: MagicMock) -> None:
        """Test main() calls the typer app."""
        from har_capture.__main__ import main

        main()

        mock_app.assert_called_once()

    def test_module_runnable(self) -> None:
        """Test module can be imported."""
        import har_capture.__main__

        assert hasattr(har_capture.__main__, "main")

    def test_main_is_callable(self) -> None:
        """Test main function is callable."""
        from har_capture.__main__ import main

        assert callable(main)

    @patch("har_capture.cli.main.app")
    def test_main_with_successful_import(self, mock_app: MagicMock) -> None:
        """Test main works when cli.main can be imported."""
        from har_capture.__main__ import main

        # Should not raise
        main()

        # app() should have been called
        mock_app.assert_called()
