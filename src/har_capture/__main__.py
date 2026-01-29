"""Entry point for python -m har_capture."""

from __future__ import annotations


def main() -> None:
    """Run the CLI application."""
    try:
        from har_capture.cli.main import app

        app()
    except ImportError as e:
        import sys

        print("CLI dependencies not installed.", file=sys.stderr)
        print("Install with: pip install har-capture[cli]", file=sys.stderr)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
