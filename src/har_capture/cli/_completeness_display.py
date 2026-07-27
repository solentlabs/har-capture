"""Shared rendering for capture-completeness reports.

Used by `get`, `sanitize`, and `validate` so the coverage summary and gap
warnings read identically wherever a HAR is handled.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from har_capture.validation.completeness import CaptureCompletenessReport


def display_completeness(
    report: CaptureCompletenessReport | None,
    summary: bool = True,
) -> None:
    """Print the coverage summary followed by one block per warning.

    Args:
        report: Report to render; ``None`` prints nothing, so callers can
            pass a report that failed to build without branching.
        summary: Print the coverage block. Set ``False`` when scanning many
            files at once (``validate --dir``, pre-commit) so only the
            actionable warnings appear.
    """
    if report is None:
        return

    if summary:
        methods = ", ".join(
            f"{method} {count}"
            for method, count in sorted(report.method_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        )

        typer.echo("Capture coverage:")
        typer.echo(f"  Requests:      {report.total_entries} ({report.unique_urls} unique URLs)")
        typer.echo(f"  Methods:       {methods or 'none'}")
        typer.echo(f"  POST requests: {report.post_count}")
        typer.echo(f"  Set-Cookie:    {report.set_cookie_responses} response(s) set a cookie")
        typer.echo()

    for warning in report.warnings:
        typer.echo(f"WARNING: {warning.message}")
        typer.echo(f"  → {warning.remedy}")
        typer.echo()
