"""Interactive review mode for sanitization.

This module provides the interactive UI for reviewing and approving
flagged values that couldn't be auto-redacted.

Uses Rich for beautiful tables and InquirerPy for checkbox selection.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from har_capture.sanitization.report import FlaggedValue, SanitizationReport

_LOGGER = logging.getLogger(__name__)


# =============================================================================
# Color scheme for categories
# =============================================================================

CATEGORY_STYLES = {
    "credential": ("🔑", "Password", "red"),
    "password": ("🔑", "Password", "red"),
    "wifi_ssid": ("📶", "WiFi SSID", "cyan"),
    "wifi": ("📶", "WiFi", "cyan"),
    "device_name": ("📱", "Device", "yellow"),
    "device": ("📱", "Device", "yellow"),
    "suspicious": ("⚠️", "Suspicious", "magenta"),
    "account": ("👤", "Account", "green"),
}

CONFIDENCE_STYLES = {
    "high": "[bold red]HIGH[/]",
    "medium": "[yellow]MED[/]",
    "low": "[dim]LOW[/]",
}


def get_category_display(category: str) -> tuple[str, str, str]:
    """Get icon, friendly name, and color for a category."""
    return CATEGORY_STYLES.get(category.lower(), ("•", category, "white"))


def get_category_color(category: str) -> str:
    """Get the color for a category."""
    return get_category_display(category)[2]


def get_category_icon(category: str) -> str:
    """Get an icon for a category."""
    return get_category_display(category)[0]


# =============================================================================
# Display Configuration
# =============================================================================

# Truncation lengths for display
_VALUE_TRUNCATE_LENGTH = 20  # Max length for values in table
_CONTEXT_TRUNCATE_LENGTH = 50  # Max length for context strings
_DETAIL_VALUE_TRUNCATE_LENGTH = 15  # Max length when showing occurrence count
_CHECKBOX_VALUE_TRUNCATE_LENGTH = 22  # Max length in checkbox display


# =============================================================================
# Helper Functions
# =============================================================================


def truncate_value(value: str, max_len: int = _VALUE_TRUNCATE_LENGTH) -> str:
    """Truncate a value for display, showing character count if truncated."""
    if len(value) <= max_len:
        return value
    # Show character count to indicate there's more content
    char_info = f" [{len(value)}]"
    truncate_at = max_len - len(char_info) - 3  # Account for "..." and char info
    return value[:truncate_at] + "..." + char_info


def format_context(context: str, max_len: int = _CONTEXT_TRUNCATE_LENGTH) -> str:
    """Format context string for display."""
    context = context.replace("\n", " ").replace("\r", "")
    context = re.sub(r"\s+", " ", context)

    # Highlight the >>> <<< markers
    context = context.replace(">>>", "[bold green]").replace("<<<", "[/]")

    if len(context) <= max_len + 20:  # Allow extra for markup
        return context
    return context[:max_len] + "..."


def capture_pipe_context(values: list[str], index: int, window: int = 3) -> str:
    """Capture context around a value in pipe-delimited list."""
    start = max(0, index - window)
    end = min(len(values), index + window + 1)
    parts = []
    for i in range(start, end):
        if i == index:
            parts.append(f">>>{values[i]}<<<")
        else:
            parts.append(values[i])
    return "|".join(parts)


def capture_html_context(html: str, start: int, end: int, window: int = 50) -> str:
    """Capture context around a match in HTML."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(html), end + window)
    before = html[ctx_start:start]
    match_text = html[start:end]
    after = html[end:ctx_end]
    return f"...{before}>>>{match_text}<<<{after}..."


# =============================================================================
# Rich Table Display
# =============================================================================


def display_flagged_table(flagged: list[FlaggedValue]) -> None:
    """Display flagged values in a beautiful Rich table."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    table = Table(
        title="[bold]Flagged Values for Review[/]",
        show_header=True,
        header_style="bold",
        border_style="dim",
    )

    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Match", justify="center", width=5, no_wrap=True)
    table.add_column("Type", justify="left", width=14, no_wrap=True)
    table.add_column("Value", justify="left", width=22)
    table.add_column("Context", justify="left")

    for i, item in enumerate(flagged, 1):
        # Confidence as colored dot
        conf_dot = {"high": "[red]●[/]", "medium": "[yellow]●[/]", "low": "[dim]●[/]"}.get(
            item.confidence.value, "○"
        )

        # Get friendly category display
        icon, friendly_name, color = get_category_display(item.category)

        value_display = item.original_value
        if item.occurrences > 1:
            value_display = (
                f"{truncate_value(item.original_value, _DETAIL_VALUE_TRUNCATE_LENGTH)} ({item.occurrences}x)"
            )
        else:
            value_display = truncate_value(item.original_value, _VALUE_TRUNCATE_LENGTH)

        table.add_row(
            str(i),
            conf_dot,
            f"[{color}]{icon} {friendly_name}[/]",
            f"[bold]{value_display}[/]",
            format_context(item.context, _CONTEXT_TRUNCATE_LENGTH - 5),
        )

    console.print()
    console.print(table)


def display_sanitization_summary(
    report: SanitizationReport,
    input_path: str,
    output_path: str,
    salt_mode: str,
) -> None:
    """Display initial sanitization summary with Rich panel."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    from har_capture import __version__

    console = Console()

    # Build content - use expand=False to prevent table from filling panel width
    table = Table(show_header=False, box=None, padding=(0, 1), expand=False)
    table.add_column("Label", style="bold")
    table.add_column("Value")

    # Version
    table.add_row("Version", f"[dim]har-capture {__version__}[/]")
    table.add_row("", "")

    # Input file
    table.add_row("Input", f"{input_path}")

    # Salt info
    table.add_row("Salt", f"[dim]{salt_mode}[/]")
    table.add_row("", "")

    # Auto-redacted total
    table.add_row("Auto-redacted", f"[green]{report.total_auto_redacted}[/]")

    # Category breakdown (indented)
    for category, count in sorted(report.auto_redacted_counts.items()):
        table.add_row(f"  [dim]{category}[/]", f"[dim]{count}[/]")

    table.add_row("", "")
    table.add_row("Output", f"[cyan]{output_path}[/]")

    # Choose title and style based on whether review is needed
    if report.flagged:
        title = "[bold]Review Required[/]"
        border_style = "yellow"
    else:
        title = "[bold]Sanitization Complete[/]"
        border_style = "green"

    panel = Panel(table, title=title, subtitle="Solent Labs™", border_style=border_style)
    console.print()
    console.print(panel)


def display_summary(report: SanitizationReport) -> None:
    """Display summary of sanitization results with Rich."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()

    # Summary table
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Auto-redacted", f"[green]{report.total_auto_redacted}[/]")
    table.add_row("User redacted", f"[cyan]{report.total_user_redacted}[/]")
    table.add_row("User skipped", f"[yellow]{report.total_user_skipped}[/]")

    panel = Panel(table, title="[bold]Summary[/]", subtitle="Solent Labs™", border_style="blue")
    console.print()
    console.print(panel)


# =============================================================================
# InquirerPy Checkbox Selection
# =============================================================================


def run_checkbox_selection(flagged: list[FlaggedValue]) -> list[int] | None:
    """Run checkbox selection for flagged values.

    Returns:
        List of indices (0-based) that user selected to redact, or None to go back
    """
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator

    # Build choices for checkbox
    choices = []

    # Group by category for better organization
    current_category = None
    for i, item in enumerate(flagged):
        # Add separator when category changes
        if item.category != current_category:
            if current_category is not None:
                choices.append(Separator())
            current_category = item.category

        icon = get_category_icon(item.category)
        conf_indicator = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(item.confidence.value, "⚪")

        # Format the choice label
        value_display = item.original_value
        if len(value_display) > _CHECKBOX_VALUE_TRUNCATE_LENGTH + 3:
            value_display = value_display[:_CHECKBOX_VALUE_TRUNCATE_LENGTH] + "..."

        label = f"{conf_indicator} {icon} {value_display}"

        # Pre-select:
        # - All HIGH confidence items (likely critical PII)
        # - MEDIUM confidence credentials/passwords (likely passwords)
        # Leave WiFi SSIDs and device names unselected for user confirmation
        should_preselect = item.confidence.value == "high" or (
            item.confidence.value == "medium" and item.category.lower() in ("credential", "password")
        )
        choices.append(  # type: ignore[arg-type,dict-item]
            {
                "name": label,
                "value": i,
                "enabled": should_preselect,
            }
        )

    # Run the checkbox prompt with checkbox symbols (not radio circles)
    try:
        selected = inquirer.checkbox(  # type: ignore[attr-defined]
            message="Select values to REDACT (high confidence pre-selected):",
            choices=choices,
            instruction="(Space=toggle, A=all, N=none, Backspace=back)",
            validate=lambda _: True,  # Allow empty selection
            invalid_message="",
            enabled_symbol="☑",
            disabled_symbol="☐",
            mandatory=False,  # Allow ESC/backspace to skip
            keybindings={
                "toggle-all-true": [{"key": "a"}],
                "toggle-all-false": [{"key": "n"}],
                "skip": [{"key": "escape"}, {"key": "backspace"}],
            },
            transformer=lambda result: f"{len(result)} selected" if result else "none selected",
        ).execute()

        # None means user pressed ESC to go back
        if selected is None:
            return None

        return selected or []
    except (KeyboardInterrupt, EOFError):
        # User wants to cancel
        return None
    except Exception as e:
        # Catch InquirerPy internal errors, terminal issues, etc.
        _LOGGER.warning("Error in checkbox selection: %s", e)
        # Return None to allow graceful fallback
        return None


def run_quick_action_prompt(flagged: list[FlaggedValue]) -> str | None:
    """Show quick action menu for common operations.

    Returns:
        Action: "select", "all", "none", "skip", or None if cancelled
    """
    from InquirerPy import inquirer

    # Count by confidence
    high = sum(1 for f in flagged if f.confidence.value == "high")
    medium = sum(1 for f in flagged if f.confidence.value == "medium")

    choices = [
        {"name": f"📋 Select individually ({len(flagged)} items)", "value": "select"},
        {"name": f"✅ Redact ALL flagged values ({len(flagged)} items)", "value": "all"},
    ]

    if high > 0:
        choices.append({"name": f"🔴 Redact HIGH confidence only ({high} items)", "value": "high"})
    if high > 0 and medium > 0:
        choices.append({"name": f"🔴🟡 Redact HIGH + MEDIUM ({high + medium} items)", "value": "high_medium"})

    choices.extend(
        [
            {"name": "⏭️ Skip review (keep all values as-is)", "value": "skip"},
        ]
    )

    try:
        return inquirer.select(  # type: ignore[attr-defined,no-any-return]
            message="How would you like to handle flagged values? (Ctrl+C to cancel)",
            choices=choices,
            default="select",
        ).execute()
    except (KeyboardInterrupt, EOFError):
        return None
    except Exception as e:
        _LOGGER.warning("Error in quick action prompt: %s", e)
        return None


# =============================================================================
# Main Interactive Review
# =============================================================================


def run_interactive_review(
    report: SanitizationReport,
    input_path: str | None = None,
    output_path: str | None = None,
    salt_mode: str | None = None,
) -> bool:
    """Run the interactive review with Rich + InquirerPy.

    Args:
        report: The sanitization report with flagged values
        input_path: Input file path (for redisplay on ESC)
        output_path: Output file path (for redisplay on ESC)
        salt_mode: Salt mode description (for redisplay on ESC)

    Returns:
        True if review completed normally, False if cancelled
    """
    from rich.console import Console

    from har_capture.sanitization.report import ConfidenceLevel, RedactionStatus

    console = Console()

    # Clear screen before starting interactive mode
    console.clear()

    flagged = report.flagged

    if not flagged:
        console.print()
        console.print("[green]✓[/] No suspicious values found. All values were handled automatically.")
        return True

    # Sort by confidence (high first), then by category
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    flagged.sort(key=lambda x: (confidence_order.get(x.confidence.value, 3), x.category))

    def display_full_screen(clear: bool = True) -> None:
        """Clear and display the full review screen."""
        if clear:
            console.clear()
        if input_path and output_path and salt_mode:
            display_sanitization_summary(report, input_path, output_path, salt_mode)
        display_flagged_table(flagged)

    # Show initial screen (already cleared above)
    display_full_screen(clear=False)

    # Main action loop - allows going back from individual selection
    while True:
        # Show quick action menu
        console.print()
        action = run_quick_action_prompt(flagged)

        if action is None:
            console.print()
            console.print("[yellow]Review cancelled.[/]")
            return False

        if action == "skip":
            console.print()
            console.print("[yellow]Review skipped.[/] Flagged values will remain unchanged.")
            return True

        if action == "all":
            # Redact all
            for item in flagged:
                item.status = RedactionStatus.USER_REDACTED
            console.print()
            console.print(f"[green]✓[/] Marked all {len(flagged)} items for redaction.")
            return True

        if action == "high":
            # Redact high confidence only
            count = 0
            for item in flagged:
                if item.confidence == ConfidenceLevel.HIGH:
                    item.status = RedactionStatus.USER_REDACTED
                    count += 1
                else:
                    item.status = RedactionStatus.USER_SKIPPED
            console.print()
            console.print(f"[green]✓[/] Marked {count} high-confidence items for redaction.")
            return True

        if action == "high_medium":
            # Redact high + medium
            count = 0
            for item in flagged:
                if item.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM):
                    item.status = RedactionStatus.USER_REDACTED
                    count += 1
                else:
                    item.status = RedactionStatus.USER_SKIPPED
            console.print()
            console.print(f"[green]✓[/] Marked {count} items for redaction.")
            return True

        # Individual selection mode
        selected_indices = run_checkbox_selection(flagged)

        # If user pressed ESC, go back to action menu
        if selected_indices is None:
            display_full_screen()
            continue

        # Apply selections
        for i, item in enumerate(flagged):
            if i in selected_indices:
                item.status = RedactionStatus.USER_REDACTED
            else:
                item.status = RedactionStatus.USER_SKIPPED

        console.print()
        console.print(
            f"[green]✓[/] Marked {len(selected_indices)} items for redaction, skipped {len(flagged) - len(selected_indices)}."
        )

        return True


# =============================================================================
# Legacy parse_indices (kept for compatibility)
# =============================================================================


def parse_indices(input_str: str, max_index: int) -> list[int]:
    """Parse user input for item indices (legacy function)."""
    input_str = input_str.strip().lower()

    if input_str == "all":
        return list(range(max_index))

    indices: set[int] = set()
    parts = input_str.split(",")

    for part in parts:
        stripped_part = part.strip()
        if not stripped_part:
            continue

        if "-" in stripped_part:
            match = re.match(r"^(\d+)-(\d+)$", stripped_part)
            if not match:
                raise ValueError(f"Invalid range: {stripped_part}")
            start, end = int(match.group(1)), int(match.group(2))
            if start < 1 or end > max_index or start > end:
                raise ValueError(f"Range out of bounds: {stripped_part} (valid: 1-{max_index})")
            indices.update(range(start - 1, end))
        else:
            if not stripped_part.isdigit():
                raise ValueError(f"Invalid index: {stripped_part}")
            idx = int(stripped_part)
            if idx < 1 or idx > max_index:
                raise ValueError(f"Index out of bounds: {idx} (valid: 1-{max_index})")
            indices.add(idx - 1)

    return sorted(indices)
