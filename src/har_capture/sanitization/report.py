"""Data classes for sanitization reports.

This module contains the data structures used to track auto-redactions,
flagged values requiring user review, and sanitization results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConfidenceLevel(Enum):
    """Confidence level for flagged values.

    Higher confidence means the value is more likely to be PII.
    """

    HIGH = "high"  # Almost certainly PII (e.g., adjacent to password label)
    MEDIUM = "medium"  # Likely PII (e.g., SSID-like string)
    LOW = "low"  # Possibly PII (e.g., short alphanumeric in suspicious context)


class RedactionStatus(Enum):
    """Status of a flagged value."""

    AUTO_REDACTED = "auto"  # Matched known pattern, auto-redacted
    FLAGGED = "flagged"  # Suspicious, needs review
    USER_REDACTED = "user"  # User chose to redact
    USER_SKIPPED = "skipped"  # User chose to keep


@dataclass
class FlaggedValue:
    """A value flagged for user review.

    Attributes:
        original_value: The suspicious value
        category: Category of the value (e.g., "wifi_ssid", "device_name", "password")
        confidence: How likely this is PII
        context: Surrounding text for review (e.g., 50 chars before/after)
        reason: Why it was flagged
        occurrences: How many times this value appears in the file
        status: Current redaction status
        redacted_value: The redacted replacement (set after user decision)
    """

    original_value: str
    category: str
    confidence: ConfidenceLevel
    context: str
    reason: str
    occurrences: int = 1
    status: RedactionStatus = RedactionStatus.FLAGGED
    redacted_value: str | None = None


@dataclass
class SanitizationReport:
    """Report of a sanitization operation.

    Attributes:
        input_file: Path to the input HAR file
        output_file: Path to the output (sanitized) HAR file
        salt: Salt used for hashing (stored for Pass 2 reconstruction)
        auto_redacted_counts: Counts by category for auto-redacted values
        flagged: List of values flagged for user review
        warnings: List of warning messages
    """

    input_file: str
    output_file: str
    salt: str
    auto_redacted_counts: dict[str, int] = field(default_factory=dict)
    flagged: list[FlaggedValue] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_auto_redacted(self) -> int:
        """Total count of auto-redacted values."""
        return sum(self.auto_redacted_counts.values())

    @property
    def total_user_redacted(self) -> int:
        """Count of values the user chose to redact."""
        return sum(1 for f in self.flagged if f.status == RedactionStatus.USER_REDACTED)

    @property
    def total_user_skipped(self) -> int:
        """Count of values the user chose to skip."""
        return sum(1 for f in self.flagged if f.status == RedactionStatus.USER_SKIPPED)

    @property
    def has_pending_review(self) -> bool:
        """Whether there are flagged values awaiting review."""
        return any(f.status == RedactionStatus.FLAGGED for f in self.flagged)

    def to_dict(self) -> dict[str, Any]:
        """Serialize report for JSON output.

        Returns:
            Dictionary suitable for JSON serialization
        """
        return {
            "input_file": self.input_file,
            "output_file": self.output_file,
            "salt": self.salt,
            "summary": {
                "auto_redacted": self.total_auto_redacted,
                "user_redacted": self.total_user_redacted,
                "user_skipped": self.total_user_skipped,
            },
            "auto_redacted_counts": self.auto_redacted_counts,
            "flagged": [
                {
                    "value": f.original_value,
                    "category": f.category,
                    "confidence": f.confidence.value,
                    "reason": f.reason,
                    "occurrences": f.occurrences,
                    "status": f.status.value,
                }
                for f in self.flagged
            ],
            "warnings": self.warnings,
        }
