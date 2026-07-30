"""Collector for tracking redactions during sanitization.

This module provides the RedactionCollector class which collects auto-redactions
and flagged values during the sanitization process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from har_capture.sanitization.report import (
    ConfidenceLevel,
    FlaggedValue,
    SanitizationReport,
)

if TYPE_CHECKING:
    from har_capture.patterns.hasher import Hasher


@dataclass
class RedactionCollector:
    """Collects redactions and flagged values during sanitization.

    This class is threaded through the sanitization call chain to:
    1. Provide a single hasher instance for consistent hashing
    2. Track counts of auto-redacted values by category
    3. Collect suspicious values for user review (with deduplication)

    Note:
        Not thread-safe. Create a separate instance per sanitization pass.

    Attributes:
        hasher: The Hasher instance for generating redaction placeholders
        auto_redacted_counts: Counts by category for auto-redacted values
        flagged: List of values flagged for user review
        redacted_values: Original value -> placeholder, for Pass 1b propagation
        _seen_flagged: Set of values already flagged (for deduplication)
    """

    hasher: Hasher
    auto_redacted_counts: dict[str, int] = field(default_factory=dict)
    flagged: list[FlaggedValue] = field(default_factory=list)
    redacted_values: dict[str, str] = field(default_factory=dict, repr=False)
    _seen_flagged: set[str] = field(default_factory=set, repr=False)

    def record_redacted_value(self, original: str, placeholder: str) -> None:
        """Remember which placeholder an auto-redacted value was given.

        Feeds the Pass 1b propagation sweep. The first surface to redact a
        value wins, so the same secret keeps one placeholder everywhere.

        Args:
            original: The pre-redaction value
            placeholder: The placeholder that replaced it
        """
        if original and original not in self.redacted_values:
            self.redacted_values[original] = placeholder

    def record_auto_redaction(self, category: str) -> None:
        """Record that a value was auto-redacted.

        Args:
            category: The category of the redacted value (e.g., "mac_address", "password")
        """
        self.auto_redacted_counts[category] = self.auto_redacted_counts.get(category, 0) + 1

    def flag_value(
        self,
        value: str,
        category: str,
        confidence: ConfidenceLevel,
        context: str,
        reason: str,
    ) -> None:
        """Flag a suspicious value for user review.

        If the value has already been flagged, increments the occurrence count
        instead of creating a duplicate entry.

        Args:
            value: The suspicious value
            category: Category of the value (e.g., "wifi_ssid", "device_name")
            confidence: Confidence level that this is PII
            context: Surrounding text for user review
            reason: Why this value was flagged
        """
        # Deduplicate - same value might be found multiple times
        if value in self._seen_flagged:
            # Increment occurrence count (keep first context seen)
            for f in self.flagged:
                if f.original_value == value:
                    f.occurrences += 1
                    break
            return

        self._seen_flagged.add(value)
        self.flagged.append(
            FlaggedValue(
                original_value=value,
                category=category,
                confidence=confidence,
                context=context,
                reason=reason,
            )
        )

    def drop_flagged(self, values: set[str]) -> int:
        """Remove flagged entries for values that no longer occur in the HAR.

        Used after Pass 1b propagation: a value that was replaced everywhere
        leaves the user a review decision that cannot change the output.

        Args:
            values: Original values to withdraw from the review queue

        Returns:
            Number of flagged entries removed
        """
        before = len(self.flagged)
        self.flagged = [f for f in self.flagged if f.original_value not in values]
        self._seen_flagged -= values
        return before - len(self.flagged)

    def to_report(self, input_file: str, output_file: str, salt: str) -> SanitizationReport:
        """Create a SanitizationReport from the collected data.

        Args:
            input_file: Path to the input HAR file
            output_file: Path to the output (sanitized) HAR file
            salt: Salt used for hashing

        Returns:
            A SanitizationReport containing all collected data
        """
        return SanitizationReport(
            input_file=input_file,
            output_file=output_file,
            salt=salt,
            auto_redacted_counts=dict(self.auto_redacted_counts),
            flagged=list(self.flagged),
        )
