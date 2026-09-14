"""Collector for tracking redactions during sanitization.

This module provides the RedactionCollector class which collects auto-redactions
and flagged values during the sanitization process.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from har_capture.sanitization.report import (
    ConfidenceLevel,
    FlaggedValue,
    SanitizationReport,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from har_capture.patterns.hasher import Hasher

_CONFIDENCE_RANK = {ConfidenceLevel.LOW: 0, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.HIGH: 2}


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
        _flag_index: Flagged value -> its entry (for deduplication)
        _flag_created, _flag_touched: Flagged value -> the flag call that
            created it, and the latest that counted it (see ``flag_mark``)
    """

    hasher: Hasher
    auto_redacted_counts: dict[str, int] = field(default_factory=dict)
    flagged: list[FlaggedValue] = field(default_factory=list)
    redacted_values: dict[str, str] = field(default_factory=dict, repr=False)
    _flag_index: dict[str, FlaggedValue] = field(default_factory=dict, repr=False)
    _flag_created: dict[str, int] = field(default_factory=dict, repr=False)
    _flag_touched: dict[str, int] = field(default_factory=dict, repr=False)
    _flag_calls: int = field(default=0, repr=False)
    _flags_muted: bool = field(default=False, repr=False)

    @contextmanager
    def flags_muted(self) -> Iterator[None]:
        """Discard flags raised inside the block; redactions are still recorded.

        For text the review cannot reach: inside a base64-wrapped payload a
        value is stored encoded, so Pass 2's find-and-replace on the HAR's
        text would never find it, and offering it for review would promise a
        redaction that cannot happen.
        """
        previous, self._flags_muted = self._flags_muted, True
        try:
            yield
        finally:
            self._flags_muted = previous

    @property
    def accepts_flags(self) -> bool:
        """False inside ``flags_muted``: a value offered for review there would be discarded."""
        return not self._flags_muted

    def flag_mark(self) -> int:
        """A mark for ``flag_value``'s ``supersede_since``: flags raised after it carry a later call number."""
        return self._flag_calls

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
        *,
        supersede_since: int | None = None,
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
            supersede_since: A ``flag_mark`` taken before a field's value was
                traversed, for the flag on that whole value. A narrower pass
                may already have flagged the same text inside it (a username
                that is exactly a phone number): that is the same occurrence,
                so it is not counted twice, and a flag the traversal created
                takes this category, context and reason, its confidence never
                lowered. A flag from another occurrence keeps its own.
        """
        if self._flags_muted:
            return
        call = self._flag_calls
        self._flag_calls += 1
        existing = self._flag_index.get(value)
        if existing is None:
            entry = FlaggedValue(
                original_value=value,
                category=category,
                confidence=confidence,
                context=context,
                reason=reason,
            )
            self.flagged.append(entry)
            self._flag_index[value] = entry
            self._flag_created[value] = call
        elif supersede_since is not None and self._flag_touched[value] >= supersede_since:
            if self._flag_created[value] >= supersede_since:
                existing.category, existing.context, existing.reason = category, context, reason
                if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[existing.confidence]:
                    existing.confidence = confidence
        else:
            # The same value found again (keep the first context seen)
            existing.occurrences += 1
        self._flag_touched[value] = call

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
        for value in values:
            self._flag_index.pop(value, None)
            self._flag_created.pop(value, None)
            self._flag_touched.pop(value, None)
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
