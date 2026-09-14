"""Tests for RedactionCollector.

This module tests the collector class that tracks both auto-redacted values
and flagged values requiring user review during sanitization.

Test Coverage:
    - Auto-redaction collection with hasher integration
    - Flagged value collection with metadata (category, confidence, context)
    - Deduplication of repeated values
    - Report generation with statistics
    - Salt preservation
    - Occurrence counting for repeated values
    - Confidence level tracking

Test Strategy:
    - Table-driven tests for various value types
    - Integration with Hasher for consistent redaction
    - Validation of report structure
    - Edge cases (empty collections, duplicate handling)

Dependencies:
    - pytest for test framework and parametrization
    - Hasher for redaction generation
"""

from __future__ import annotations

import pytest

from har_capture.patterns import Hasher
from har_capture.sanitization.collector import RedactionCollector
from har_capture.sanitization.report import ConfidenceLevel, RedactionStatus

# =============================================================================
# Test Data Tables
# =============================================================================

# fmt: off
RECORD_AUTO_REDACTION_CASES = [
    # (categories_to_record, expected_counts)
    (["mac"], {"mac": 1}),
    (["mac", "mac"], {"mac": 2}),
    (["mac", "ip", "mac"], {"mac": 2, "ip": 1}),
    (["pass", "pass", "pass"], {"pass": 3}),
    (["mac", "ip", "pass", "token"], {"mac": 1, "ip": 1, "pass": 1, "token": 1}),
]

FLAG_VALUE_DEDUP_CASES = [
    # (values_to_flag, expected_count, expected_occurrences_for_first)
    (["val1"], 1, 1),
    (["val1", "val1"], 1, 2),
    (["val1", "val1", "val1"], 1, 3),
    (["val1", "val2"], 2, 1),
    (["val1", "val2", "val1"], 2, 2),
    (["val1", "val2", "val2", "val1", "val3"], 3, 2),
]

FLAG_VALUE_CONFIDENCE_CASES = [
    # (confidence, expected_confidence_value)
    (ConfidenceLevel.HIGH, "high"),
    (ConfidenceLevel.MEDIUM, "medium"),
    (ConfidenceLevel.LOW, "low"),
]

# A field's flag on its whole value (supersede_since, from the mark taken
# before its traversal). Steps: ("mark",), ("drop",), or ("flag", category,
# confidence, whole_value_flag). Expected: (category, confidence, occurrences).
_H, _M, _L = ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW
SUPERSEDE_CASES = [
    ("inner_flag_taken_over",           [("mark",), ("flag", "phone", _L, False), ("flag", "field", _M, True)],   ("field", _M, 1)),
    ("confidence_never_lowered",        [("mark",), ("flag", "phone", _H, False), ("flag", "field", _M, True)],   ("field", _H, 1)),
    ("other_occurrence_keeps_its_flag", [("flag", "api_key", _H, False), ("mark",), ("flag", "field", _M, True)], ("api_key", _H, 2)),
    ("earlier_flag_counted_once",       [("flag", "api_key", _H, False), ("mark",), ("flag", "phone", _M, False),
                                         ("flag", "field", _M, True)],                                             ("api_key", _H, 2)),
    ("reflagged_after_drop_is_new",      [("flag", "api_key", _H, False), ("drop",), ("mark",),
                                         ("flag", "field", _L, True)],                                             ("field", _L, 1)),
]
# fmt: on


# =============================================================================
# Test Classes
# =============================================================================


class TestRedactionCollectorAutoRedaction:
    """Tests for auto-redaction recording."""

    @pytest.mark.parametrize(
        ("categories", "expected_counts"),
        RECORD_AUTO_REDACTION_CASES,
        ids=[f"categories_{len(c[0])}_distinct_{len(c[1])}" for c in RECORD_AUTO_REDACTION_CASES],
    )
    def test_record_auto_redaction_counts(
        self, categories: list[str], expected_counts: dict[str, int]
    ) -> None:
        """Test auto-redaction counting."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        for cat in categories:
            collector.record_auto_redaction(cat)
        assert collector.auto_redacted_counts == expected_counts

    def test_record_auto_redaction_empty_initially(self) -> None:
        """Test collector starts with empty counts."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        assert collector.auto_redacted_counts == {}


class TestRedactionCollectorFlagging:
    """Tests for flagging suspicious values."""

    @pytest.mark.parametrize(
        ("values", "expected_count", "expected_occurrences"),
        FLAG_VALUE_DEDUP_CASES,
        ids=[f"vals_{len(c[0])}_unique_{c[1]}" for c in FLAG_VALUE_DEDUP_CASES],
    )
    def test_flag_value_deduplicates(
        self, values: list[str], expected_count: int, expected_occurrences: int
    ) -> None:
        """Test flag_value deduplicates repeated values."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        for val in values:
            collector.flag_value(
                value=val,
                category="test_cat",
                confidence=ConfidenceLevel.MEDIUM,
                context="test context",
                reason="test reason",
            )
        assert len(collector.flagged) == expected_count
        # Check occurrences of first unique value
        first_val = values[0]
        first_flagged = next(f for f in collector.flagged if f.original_value == first_val)
        assert first_flagged.occurrences == expected_occurrences

    def test_flag_value_increments_occurrences(self) -> None:
        """Test flag_value increments occurrence count for duplicates."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))

        # Flag same value multiple times
        for _ in range(5):
            collector.flag_value(
                value="repeated-value",
                category="wifi_ssid",
                confidence=ConfidenceLevel.HIGH,
                context="ctx",
                reason="reason",
            )

        assert len(collector.flagged) == 1
        assert collector.flagged[0].occurrences == 5
        assert collector.flagged[0].original_value == "repeated-value"

    def test_flag_value_keeps_first_context(self) -> None:
        """Test flag_value keeps the first context when deduplicating."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))

        collector.flag_value(
            value="test-val",
            category="cat",
            confidence=ConfidenceLevel.MEDIUM,
            context="FIRST CONTEXT",
            reason="reason",
        )
        collector.flag_value(
            value="test-val",
            category="cat",
            confidence=ConfidenceLevel.HIGH,  # Different confidence
            context="SECOND CONTEXT",  # Different context
            reason="different reason",
        )

        assert len(collector.flagged) == 1
        assert collector.flagged[0].context == "FIRST CONTEXT"
        assert collector.flagged[0].occurrences == 2

    @pytest.mark.parametrize(
        ("confidence", "expected_value"),
        FLAG_VALUE_CONFIDENCE_CASES,
        ids=[c[1] for c in FLAG_VALUE_CONFIDENCE_CASES],
    )
    def test_flag_value_confidence_levels(self, confidence: ConfidenceLevel, expected_value: str) -> None:
        """Test flag_value stores correct confidence level."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        collector.flag_value(
            value="test",
            category="cat",
            confidence=confidence,
            context="ctx",
            reason="reason",
        )
        assert collector.flagged[0].confidence.value == expected_value

    @pytest.mark.parametrize(
        ("steps", "expected"), [c[1:] for c in SUPERSEDE_CASES], ids=[c[0] for c in SUPERSEDE_CASES]
    )
    def test_whole_value_flag_supersedes_only_its_own_occurrence(
        self, steps: list[tuple], expected: tuple[str, ConfidenceLevel, int]
    ) -> None:
        """A field's whole-value flag takes over only a flag raised inside its traversal, counted once."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        mark = 0
        for step in steps:
            if step[0] == "mark":
                mark = collector.flag_mark()
            elif step[0] == "drop":
                collector.drop_flagged({"555-123-4567"})
            else:
                _, category, confidence, whole_value = step
                collector.flag_value(
                    "555-123-4567",
                    category,
                    confidence,
                    "ctx",
                    "reason",
                    supersede_since=mark if whole_value else None,
                )
        [item] = collector.flagged
        assert (item.category, item.confidence, item.occurrences) == expected

    def test_flag_value_default_status(self) -> None:
        """Test flagged values have FLAGGED status by default."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        collector.flag_value(
            value="test",
            category="cat",
            confidence=ConfidenceLevel.MEDIUM,
            context="ctx",
            reason="reason",
        )
        assert collector.flagged[0].status == RedactionStatus.FLAGGED


class TestRedactionCollectorToReport:
    """Tests for to_report method."""

    def test_to_report_creates_valid_report(self) -> None:
        """Test to_report creates a valid SanitizationReport."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        collector.record_auto_redaction("mac")
        collector.record_auto_redaction("ip")
        collector.flag_value(
            value="suspicious",
            category="wifi_ssid",
            confidence=ConfidenceLevel.HIGH,
            context="ctx",
            reason="reason",
        )

        report = collector.to_report(
            input_file="input.har",
            output_file="output.har",
            salt="test-salt",
        )

        assert report.input_file == "input.har"
        assert report.output_file == "output.har"
        assert report.salt == "test-salt"
        assert report.auto_redacted_counts == {"mac": 1, "ip": 1}
        assert len(report.flagged) == 1
        assert report.flagged[0].original_value == "suspicious"

    def test_to_report_copies_data(self) -> None:
        """Test to_report creates copies of data (not references)."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))
        collector.record_auto_redaction("mac")

        report = collector.to_report("in.har", "out.har", "salt")

        # Modify collector after creating report
        collector.record_auto_redaction("ip")

        # Report should not be affected
        assert "ip" not in report.auto_redacted_counts


class TestRedactionCollectorHasher:
    """Tests for hasher threading through collector."""

    def test_collector_preserves_hasher(self) -> None:
        """Test collector provides consistent hasher instance."""
        hasher = Hasher.create("consistent-salt")
        collector = RedactionCollector(hasher=hasher)

        # Same hasher should produce same hashes
        hash1 = collector.hasher.hash_generic("test-value", "CAT")
        hash2 = collector.hasher.hash_generic("test-value", "CAT")

        assert hash1 == hash2
        assert collector.hasher is hasher

    def test_collector_hasher_uses_correct_salt(self) -> None:
        """Test collector's hasher uses the configured salt."""
        collector1 = RedactionCollector(hasher=Hasher.create("salt-one"))
        collector2 = RedactionCollector(hasher=Hasher.create("salt-two"))

        hash1 = collector1.hasher.hash_generic("value", "CAT")
        hash2 = collector2.hasher.hash_generic("value", "CAT")

        # Different salts should produce different hashes
        assert hash1 != hash2

    def test_collector_hasher_consistent_across_operations(self) -> None:
        """Test hasher remains consistent after recording operations."""
        collector = RedactionCollector(hasher=Hasher.create("test-salt"))

        # Get hash before recording
        hash_before = collector.hasher.hash_generic("test", "CAT")

        # Record various operations
        collector.record_auto_redaction("mac")
        collector.flag_value(
            value="flagged",
            category="cat",
            confidence=ConfidenceLevel.HIGH,
            context="ctx",
            reason="reason",
        )

        # Hash should still be the same
        hash_after = collector.hasher.hash_generic("test", "CAT")
        assert hash_before == hash_after
