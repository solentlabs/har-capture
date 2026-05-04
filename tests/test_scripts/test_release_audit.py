"""Unit tests for the release-discipline audit (gates A + E) in ``scripts/release.py``.

Covers the pure helpers — ``scan_log_for_anti_patterns`` (gate A's regex
behaviour) and ``check_signoff_phrase`` / ``expected_signoff_phrase``
(gate E's exact-match logic). Gate B (``print_audit_checklist``) is
formatting-only; not exercised here because the value is what Ken
sees, not what string-equality assertions catch.

These helpers were extracted as pure functions specifically so this
file could exist without git fixtures or stdin mocking — testability
followed structure.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# scripts/ is not a package; add it to sys.path so we can import release.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from release import (  # type: ignore[import-not-found]  # noqa: E402
    check_signoff_phrase,
    expected_signoff_phrase,
    scan_log_for_anti_patterns,
)

# =============================================================================
# Gate A — anti-pattern scan
# =============================================================================


# fmt: off
ANTI_PATTERN_BLOCK_CASES = [
    # (id, log_text, description)
    ("pre_existing_lowercase",  "fix: pre-existing flake in fixture",       "lowercase hyphenated"),
    ("pre_existing_titlecase",  "Pre-Existing issue surfaced during tests", "title case"),
    ("pre_existing_two_words",  "this is pre existing behavior",            "two-word form"),
    ("pre_existing_no_hyphen",  "preexisting test failure",                 "no hyphen"),
    ("pre_existing_in_body",    "fix: timing fix\n\nThe stays_pending case is pre-existing", "body of message"),
]

ANTI_PATTERN_WARN_CASES = [
    # (id, log_text, description)
    ("no_verify_flag",  "chore: skip hooks --no-verify because urgent",       "--no-verify mention"),
    ("no_cov_flag",     "test: ran with --no-cov to bypass gate",             "--no-cov mention"),
    ("papercut",        "chore: minor papercut in release.py",                "papercut keyword"),
    ("flake_word",      "fix: minor flake in test_browser",                   "minor flake keyword"),
    ("deferred",        "docs: deferred to next release",                     "deferred keyword"),
    ("retry_past",      "ci: retry-past the broken test once and continue",   "retry-past keyword"),
]

# Cases that must NOT trigger any finding — guards against false positives
# that would erode the gate's signal.
ANTI_PATTERN_CLEAN_CASES = [
    ("normal_fix",       "fix(capture): subscribe to popup events",          "ordinary fix message"),
    ("normal_feat",      "feat(cli): add --patterns flag",                   "ordinary feat message"),
    ("empty_log",        "",                                                 "empty log (no commits)"),
    ("legitimate_minor", "chore(release): bump minor version to 0.9.0",      "'minor' in version-bump context (NOT in our keyword list)"),
    ("preface_word",     "feat: prefix-existing API gets a new flag",        "'prefix' near 'existing' but not pre-existing"),
]
# fmt: on


class TestAntiPatternBlockers:
    """BLOCK-severity findings — these abort the release."""

    @pytest.mark.parametrize(
        ("case_id", "log_text", "desc"),
        ANTI_PATTERN_BLOCK_CASES,
        ids=[c[0] for c in ANTI_PATTERN_BLOCK_CASES],
    )
    def test_pre_existing_variants_are_blockers(self, case_id: str, log_text: str, desc: str) -> None:
        """Every variant of "pre-existing" framing must trip the BLOCK gate."""
        blockers, _ = scan_log_for_anti_patterns(log_text)
        assert blockers, f"{desc}: expected blocker, got none for {log_text!r}"
        assert any("pre-existing" in b.lower() for b in blockers), (
            f"{desc}: blocker should mention pre-existing"
        )


class TestAntiPatternWarnings:
    """WARN-severity findings — advisory, printed in audit but don't block."""

    @pytest.mark.parametrize(
        ("case_id", "log_text", "desc"),
        ANTI_PATTERN_WARN_CASES,
        ids=[c[0] for c in ANTI_PATTERN_WARN_CASES],
    )
    def test_warn_keywords_produce_warnings(self, case_id: str, log_text: str, desc: str) -> None:
        blockers, warnings = scan_log_for_anti_patterns(log_text)
        assert not blockers, f"{desc}: warn keyword should not be a blocker"
        assert warnings, f"{desc}: expected at least one warning"


class TestAntiPatternCleanCases:
    """No false positives — clean log text must produce zero findings."""

    @pytest.mark.parametrize(
        ("case_id", "log_text", "desc"),
        ANTI_PATTERN_CLEAN_CASES,
        ids=[c[0] for c in ANTI_PATTERN_CLEAN_CASES],
    )
    def test_clean_log_produces_no_findings(self, case_id: str, log_text: str, desc: str) -> None:
        blockers, warnings = scan_log_for_anti_patterns(log_text)
        assert not blockers, f"{desc}: false-positive blocker on {log_text!r}: {blockers}"
        assert not warnings, f"{desc}: false-positive warning on {log_text!r}: {warnings}"


def test_multiple_findings_in_one_log() -> None:
    """A log with both BLOCK and WARN signatures yields both."""
    log = "fix: pre-existing flake in fixture\n---\nchore: minor flake in another test\n"
    blockers, warnings = scan_log_for_anti_patterns(log)
    assert blockers, "expected BLOCK finding for pre-existing"
    assert warnings, "expected WARN finding for 'minor flake'"


# =============================================================================
# Gate E — sign-off phrase
# =============================================================================


# fmt: off
SIGNOFF_CASES = [
    # (version, response, expected_ok, description)
    ("0.8.3",  "RELEASE OK 0.8.3",     True,  "exact match"),
    ("0.8.3",  "  RELEASE OK 0.8.3 ",  True,  "leading/trailing whitespace stripped"),
    ("0.8.3",  "RELEASE OK 0.8.3\n",   True,  "trailing newline tolerated"),
    ("0.8.3",  "release ok 0.8.3",     False, "case-sensitive: lowercase rejected"),
    ("0.8.3",  "RELEASE OK 0.8.4",     False, "wrong version rejected"),
    ("0.8.3",  "RELEASE OK",           False, "missing version rejected"),
    ("0.8.3",  "RELEASE-OK-0.8.3",     False, "wrong separator rejected"),
    ("0.8.3",  "yes",                  False, "loose 'yes' rejected"),
    ("0.8.3",  "",                     False, "empty rejected"),
    ("1.0.0",  "RELEASE OK 1.0.0",     True,  "different version exact match"),
]
# fmt: on


@pytest.mark.parametrize(
    ("version", "response", "expected_ok", "desc"),
    SIGNOFF_CASES,
    ids=[c[3] for c in SIGNOFF_CASES],
)
def test_check_signoff_phrase(version: str, response: str, expected_ok: bool, desc: str) -> None:
    assert check_signoff_phrase(version, response) is expected_ok, desc


def test_expected_signoff_phrase_format() -> None:
    """The expected phrase format is documented in CHANGELOG; lock it."""
    assert expected_signoff_phrase("0.8.3") == "RELEASE OK 0.8.3"
    assert expected_signoff_phrase("1.2.10") == "RELEASE OK 1.2.10"
