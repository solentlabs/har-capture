"""Table-driven tests for the Hasher class."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from har_capture.patterns.hasher import Hasher
from har_capture.patterns.redaction import is_redacted, mac_layout

_FIXTURES = json.loads((Path(__file__).parent.parent / "fixtures" / "test_hasher.json").read_text())


def _cases(key: str) -> list[dict]:
    return _FIXTURES[key]["cases"]


def _ids(key: str) -> list[str]:
    return [c["id"] for c in _cases(key)]


@pytest.mark.parametrize("case", _cases("create_cases"), ids=_ids("create_cases"))
def test_hasher_create(case: dict) -> None:
    """Hasher.create() mints, disables, or keeps the salt."""
    hasher = Hasher.create(salt=case["salt"])

    if case["expected"] == "random_hex":
        assert hasher.salt is not None
        assert re.fullmatch(r"[0-9a-f]{32}", hasher.salt)
    else:
        assert hasher.salt == case["expected"]


@pytest.mark.parametrize("case", _cases("hash_mac_format_cases"), ids=_ids("hash_mac_format_cases"))
def test_hash_mac_keeps_layout(case: dict) -> None:
    """hash_mac() output occupies the input's layout, in the locally administered range."""
    result = Hasher.create(salt="test-salt").hash_mac(case["input"])
    assert re.fullmatch(case["output_re"], result), result


@pytest.mark.parametrize(
    "case", _cases("hash_mac_normalization_cases"), ids=_ids("hash_mac_normalization_cases")
)
def test_hash_mac_correlates_across_layouts(case: dict) -> None:
    """One hasher gives every layout of one MAC the same digits, each in its own layout."""
    hasher = Hasher.create(salt="normalize")
    results = [hasher.hash_mac(mac) for mac in case["inputs"]]

    assert len({re.sub(r"[^0-9a-f]", "", r) for r in results}) == 1
    for mac, result in zip(case["inputs"], results, strict=True):
        expected = mac_layout(mac)
        assert mac_layout(result) == (":" if expected is None else expected), (mac, result)


@pytest.mark.parametrize("case", _cases("hash_mac_stable_cases"), ids=_ids("hash_mac_stable_cases"))
def test_hash_mac_stable_under_fixed_salt(case: dict) -> None:
    """A fixed salt keeps giving a MAC the placeholder earlier releases gave it."""
    assert Hasher.create(salt=case["salt"]).hash_mac(case["input"]) == case["expected"]


def test_hash_mac_separated_placeholders_are_redacted() -> None:
    """The allowlist recognizes the colon and hyphen placeholders text scans meet."""
    hasher = Hasher.create(salt="test-salt")
    assert is_redacted(hasher.hash_mac("3C:7A:8A:12:34:56"))
    assert is_redacted(hasher.hash_mac("3C-7A-8A-12-34-56"))


def test_hash_mac_without_salt() -> None:
    """Test hash_mac() returns static placeholder without salt."""
    hasher = Hasher.create(salt=None)
    result = hasher.hash_mac("AA:BB:CC:DD:EE:FF")
    assert result == "XX:XX:XX:XX:XX:XX"


def test_hash_mac_consistency() -> None:
    """Test same MAC produces same hash with same salt."""
    hasher = Hasher.create(salt="consistent")
    result1 = hasher.hash_mac("AA:BB:CC:DD:EE:FF")
    result2 = hasher.hash_mac("AA:BB:CC:DD:EE:FF")
    assert result1 == result2


def test_hash_mac_different_values() -> None:
    """Test different MACs produce different hashes."""
    hasher = Hasher.create(salt="test")
    result1 = hasher.hash_mac("AA:BB:CC:DD:EE:FF")
    result2 = hasher.hash_mac("11:22:33:44:55:66")
    assert result1 != result2


@pytest.mark.parametrize("case", _cases("hash_ip_cases"), ids=_ids("hash_ip_cases"))
def test_hash_ip_with_salt(case: dict) -> None:
    """hash_ip() keeps IPv4 form in the reserved range for its class."""
    result = Hasher.create(salt="test-salt").hash_ip(case["ip"], is_private=case["is_private"])

    assert result.startswith(case["prefix"]), result
    parts = result.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def test_hash_ip_without_salt() -> None:
    """Test hash_ip() returns static placeholder without salt."""
    hasher = Hasher.create(salt=None)
    assert hasher.hash_ip("192.168.1.1", is_private=True) == "0.0.0.0"
    assert hasher.hash_ip("8.8.8.8", is_private=False) == "0.0.0.0"


def test_hash_ip_caching() -> None:
    """Test IP hashing uses cache for same values."""
    hasher = Hasher.create(salt="cache-test")
    result1 = hasher.hash_ip("192.168.1.1", is_private=True)
    result2 = hasher.hash_ip("192.168.1.1", is_private=True)
    assert result1 == result2
    # Verify it's in the cache
    assert "PRIV_IP:192.168.1.1" in hasher._cache


@pytest.mark.parametrize("case", _cases("hash_ipv6_cases"), ids=_ids("hash_ipv6_cases"))
def test_hash_ipv6_with_salt(case: dict) -> None:
    """hash_ipv6() writes into the documentation prefix."""
    assert Hasher.create(salt="test-salt").hash_ipv6(case["ip"]).startswith("2001:db8::")


def test_hash_ipv6_without_salt() -> None:
    """Test hash_ipv6() returns static placeholder without salt."""
    hasher = Hasher.create(salt=None)
    result = hasher.hash_ipv6("fe80::1")
    assert result == "::"


def test_hash_ipv6_format() -> None:
    """Test hash_ipv6() produces valid IPv6 format."""
    hasher = Hasher.create(salt="format-test")
    result = hasher.hash_ipv6("fe80::1")

    # Should be in format 2001:db8::xxxx:xxxx
    assert result.startswith("2001:db8::")
    suffix = result.replace("2001:db8::", "")
    parts = suffix.split(":")
    assert len(parts) == 2
    assert all(len(p) == 4 for p in parts)


def test_hash_ipv6_caching() -> None:
    """Test hash_ipv6() returns cached results for repeated calls."""
    hasher = Hasher.create(salt="cache-test")

    # Call twice with same value - second should hit cache
    result1 = hasher.hash_ipv6("2001:db8::1")
    result2 = hasher.hash_ipv6("2001:db8::1")

    # Both should be identical (from cache)
    assert result1 == result2


@pytest.mark.parametrize("case", _cases("hash_email_cases"), ids=_ids("hash_email_cases"))
def test_hash_email_with_salt(case: dict) -> None:
    """hash_email() writes a placeholder in the .invalid TLD."""
    result = Hasher.create(salt="test-salt").hash_email(case["email"])
    assert re.fullmatch(r"user_[0-9a-f]{8}@redacted\.invalid", result), result


def test_hash_email_without_salt() -> None:
    """Test hash_email() returns static placeholder without salt."""
    hasher = Hasher.create(salt=None)
    result = hasher.hash_email("user@example.com")
    assert result == "x@x.invalid"


def test_hash_email_normalization() -> None:
    """Test emails are normalized to lowercase before hashing."""
    hasher = Hasher.create(salt="normalize")
    result1 = hasher.hash_email("User@Example.COM")
    result2 = hasher.hash_email("user@example.com")
    assert result1 == result2


@pytest.mark.parametrize("case", _cases("hash_value_cases"), ids=_ids("hash_value_cases"))
def test_hash_value_with_salt(case: dict) -> None:
    """hash_value() writes PREFIX_ plus 8 hex characters."""
    result = Hasher.create(salt="test-salt").hash_value(case["value"], case["prefix"])
    assert re.fullmatch(rf"{case['prefix']}_[0-9a-f]{{8}}", result), result


@pytest.mark.parametrize("case", _cases("hash_value_cases"), ids=_ids("hash_value_cases"))
def test_hash_value_without_salt(case: dict) -> None:
    """hash_value() returns the static placeholder without a salt."""
    assert Hasher.create(salt=None).hash_value(case["value"], case["prefix"]) == f"***{case['prefix']}***"


def test_hash_generic_is_alias() -> None:
    """Test hash_generic() is an alias for hash_value()."""
    hasher = Hasher.create(salt="test")
    result1 = hasher.hash_value("test", "PREFIX")
    result2 = hasher.hash_generic("test", "PREFIX")
    assert result1 == result2


class TestHasherCaching:
    """Tests for hasher internal caching behavior."""

    def test_cache_populated_on_hash(self) -> None:
        """Test cache is populated after hashing."""
        hasher = Hasher.create(salt="cache-test")
        assert len(hasher._cache) == 0

        hasher.hash_mac("AA:BB:CC:DD:EE:FF")
        assert len(hasher._cache) == 1

        hasher.hash_ip("192.168.1.1", is_private=True)
        assert len(hasher._cache) == 2

    def test_cache_hit_returns_same_value(self) -> None:
        """Test cache hit returns identical value."""
        hasher = Hasher.create(salt="cache-hit")

        # First call populates cache
        result1 = hasher.hash_email("test@example.com")

        # Second call should hit cache
        result2 = hasher.hash_email("test@example.com")

        assert result1 is result2  # Same object, not just equal

    def test_different_salts_produce_different_hashes(self) -> None:
        """Test different salts produce different results."""
        hasher1 = Hasher.create(salt="salt1")
        hasher2 = Hasher.create(salt="salt2")

        result1 = hasher1.hash_mac("AA:BB:CC:DD:EE:FF")
        result2 = hasher2.hash_mac("AA:BB:CC:DD:EE:FF")

        assert result1 != result2
