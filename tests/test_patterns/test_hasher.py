"""Table-driven tests for the Hasher class."""

from __future__ import annotations

import pytest

from har_capture.patterns.hasher import Hasher

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ Hasher.create() test cases                                                  │
# ├──────────────┬─────────────────────┬────────────────────────────────────────┤
# │ salt_input   │ expected_salt_type  │ description                            │
# ├──────────────┼─────────────────────┼────────────────────────────────────────┤
# │ "auto"       │ str (32 hex chars)  │ generates random salt                  │
# │ "random"     │ str (32 hex chars)  │ alias for auto                         │
# │ None         │ None                │ static placeholders mode               │
# │ "my-salt"    │ "my-salt"           │ custom salt preserved                  │
# │ ""           │ ""                  │ empty string is valid salt             │
# └──────────────┴─────────────────────┴────────────────────────────────────────┘
#
# fmt: off
CREATE_CASES = [
    ("auto",     "random_hex", "generates random salt"),
    ("random",   "random_hex", "alias for auto"),
    (None,       None,         "static placeholders mode"),
    ("my-salt",  "my-salt",    "custom salt preserved"),
    ("",         "",           "empty string is valid salt"),
]
# fmt: on


@pytest.mark.parametrize(("salt_input", "expected", "desc"), CREATE_CASES)
def test_hasher_create(salt_input: str | None, expected: str | None, desc: str) -> None:
    """Test Hasher.create() with various salt options."""
    hasher = Hasher.create(salt=salt_input)

    if expected == "random_hex":
        assert hasher.salt is not None
        assert len(hasher.salt) == 32  # 16 bytes = 32 hex chars
        assert all(c in "0123456789abcdef" for c in hasher.salt)
    else:
        assert hasher.salt == expected


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ hash_mac() test cases                                                       │
# ├─────────────────────────┬───────────────────┬───────────────────────────────┤
# │ input                   │ expected_prefix   │ description                   │
# ├─────────────────────────┼───────────────────┼───────────────────────────────┤
# │ "AA:BB:CC:DD:EE:FF"     │ "02:"             │ standard colon format         │
# │ "aa:bb:cc:dd:ee:ff"     │ "02:"             │ lowercase                     │
# │ "AA-BB-CC-DD-EE-FF"     │ "02:"             │ dash separator                │
# │ "AABBCCDDEEFF"          │ "02:"             │ no separator                  │
# │ "aabbccddeeff"          │ "02:"             │ lowercase no separator        │
# └─────────────────────────┴───────────────────┴───────────────────────────────┘
#
# fmt: off
MAC_CASES = [
    ("AA:BB:CC:DD:EE:FF", "02:", "standard colon format"),
    ("aa:bb:cc:dd:ee:ff", "02:", "lowercase"),
    ("AA-BB-CC-DD-EE-FF", "02:", "dash separator"),
    ("AABBCCDDEEFF",      "02:", "no separator (normalized)"),
    ("aabbccddeeff",      "02:", "lowercase no separator"),
]
# fmt: on


@pytest.mark.parametrize(("mac_input", "expected_prefix", "desc"), MAC_CASES)
def test_hash_mac_with_salt(mac_input: str, expected_prefix: str, desc: str) -> None:
    """Test hash_mac() produces format-preserving output with salt."""
    hasher = Hasher.create(salt="test-salt")
    result = hasher.hash_mac(mac_input)

    assert result.startswith(expected_prefix), f"Expected prefix {expected_prefix}, got {result}"
    # Should be valid MAC format: 02:xx:xx:xx:xx:xx
    parts = result.split(":")
    assert len(parts) == 6
    assert all(len(p) == 2 for p in parts)


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


def test_hash_mac_normalization() -> None:
    """Test different formats of same MAC produce same hash."""
    hasher = Hasher.create(salt="normalize")
    result1 = hasher.hash_mac("AA:BB:CC:DD:EE:FF")
    result2 = hasher.hash_mac("aa:bb:cc:dd:ee:ff")
    result3 = hasher.hash_mac("AA-BB-CC-DD-EE-FF")
    assert result1 == result2 == result3


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ hash_ip() test cases                                                        │
# ├─────────────────────────┬────────────┬──────────────┬───────────────────────┤
# │ input                   │ is_private │ expected_pfx │ description           │
# ├─────────────────────────┼────────────┼──────────────┼───────────────────────┤
# │ "192.168.1.1"           │ True       │ "10.255."    │ private IP            │
# │ "10.0.0.1"              │ True       │ "10.255."    │ private 10.x          │
# │ "172.16.0.1"            │ True       │ "10.255."    │ private 172.x         │
# │ "8.8.8.8"               │ False      │ "192.0.2."   │ public IP             │
# │ "1.1.1.1"               │ False      │ "192.0.2."   │ cloudflare DNS        │
# └─────────────────────────┴────────────┴──────────────┴───────────────────────┘
#
# fmt: off
IP_CASES = [
    ("192.168.1.1", True,  "10.255.",  "private IP"),
    ("10.0.0.1",    True,  "10.255.",  "private 10.x"),
    ("172.16.0.1",  True,  "10.255.",  "private 172.x"),
    ("8.8.8.8",     False, "192.0.2.", "public IP (Google DNS)"),
    ("1.1.1.1",     False, "192.0.2.", "public IP (Cloudflare)"),
]
# fmt: on


@pytest.mark.parametrize(("ip_input", "is_private", "expected_prefix", "desc"), IP_CASES)
def test_hash_ip_with_salt(ip_input: str, is_private: bool, expected_prefix: str, desc: str) -> None:
    """Test hash_ip() produces format-preserving output."""
    hasher = Hasher.create(salt="test-salt")
    result = hasher.hash_ip(ip_input, is_private=is_private)

    assert result.startswith(expected_prefix), f"Expected prefix {expected_prefix}, got {result}"
    # Should be valid IP format
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


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ hash_ipv6() test cases                                                      │
# ├─────────────────────────────────────┬───────────────┬───────────────────────┤
# │ input                               │ expected_pfx  │ description           │
# ├─────────────────────────────────────┼───────────────┼───────────────────────┤
# │ "fe80::1"                           │ "2001:db8::"  │ link-local            │
# │ "2001:4860:4860::8888"              │ "2001:db8::"  │ Google DNS IPv6       │
# │ "::1"                               │ "2001:db8::"  │ localhost             │
# │ "fd00::1234:5678"                   │ "2001:db8::"  │ unique local          │
# └─────────────────────────────────────┴───────────────┴───────────────────────┘
#
# fmt: off
IPV6_CASES = [
    ("fe80::1",                "2001:db8::", "link-local address"),
    ("2001:4860:4860::8888",   "2001:db8::", "Google DNS IPv6"),
    ("::1",                    "2001:db8::", "localhost"),
    ("fd00::1234:5678",        "2001:db8::", "unique local address"),
]
# fmt: on


@pytest.mark.parametrize(("ipv6_input", "expected_prefix", "desc"), IPV6_CASES)
def test_hash_ipv6_with_salt(ipv6_input: str, expected_prefix: str, desc: str) -> None:
    """Test hash_ipv6() produces format-preserving output."""
    hasher = Hasher.create(salt="test-salt")
    result = hasher.hash_ipv6(ipv6_input)

    assert result.startswith(expected_prefix), f"Expected prefix {expected_prefix}, got {result}"


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


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ hash_email() test cases                                                     │
# ├─────────────────────────────────────┬───────────────────────────────────────┤
# │ input                               │ description                           │
# ├─────────────────────────────────────┼───────────────────────────────────────┤
# │ "user@example.com"                  │ standard email                        │
# │ "USER@EXAMPLE.COM"                  │ uppercase (normalized)                │
# │ "test.user+tag@domain.co.uk"        │ complex email                         │
# │ "a@b.c"                             │ minimal valid email                   │
# └─────────────────────────────────────┴───────────────────────────────────────┘
#
# fmt: off
EMAIL_CASES = [
    ("user@example.com",            "standard email"),
    ("USER@EXAMPLE.COM",            "uppercase (normalized)"),
    ("test.user+tag@domain.co.uk",  "complex email"),
    ("a@b.c",                       "minimal valid email"),
]
# fmt: on


@pytest.mark.parametrize(("email_input", "desc"), EMAIL_CASES)
def test_hash_email_with_salt(email_input: str, desc: str) -> None:
    """Test hash_email() produces format-preserving output."""
    hasher = Hasher.create(salt="test-salt")
    result = hasher.hash_email(email_input)

    assert result.startswith("user_"), f"Expected user_ prefix, got {result}"
    assert result.endswith("@redacted.invalid"), f"Expected @redacted.invalid suffix, got {result}"


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


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ hash_value() / hash_generic() test cases                                    │
# ├────────────────┬─────────────┬──────────────────────────────────────────────┤
# │ value          │ prefix      │ description                                  │
# ├────────────────┼─────────────┼──────────────────────────────────────────────┤
# │ "ABC123"       │ "SERIAL"    │ serial number                                │
# │ "secret-token" │ "TOKEN"     │ auth token                                   │
# │ "password123"  │ "PASS"      │ password                                     │
# │ ""             │ "EMPTY"     │ empty value                                  │
# └────────────────┴─────────────┴──────────────────────────────────────────────┘
#
# fmt: off
GENERIC_CASES = [
    ("ABC123",       "SERIAL", "serial number"),
    ("secret-token", "TOKEN",  "auth token"),
    ("password123",  "PASS",   "password"),
    ("",             "EMPTY",  "empty value"),
]
# fmt: on


@pytest.mark.parametrize(("value", "prefix", "desc"), GENERIC_CASES)
def test_hash_value_with_salt(value: str, prefix: str, desc: str) -> None:
    """Test hash_value() produces prefixed hashed output."""
    hasher = Hasher.create(salt="test-salt")
    result = hasher.hash_value(value, prefix)

    assert result.startswith(f"{prefix}_"), f"Expected {prefix}_ prefix, got {result}"
    # Should have 8 hex chars after underscore
    hash_part = result.split("_")[1]
    assert len(hash_part) == 8
    assert all(c in "0123456789abcdef" for c in hash_part)


@pytest.mark.parametrize(("value", "prefix", "desc"), GENERIC_CASES)
def test_hash_value_without_salt(value: str, prefix: str, desc: str) -> None:
    """Test hash_value() returns static placeholder without salt."""
    hasher = Hasher.create(salt=None)
    result = hasher.hash_value(value, prefix)
    assert result == f"***{prefix}***"


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
