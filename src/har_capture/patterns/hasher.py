"""Salted hasher for correlation-preserving redaction.

This module provides the Hasher class which generates consistent hash-based
placeholders for sensitive values, allowing analysts to correlate redacted
values without knowing the originals.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field

from har_capture.patterns.redaction import is_mac_value, mac_layout

_NON_HEX_RE = re.compile(r"[^0-9A-Fa-f]")


def _mac_digest_input(mac: str) -> str:
    """Canonical text a MAC is hashed from: its digits as uppercase colon pairs.

    Every layout of one MAC reads the same, and the colon form is what every
    release before 0.13.0 hashed, so a fixed salt keeps giving a colon MAC the
    same placeholder. A value in no MAC layout is hashed as it was then.
    """
    if not is_mac_value(mac):
        return mac.upper().replace("-", ":")
    digits = _NON_HEX_RE.sub("", mac).upper()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


@dataclass
class Hasher:
    """Salted hasher for correlation-preserving redaction.

    Generates consistent hash-based placeholders for the same input value,
    allowing analysts to correlate redacted values without knowing the originals.

    Uses format-preserving hashes where possible:
    - MAC addresses: 02:xx:xx:xx:xx:xx (locally administered, in the input's layout)
    - Private IPs: 10.255.x.x
    - Public IPs: 192.0.2.x (TEST-NET-1)
    - IPv6: 2001:db8::xxxx:xxxx (documentation prefix)
    - Email: user_xxx@redacted.invalid

    Attributes:
        salt: The salt used for hashing. If None, uses static placeholders.
        hash_length: Number of hex characters in the hash (default 8).
        _cache: Internal cache mapping original values to their hashed replacements.
    """

    salt: str | None = None
    hash_length: int = 8
    _cache: dict[str, str] = field(default_factory=dict, repr=False)

    @staticmethod
    def generate_salt() -> str:
        """Generate a random salt for hashing.

        This separates salt generation from hasher creation, allowing the salt
        to be stored in reports for later reconstruction of the same hasher.

        Returns:
            A 32-character hex string (16 bytes of randomness)
        """
        return secrets.token_hex(16)

    @classmethod
    def create(cls, salt: str | None = "auto") -> Hasher:
        """Create a new hasher with the specified salt.

        Args:
            salt: Salt for hashing. Options:
                - "auto" or "random": Generate random salt (default)
                - None: Use static placeholders (no hashing)
                - Any string: Use as salt for consistent hashing

        Returns:
            Configured Hasher instance
        """
        actual_salt: str | None
        if salt in ("auto", "random"):
            actual_salt = cls.generate_salt()
        else:
            actual_salt = salt

        return cls(salt=actual_salt)

    def _get_hash_bytes(self, value: str, prefix: str) -> bytes:
        """Generate raw hash bytes for a value.

        Args:
            value: The original sensitive value
            prefix: Type prefix for namespacing

        Returns:
            Raw SHA-256 hash bytes
        """
        salted = f"{self.salt}:{prefix}:{value}"
        # surrogatepass: a JSON body can carry a lone surrogate (`"\ud800"`), and
        # hashing it must not crash the run.
        return hashlib.sha256(salted.encode("utf-8", "surrogatepass")).digest()

    def hash_value(self, value: str, prefix: str) -> str:
        """Generate a hashed placeholder for a value (non-format-preserving).

        Args:
            value: The original sensitive value
            prefix: Type prefix (e.g., "SERIAL", "TOKEN")

        Returns:
            Hashed placeholder like "TOKEN_a1b2c3d4" or static "***TOKEN***" if no salt
        """
        if self.salt is None:
            return f"***{prefix}***"

        cache_key = f"{prefix}:{value}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_bytes = self._get_hash_bytes(value, prefix)
        short_hash = hash_bytes[: self.hash_length // 2].hex()

        result = f"{prefix}_{short_hash}"
        self._cache[cache_key] = result
        return result

    def hash_mac(self, mac: str) -> str:
        """Hash a MAC address (format-preserving).

        The placeholder is in the locally administered range (first octet
        ``02``: locally administered, unicast) and occupies the input's
        layout — separator and grouping survive, so a consumer that parses
        ``AABBCCDDEEFF`` or ``aabb.ccdd.eeff`` still parses the placeholder.
        The hash is taken over the hex digits alone, so every layout of one
        MAC correlates. A value in no MAC layout gets the colon form.

        Args:
            mac: MAC address string (any layout)

        Returns:
            Format-preserving MAC like "02:a1:b2:c3:d4:e5" in the input's
            layout, or "XX:XX:XX:XX:XX:XX" if no salt
        """
        if self.salt is None:
            return "XX:XX:XX:XX:XX:XX"

        separator = mac_layout(mac)
        layout = ":" if separator is None else separator
        normalized = _mac_digest_input(mac)
        cache_key = f"MAC{layout}:{normalized}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_bytes = self._get_hash_bytes(normalized, "MAC")
        digits = "02" + hash_bytes[:5].hex()
        if layout == ".":
            result = f"{digits[:4]}.{digits[4:8]}.{digits[8:]}"
        else:
            result = layout.join(digits[i : i + 2] for i in range(0, 12, 2))

        self._cache[cache_key] = result
        return result

    def hash_ip(self, ip: str, is_private: bool = True) -> str:
        """Hash an IP address (format-preserving).

        Uses reserved ranges:
        - Private: 10.255.x.x (within RFC 1918 private range)
        - Public: 192.0.2.x (TEST-NET-1, RFC 5737 documentation range)

        Args:
            ip: IP address string
            is_private: Whether this is a private IP

        Returns:
            Format-preserving IP like "10.255.42.17" or "0.0.0.0" if no salt
        """
        if self.salt is None:
            return "0.0.0.0"

        prefix = "PRIV_IP" if is_private else "PUB_IP"
        cache_key = f"{prefix}:{ip}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_bytes = self._get_hash_bytes(ip, prefix)

        if is_private:
            # 10.255.x.x - uses 10.255 prefix (clearly in private range)
            result = f"10.255.{hash_bytes[0]}.{hash_bytes[1]}"
        else:
            # 192.0.2.x - TEST-NET-1 (RFC 5737, reserved for documentation)
            result = f"192.0.2.{hash_bytes[0]}"

        self._cache[cache_key] = result
        return result

    def hash_ipv6(self, ipv6: str) -> str:
        """Hash an IPv6 address (format-preserving).

        Uses 2001:db8::/32 documentation prefix (RFC 3849).

        Args:
            ipv6: IPv6 address string

        Returns:
            Format-preserving IPv6 like "2001:db8::a1b2:c3d4" or "::" if no salt
        """
        if self.salt is None:
            return "::"

        cache_key = f"IPV6:{ipv6}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_bytes = self._get_hash_bytes(ipv6, "IPV6")
        # Use documentation prefix + hash-derived suffix
        result = f"2001:db8::{hash_bytes[0]:02x}{hash_bytes[1]:02x}:{hash_bytes[2]:02x}{hash_bytes[3]:02x}"

        self._cache[cache_key] = result
        return result

    def hash_email(self, email: str) -> str:
        """Hash an email address (format-preserving).

        Uses .invalid TLD (RFC 2606 reserved for testing).

        Args:
            email: Email address string

        Returns:
            Format-preserving email like "user_a1b2c3d4@redacted.invalid" or "x@x.invalid" if no salt
        """
        if self.salt is None:
            return "x@x.invalid"

        normalized = email.lower()
        cache_key = f"EMAIL:{normalized}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_bytes = self._get_hash_bytes(normalized, "EMAIL")
        short_hash = hash_bytes[:4].hex()
        result = f"user_{short_hash}@redacted.invalid"

        self._cache[cache_key] = result
        return result

    def hash_generic(self, value: str, prefix: str) -> str:
        """Hash a generic sensitive value (non-format-preserving).

        Args:
            value: The sensitive value
            prefix: Type prefix (e.g., "SERIAL", "TOKEN")

        Returns:
            Hashed placeholder like "SERIAL_a1b2c3d4"
        """
        return self.hash_value(value, prefix)

    def hash_sensitive_value(self, value: str, category: str) -> str:
        """Hash a heuristically-detected sensitive value with category-aware prefix.

        Maps heuristic detection categories to appropriate hash prefixes for
        human-readable redacted output. This is used when heuristics detect
        potential PII but can't determine the exact type.

        Args:
            value: The sensitive value to hash
            category: Category from heuristics analysis. Common values:
                - "wifi_ssid": WiFi network names
                - "credential": High-entropy potential passwords
                - "device_name": Device/host names
                - "suspicious": Values adjacent to redacted content

        Returns:
            Hashed value like "WIFI_a1b2c3d4" or "***WIFI***" if no salt

        Example:
            >>> hasher = Hasher.create("test-salt")
            >>> hasher.hash_sensitive_value("MyNetwork-5G", "wifi_ssid")
            'WIFI_...'
            >>> hasher = Hasher.create(None)
            >>> hasher.hash_sensitive_value("password123", "credential")
            '***CRED***'
        """
        # Map heuristic categories to prefixes. Every prefix emitted here
        # must be listed in allowlist.json hash_prefixes so downstream
        # tools recognize the placeholder as already redacted.
        prefix_map = {
            "wifi_ssid": "WIFI",
            "credential": "CRED",
            "device_name": "DEVICE",
            "suspicious": "SENSITIVE",
            "serial_number": "SERIAL",
            "account": "ACCOUNT",
            "field": "FIELD",
            "phone": "PHONE",
            "ssn": "SSN",
        }
        prefix = prefix_map.get(category, "SENSITIVE")
        return self.hash_value(value, prefix)
