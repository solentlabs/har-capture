"""Salted hasher for correlation-preserving redaction.

This module provides the Hasher class which generates consistent hash-based
placeholders for sensitive values, allowing analysts to correlate redacted
values without knowing the originals.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field


@dataclass
class Hasher:
    """Salted hasher for correlation-preserving redaction.

    Generates consistent hash-based placeholders for the same input value,
    allowing analysts to correlate redacted values without knowing the originals.

    Uses format-preserving hashes where possible:
    - MAC addresses: 02:xx:xx:xx:xx:xx (locally administered)
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
            # Generate a random salt for this session
            actual_salt = secrets.token_hex(16)
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
        return hashlib.sha256(salted.encode("utf-8")).digest()

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

        Uses locally administered address range (02:xx:xx:xx:xx:xx).
        The 02 prefix indicates a locally administered, unicast address.

        Args:
            mac: MAC address string (any format)

        Returns:
            Format-preserving MAC like "02:a1:b2:c3:d4:e5" or "XX:XX:XX:XX:XX:XX" if no salt
        """
        if self.salt is None:
            return "XX:XX:XX:XX:XX:XX"

        # Normalize for consistent hashing
        normalized = mac.upper().replace("-", ":")
        cache_key = f"MAC:{normalized}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_bytes = self._get_hash_bytes(normalized, "MAC")
        # Use 02 prefix (locally administered bit set) + 5 bytes from hash
        result = f"02:{hash_bytes[0]:02x}:{hash_bytes[1]:02x}:{hash_bytes[2]:02x}:{hash_bytes[3]:02x}:{hash_bytes[4]:02x}"

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
