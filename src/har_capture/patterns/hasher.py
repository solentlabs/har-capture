"""Salted hasher for correlation-preserving redaction.

This module provides the Hasher class which generates consistent hash-based
placeholders for sensitive values, allowing analysts to correlate redacted
values without knowing the originals.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from har_capture.patterns.redaction import is_mac_value, mac_layout

if TYPE_CHECKING:
    from collections.abc import Callable

_NON_HEX_RE = re.compile(r"[^0-9A-Fa-f]")

# Length-preserving stand-ins (SANITIZATION_SPEC "Length-Preserving Stand-ins").
_STAND_IN_ATTEMPTS = 64
_HEX_LOWER = "0123456789abcdef"
_PRIVATE_IPV4_PREFIX_RE = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")
# A first group that keeps an IPv6 address link-local (fe80::/10) or unique
# local (fc00::/7): kept, as the RFC 1918 prefix is for IPv4.
_LOCAL_IPV6_GROUP_RE = re.compile(r"^(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{0,2})(?=:)", re.IGNORECASE)


class _Draw:
    """A deterministic source of choices, from SHA-256 of a seed in counter mode."""

    def __init__(self, seed: str) -> None:
        self._seed = seed.encode("utf-8", "surrogatepass")
        self._block = 0
        self._buffer = b""

    def below(self, bound: int) -> int:
        """A number in ``range(bound)``."""
        if not self._buffer:
            self._buffer = hashlib.sha256(self._seed + b":" + str(self._block).encode()).digest()
            self._block += 1
        value, self._buffer = self._buffer[0], self._buffer[1:]
        return value % bound

    def char(self, alphabet: str) -> str:
        """One character of ``alphabet``."""
        return alphabet[self.below(len(alphabet))]


def _is_hex_token(value: str) -> bool:
    """Whether the value's letters and digits are all hex digits, with at least one of each."""
    alnum = [c for c in value if c.isascii() and c.isalnum()]
    return (
        all(c in string.hexdigits for c in alnum)
        and any(c.isdigit() for c in alnum)
        and any(c.isalpha() for c in alnum)
    )


def class_stand_in(value: str, draw: _Draw | None, *, hex_letters: bool | None = None) -> str:
    """The value with each character replaced by one of its class (the class rule), or by the class fill.

    A digit becomes a digit, an ASCII letter a letter of the same case (within
    ``a``-``f`` for a hex token), a non-ASCII character lowercase ASCII letters,
    one per UTF-8 byte; every other ASCII character is kept. With no ``draw``
    the fixed fill is written: ``0``, ``X``, ``x``.

    Args:
        value: The value to stand in for
        draw: The choice source, or None for the fill
        hex_letters: Force (or forbid) the hex alphabet; default decides from the value

    Returns:
        A string of the value's UTF-8 byte length
    """
    hex_mode = _is_hex_token(value) if hex_letters is None else hex_letters
    pieces: list[str] = []
    for c in value:
        if not c.isascii():
            width = len(c.encode("utf-8", "surrogatepass"))
            pieces.append(
                "x" * width
                if draw is None
                else "".join(draw.char(string.ascii_lowercase) for _ in range(width))
            )
        elif c.isdigit():
            pieces.append("0" if draw is None else draw.char(string.digits))
        elif c.isalpha():
            if draw is None:
                pieces.append("X" if c.isupper() else "x")
                continue
            alphabet = _HEX_LOWER[10:] if hex_mode else string.ascii_lowercase
            letter = draw.char(alphabet)
            pieces.append(letter.upper() if c.isupper() else letter)
        else:
            pieces.append(c)
    return "".join(pieces)


def _octet_stand_in(octet: str, draw: _Draw | None) -> str:
    """An octet with the same digit count that is still an octet; a zero-padded one stays padded."""
    width = len(octet)
    padded = width > 1 and octet.startswith("0")
    if draw is None:
        return "0" * (width - 1) + "1" if padded else "1" * width
    if padded:
        return str(draw.below(min(256, 10**width))).zfill(width)
    low = 0 if width == 1 else 10 ** (width - 1)
    return str(low + draw.below(min(255, 10**width - 1) - low + 1))


def ipv4_stand_in(ip: str, draw: _Draw | None, *, private: bool) -> str:
    """An IPv4 address of the same length; a private one keeps its RFC 1918 prefix.

    A value that is not four octets of 1-3 digits takes the class rule.
    """
    octets = ip.split(".")
    if len(octets) != 4 or not all(octet.isdigit() and 1 <= len(octet) <= 3 for octet in octets):
        return class_stand_in(ip, draw)
    match = _PRIVATE_IPV4_PREFIX_RE.match(ip) if private else None
    kept = match.group(0).count(".") if match else 0
    return ".".join(octets[:kept] + [_octet_stand_in(octet, draw) for octet in octets[kept:]])


def ipv6_stand_in(address: str, draw: _Draw | None) -> str:
    """An IPv6 address of the same length: hex digits replaced in their case, ``:`` kept.

    A link-local or unique-local first group is kept; a dotted IPv4 tail takes
    the public IPv4 rule. The fill writes ``0`` for every hex digit.
    """
    head, tail = address, ""
    if "." in address:
        cut = address.rfind(":") + 1
        head, tail = address[:cut], address[cut:]
    match = _LOCAL_IPV6_GROUP_RE.match(head)
    kept = match.group(0) if match else ""
    rest = head[len(kept) :]
    body = re.sub(r"[0-9A-Fa-f]", "0", rest) if draw is None else class_stand_in(rest, draw, hex_letters=True)
    return kept + body + (ipv4_stand_in(tail, draw, private=False) if tail else "")


def email_stand_in(email: str, draw: _Draw | None) -> str:
    """An e-mail address of the same length: ``@``, ``.`` and the top-level domain kept."""
    local, at, domain = email.rpartition("@")
    if not at:
        return class_stand_in(email, draw)
    labels = domain.split(".")
    if len(labels) > 1:
        labels = [class_stand_in(label, draw) for label in labels[:-1]] + labels[-1:]
    else:
        labels = [class_stand_in(domain, draw)]
    return f"{class_stand_in(local, draw)}@{'.'.join(labels)}"


def mac_stand_in(mac: str, draw: _Draw | None) -> str:
    """A MAC in the input's layout and letter case: ``02`` then drawn hex digits, or ``X`` per hex digit."""
    if draw is None:
        return re.sub(r"[0-9A-Fa-f]", "X", mac)
    digits = "02" + "".join(draw.char(_HEX_LOWER) for _ in range(10))
    if mac.upper() == mac and any(c.isalpha() for c in _NON_HEX_RE.sub("", mac)):
        digits = digits.upper()
    pieces: list[str] = []
    it = iter(digits)
    for c in mac:
        pieces.append(next(it) if c in string.hexdigits else c)
    return "".join(pieces)


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
        seen_macs: The 12 lowercase hex digits of every MAC this hasher was asked
            to replace (static mode included). The sweeps that follow the
            entries use it to find the same MAC where it is not standalone:
            inside a longer hex run, or as the tail of a default network name.
        preserve_length: Write length-preserving stand-ins instead of placeholders
        avoid_text: Text no stand-in may occur in: the capture as loaded
        stand_ins: The run's record: every stand-in written (and any the input
            already recorded), which the tools treat as redacted
    """

    salt: str | None = None
    hash_length: int = 8
    _cache: dict[str, str] = field(default_factory=dict, repr=False)
    seen_macs: set[str] = field(default_factory=set, repr=False, compare=False)
    preserve_length: bool = False
    avoid_text: str = field(default="", repr=False, compare=False)
    stand_ins: set[str] = field(default_factory=set, repr=False, compare=False)
    _stand_in_owner: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

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

    def stand_in(self, kind: str, value: str, build: Callable[[_Draw | None], str]) -> str:
        """The length-preserving stand-in for ``value`` of ``kind``, recorded when it is safe to trust.

        A recorded stand-in is returned as it is. Without a salt the fill is
        written and recorded. With one, candidates
        are drawn from the salt, kind, value and an attempt number until one
        differs from the value, does not occur in ``avoid_text`` and is no other
        value's stand-in; a value that exhausts the attempts gets the last
        candidate, unrecorded.

        Args:
            kind: The value's kind (a placeholder prefix or address type)
            value: The value replaced
            build: Writes a candidate from a choice source (None: the fill)

        Returns:
            A string of the value's UTF-8 byte length
        """
        if value in self.stand_ins:
            # A recorded stand-in is its own stand-in: a later pass, or a later
            # run, that matches one keeps it and its correlation.
            return value
        cache_key = f"STAND_IN:{kind}:{value}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        if self.salt is None:
            result = build(None)
            self.stand_ins.add(result)
        else:
            result = value
            recorded = False
            for attempt in range(_STAND_IN_ATTEMPTS):
                candidate = build(_Draw(f"{self.salt}:{kind}:{value}:{attempt}"))
                if candidate == value:
                    continue
                result = candidate
                owner = self._stand_in_owner.get(candidate)
                if (owner is None or owner == cache_key) and candidate not in self.avoid_text:
                    recorded = True
                    break
            if recorded:
                self.stand_ins.add(result)
                self._stand_in_owner[result] = cache_key
        self._cache[cache_key] = result
        return result

    def hash_value(self, value: str, prefix: str) -> str:
        """Generate a hashed placeholder for a value (non-format-preserving).

        Args:
            value: The original sensitive value
            prefix: Type prefix (e.g., "SERIAL", "TOKEN")

        Returns:
            Hashed placeholder like "TOKEN_a1b2c3d4" or static "***TOKEN***" if no salt
        """
        if self.preserve_length:
            return self.stand_in(prefix, value, lambda draw: class_stand_in(value, draw))
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
        if is_mac_value(mac):
            self.seen_macs.add(_NON_HEX_RE.sub("", mac).lower())
        if self.preserve_length:
            if is_mac_value(mac):
                return self.stand_in("MAC", mac, lambda draw: mac_stand_in(mac, draw))
            return self.stand_in("MAC", mac, lambda draw: class_stand_in(mac, draw))
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
        if self.preserve_length:
            kind = "PRIV_IP" if is_private else "PUB_IP"
            return self.stand_in(kind, ip, lambda draw: ipv4_stand_in(ip, draw, private=is_private))
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
        if self.preserve_length:
            return self.stand_in("IPV6", ipv6, lambda draw: ipv6_stand_in(ipv6, draw))
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
        if self.preserve_length:
            return self.stand_in("EMAIL", email, lambda draw: email_stand_in(email, draw))
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
            "password": "PASS",  # pragma: allowlist secret
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
