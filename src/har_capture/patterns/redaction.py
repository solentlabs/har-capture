"""Consolidated redaction checking logic.

This module provides a single source of truth for determining if a value
has been redacted or sanitized. It combines pattern matching from both
configuration files and code-based patterns.

Also provides shared detection helpers used by both sanitization and
validation modules.
"""

from __future__ import annotations

import base64
import functools
import ipaddress
import json
import logging
import re
import urllib.parse
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from .loader import load_allowlist

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

_LOGGER = logging.getLogger(__name__)


def _check_patterns(value: str, allowlist: dict[str, Any]) -> bool:
    """Check if a value matches any pattern in the allowlist.

    Args:
        value: Value to check
        allowlist: Allowlist configuration data

    Returns:
        True if value matches any pattern
    """
    # Check static placeholders (exact matches)
    static = allowlist.get("static_placeholders", {})
    if value in static.get("values", []):
        return True

    # Check hash prefixes (e.g., DEVICE_xxxxxxxx)
    prefixes = allowlist.get("hash_prefixes", {})
    for prefix in prefixes.get("values", []):
        if value.startswith(prefix):
            return True

    # Check format-preserving patterns (e.g., 02:xx:xx:xx:xx:xx MACs)
    format_patterns = allowlist.get("format_preserving_patterns", {})
    for pattern_def in format_patterns.values():
        if isinstance(pattern_def, dict) and "pattern" in pattern_def:
            try:
                if re.match(pattern_def["pattern"], value, re.IGNORECASE):
                    return True
            except re.error:
                _LOGGER.warning("Skipping invalid format-preserving regex pattern")

    # Check additional redaction patterns (skip invalid patterns gracefully)
    redacted_patterns = allowlist.get("redaction_patterns", {})
    for pattern in redacted_patterns.get("values", []):
        try:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        except re.error:  # noqa: PERF203 - must check each pattern individually
            _LOGGER.warning("Skipping invalid regex pattern in allowlist")
    return False


def is_redacted(value: str, custom_patterns: str | dict[str, Any] | None = None) -> bool:
    """Check if a value appears to be properly redacted.

    This function checks if a value matches:
    1. Standard redaction patterns (from allowlist.json)
    2. Format-preserving hash patterns (from allowlist.json)
    3. Hash prefix patterns (from allowlist.json)
    4. Static placeholder values (from allowlist.json)

    Args:
        value: Value to check
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if value appears to be redacted

    Examples:
        >>> is_redacted("[REDACTED]")
        True
        >>> is_redacted("DEVICE_a1b2c3d4")
        True
        >>> is_redacted("my_password")
        False
    """
    allowlist = load_allowlist(custom_patterns)
    return _check_patterns(value, allowlist)


# A redaction placeholder is one opaque token: alphanumerics plus the punctuation
# the placeholder formats actually use (`PASS_a1b2c3d4`, `XX:XX:XX:XX:XX:XX`,
# `user_x@redacted.invalid`, `***SERIAL***`, `[REDACTED]`, `2001:db8::1`).
# Structural punctuation — braces, quotes, semicolons, equals — means the string
# is a document, not a placeholder.
_PLACEHOLDER_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-.:@\[\]*/]+")


def is_fully_redacted(value: str, custom_patterns: str | dict[str, Any] | None = None) -> bool:
    """Check if a string is *entirely* a redaction placeholder.

    :func:`is_redacted` answers "does this value look redacted", and the
    allowlist families backing it are matched with :func:`re.search` — correct
    for a single field value, wrong for a whole document. A minified CSS body
    carrying ``#000000``, a JSON body with ``"ver":"0.000000"``, or any body
    containing the literal ``XXX`` would otherwise report as fully redacted and
    skip every check the caller meant to run.

    This predicate requires the whole string to be one placeholder token: no
    whitespace, no markup, no structural punctuation, and a match that accounts
    for the entire token rather than appearing somewhere inside it.

    Args:
        value: String to check
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if the whole string is a redaction placeholder

    Examples:
        >>> is_fully_redacted("[REDACTED]")
        True
        >>> is_fully_redacted("body{color:#000000}")
        False
        >>> is_fully_redacted("<p>hunter2</p>")
        False
    """
    stripped = value.strip()
    if not stripped or "<" in stripped or not _PLACEHOLDER_TOKEN_RE.fullmatch(stripped):
        return False

    allowlist = load_allowlist(custom_patterns)

    if stripped in allowlist.get("static_placeholders", {}).get("values", []):
        return True

    # A hash prefix must account for the whole token, not just start it —
    # `PASS_a1b2c3d4somethingelse` is not a placeholder.
    for prefix in allowlist.get("hash_prefixes", {}).get("values", []):
        if re.fullmatch(re.escape(prefix) + r"\w+", stripped):
            return True

    # Format-preserving patterns describe single-value formats and are
    # deliberately one-sided (an IPv6 documentation *prefix*, an email
    # *suffix*), so neither end can be anchored here. The token-class guard
    # above is what stops a document from reaching this point.
    format_patterns = allowlist.get("format_preserving_patterns", {})
    for pattern_def in format_patterns.values():
        if isinstance(pattern_def, dict) and "pattern" in pattern_def:
            try:
                if re.search(pattern_def["pattern"], stripped, re.IGNORECASE):
                    return True
            except re.error:
                _LOGGER.warning("Skipping invalid format-preserving regex pattern")

    # These are the unanchored ones (`XXX+`, `0{6,}`, `REDACTED`) — they must
    # consume the entire token here, not merely appear within it.
    for pattern in allowlist.get("redaction_patterns", {}).get("values", []):
        try:
            if re.fullmatch(pattern, stripped, re.IGNORECASE):
                return True
        except re.error:  # noqa: PERF203 - must check each pattern individually
            _LOGGER.warning("Skipping invalid regex pattern in allowlist")

    return False


def is_allowlisted(value: str, allowlist: dict[str, Any] | None = None) -> bool:
    """Check if a value is in the allowlist.

    This is a wrapper around is_redacted() that accepts a pre-loaded allowlist.
    Maintained for backward compatibility.

    Args:
        value: Value to check
        allowlist: Allowlist data (loads default if None)

    Returns:
        True if the value should be ignored
    """
    if allowlist is None:
        return is_redacted(value)

    return _check_patterns(value, allowlist)


# ── Shared detection helpers ─────────────────────────────────────────────────

# The one MAC definition for the sanitizer, the validator and check_for_pii
# (pii.json's mac_address regex carries it verbatim; a test pins the two): six
# hex pairs joined by ':' or '-', wherever they occur. No boundary is required
# on either side — a MAC glued to an identifier (`wanmac3C:7A:…`) is still a
# MAC, and nothing else in device traffic has this separator run.
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

# Whole-value MAC layouts, keyed by the separator a placeholder in that layout
# is written with: "." is the dotted 4-4-4 grouping, "" is bare 12-hex. Bare
# and dotted MACs carry no separator run for MAC_RE to find in text; they are
# recognized only where the value is already known to be a MAC.
_MAC_LAYOUTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"), ":"),
    (re.compile(r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"), "-"),
    (re.compile(r"[0-9A-Fa-f]{12}"), ""),
    (re.compile(r"[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"), "."),
)


def mac_layout(value: str) -> str | None:
    """Return the separator of a whole value's MAC layout.

    Args:
        value: Candidate value

    Returns:
        ``":"`` or ``"-"`` (six pairs), ``""`` (bare 12-hex), ``"."`` (dotted
        4-4-4), or None when the value is not a MAC in one uniform layout
    """
    return next((sep for layout, sep in _MAC_LAYOUTS if layout.fullmatch(value)), None)


def is_mac_value(value: str) -> bool:
    """Check if a whole value is a MAC address in any layout.

    Separated (``AA:BB:CC:DD:EE:FF``, ``aa-bb-…``, or mixed separators), bare
    (``AABBCCDDEEFF``) or dotted (``aabb.ccdd.eeff``).

    Args:
        value: Candidate value

    Returns:
        True if the value is exactly one MAC address
    """
    return mac_layout(value) is not None or MAC_RE.fullmatch(value) is not None


def is_mac_placeholder(value: str) -> bool:
    """Check if a value is a MAC placeholder ``hash_mac`` could have written.

    A MAC in one uniform layout, lowercase, with first octet ``02``. Only for
    a value already known to be a MAC — under a MAC-named key — since a bare
    02-prefixed hex run in free text could be anything.

    Args:
        value: Candidate value

    Returns:
        True if the value has the shape of a MAC placeholder
    """
    return mac_layout(value) is not None and value == value.lower() and value.startswith("02")


def is_constant_mac(mac: str) -> bool:
    """Check if a MAC is one byte repeated: broadcast ``ff:ff:…``, zero ``00:00:…``.

    These are protocol constants, not a device's identity, and scripts
    compare against them (``if (mac == 'ff:ff:ff:ff:ff:ff')``). Neither tool
    treats them as PII: redacting one would rewrite program logic.

    Args:
        mac: A MAC in any layout

    Returns:
        True if every octet is the same
    """
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    return len(digits) == 12 and digits == digits[:2] * 6


# TLS certificate names on a HAR entry (ADR-17). A device CA names the device
# its certificate is issued to — a CableLabs modem certificate by the modem's
# MAC (`A4:56:30:…`), an HWROB/SWROB device CA by a bare 12-hex ID — so these
# fields are a device identity field: a whole name in any MAC layout is a MAC,
# as under a MAC-named JSON key, and so is a separated MAC inside a name.
CERTIFICATE_NAME_FIELDS = ("subjectName", "issuer")


def certificate_name_macs(name: str) -> list[str]:
    """The MACs a certificate name carries: the whole name in any MAC layout, else each separated MAC in it.

    Constants (one byte repeated) are left out, as everywhere else.

    Args:
        name: A ``_securityDetails`` subject or issuer name

    Returns:
        The MAC texts as written in the name, in order
    """
    if is_mac_value(name):
        return [] if is_constant_mac(name) else [name]
    return [match.group(0) for match in MAC_RE.finditer(name) if not is_constant_mac(match.group(0))]


# A key is read as its words — camelCase humps, acronyms, digit runs —
# lowercased and joined with '_' (`StatusSoftwareSerialNum` →
# `status_software_serial_num`, `CMMACAddress` → `cmmac_address`). The
# identity must end the key: `serialNumberLabel` and `MacAddressFilterEnabled`
# name something about the identity, and `macaddr.wan` is not recognized.
# Within the last word a glued prefix is allowed (`cmserialnumber`,
# `wanmacaddr`, `ethmac`), except `h` alone: a word starting `hmac` names a
# message authentication code. Of the bare abbreviations only an exact `sn`
# counts; `snr` is a signal ratio.
_KEY_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
SERIAL_KEY_RE = re.compile(r"serial(?:_?(?:num(?:ber)?|no))?(?:_\d+)?$|^sn$")
MAC_KEY_RE = re.compile(r"(?:(?<!^h)(?<!_h)mac(?:_?addr(?:ess)?)?|hw_?addr(?:ess)?)(?:_\d+)?$")

# A serial is one whitespace-free token of five or more characters carrying a
# digit. Every real serial across the cable_modem_monitor fleet carries one,
# while the digit-free values under serial keys are placeholders ('-', 'N/A')
# and labels ('Seriennummer') — the digit rule is what excludes status words.
# Five mirrors the HTML engine's labeled-serial value class and rejects flags
# and lengths ('1', '12').
_SERIAL_VALUE_RE = re.compile(r"(?=\S*\d)\S{5,}")

# A key naming a Wi-Fi network name (`ssid`, `ssid_24g`, `WiFiSSID`): its value
# identifies a network rather than authenticating to it, so it is offered for
# review, never auto-redacted.
SSID_KEY_RE = re.compile(r"(?:^|_)ssid(?:_|$)")


# Every identity key holds one of these, in any case; a key without one skips
# the word split.
_IDENTITY_KEY_HINT_RE = re.compile(r"serial|sn|mac|hw", re.IGNORECASE)


@functools.lru_cache(maxsize=4096)
def _key_words(key: str) -> str:
    return "_".join(word.lower() for word in _KEY_WORD_RE.findall(key))


# The words a response serves under a credential-named key when the key
# labels a button rather than holding a credential: the fleet's firmware
# translation tables hold "Yes" and "No" there, and no other word, and no
# credential it submits is one.
_CREDENTIAL_STATUS_WORDS = frozenset({"yes", "no"})
# Text with words on both sides of a space: a UI string, or a passphrase.
_PROSE_RE = re.compile(r"\S\s+\S")

# Auth schemes of the IANA HTTP Authentication Scheme Registry that the
# sanitizer keeps in an Authorization-style header while redacting the
# credential after them: a downstream tool can then classify the auth
# mechanism from one authenticated request, without a 401 exchange that cached
# credentials may never produce. An unrecognized leading token may be the start
# of a secret, so the list stays closed.
KNOWN_AUTH_SCHEMES: frozenset[str] = frozenset({"basic", "bearer", "digest", "ntlm", "negotiate", "oauth"})
# An RFC 7235 credential value: a known scheme, then its credentials — one
# token68 or a list of auth-params (Digest's `username="a", response="…"`).
_SCHEME_CREDENTIALS_RE = re.compile(
    r"(" + "|".join(sorted(KNOWN_AUTH_SCHEMES)) + r")\s+(\S.*)", re.IGNORECASE | re.DOTALL
)
_AUTH_PARAM = r"""[\w-]+=(?:"[^"]*"|[^\s,]*)"""
_AUTH_PARAMS_RE = re.compile(_AUTH_PARAM + r"(?:\s*,\s*" + _AUTH_PARAM + r")*")
_TOKEN68_RE = re.compile(r"[A-Za-z0-9._~+/-]{16,}=*")
# A PEM block: its BEGIN line, any `Name: value` headers, then base64 body
# text (lines flattened to spaces too). The END line is not required: a
# truncated block is still key material.
_PEM_BLOCK_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----\s+(?:[\w-]+:[^\n]*\n\s*)*[A-Za-z0-9+/]{16,}")


def _is_format_credential(value: str) -> bool:
    """True for a value whose format proves it a credential, whatever words it holds.

    A PEM block (its END line not required), or a known auth scheme followed by credentials: for Basic,
    base64 of ``user:pass``; for the others, auth-params or a token68 of 16 or
    more characters that holds a digit or symbol, or mixes case at least twice
    each way. A scheme word followed by prose (``Basic settings``, ``Bearer
    token``, ``OAuth 2.0``) is not a credential.
    """
    if _PEM_BLOCK_RE.search(value):
        return True
    match = _SCHEME_CREDENTIALS_RE.fullmatch(value)
    if match is None:
        return False
    scheme, rest = match.group(1).lower(), match.group(2).strip()
    if scheme == "basic":
        return is_base64_credential(rest)
    if _AUTH_PARAMS_RE.fullmatch(rest):
        return True
    return bool(_TOKEN68_RE.fullmatch(rest)) and (
        not rest.isalpha() or (sum(c.isupper() for c in rest) >= 2 and sum(c.islower() for c in rest) >= 2)
    )


def credential_value_action(value: str) -> Literal["keep", "review", "redact"]:
    """Decide what both tools do with a value a response serves under a credential-named key.

    A credential-named key in a response is often a firmware translation
    table's label for UI text about credentials (`PAGE_GENERAL_SET_PASSWORD`,
    even a bare `password`), so its name does not make the value certain.
    A button word is kept; prose is offered for the user's review, since a
    passphrase can hold spaces — unless its format proves a credential
    (``_is_format_credential``: an Authorization-style value, a PEM block);
    anything else is redacted. A value a client submits is always redacted —
    the caller decides which one it holds.

    Args:
        value: A non-empty value the caller has not recognized as redacted

    Returns:
        ``"keep"``, ``"review"`` or ``"redact"``
    """
    stripped = value.strip()
    if stripped.lower() in _CREDENTIAL_STATUS_WORDS:
        return "keep"
    if _is_format_credential(stripped):
        return "redact"
    if _PROSE_RE.search(value):
        return "review"
    return "redact"


def is_ssid_key(key: str) -> bool:
    """Check if a field name names a Wi-Fi network name (``ssid``, ``ssid_5g``, ``guestSSID``).

    Args:
        key: Field name, in any case convention

    Returns:
        True if one of the key's words is ``ssid``
    """
    return bool(SSID_KEY_RE.search(_key_words(key)))


def classify_identity_field(key: str, value: object) -> str | None:
    """Classify a field whose key names a device identity and whose value has its shape.

    The one definition shared by the JSON sanitizer and the validator. A
    serial already replaced by a placeholder is not a serial. A MAC
    placeholder is still classified: it cannot be told from a real locally
    administered MAC, so whether to skip it is the caller's decision — the
    sanitizer never does.

    Args:
        key: Field name, in any case convention
        value: Field value

    Returns:
        ``"serial_number"``, ``"mac_address"``, or None

    Examples:
        >>> classify_identity_field("StatusSoftwareSerialNum", "SN0012345XY")
        'serial_number'
        >>> classify_identity_field("CmMacAddress", "AABBCCDDEEFF")
        'mac_address'
        >>> classify_identity_field("hmac_algorithm", "AABBCCDDEEFF") is None
        True
    """
    if not isinstance(value, str) or not _IDENTITY_KEY_HINT_RE.search(key):
        return None
    # Read as words (`CmMacAddress` → `cm_mac_address`) and as written: an
    # acronym run into a word (`HWaddr`, `MACaddress`, `SERIALnumber`) splits
    # at the wrong letter, but its lowercase spelling still names the field.
    # The written form holds no word boundary to exclude `hmac` by, so a key
    # containing it is read as words only (`userHMAC` is a message
    # authentication code; `ethmac` still reads as `eth` + `mac`).
    words, written = _key_words(key), key.lower()
    if (
        any(SERIAL_KEY_RE.search(form) for form in (words, written))
        and _SERIAL_VALUE_RE.fullmatch(value)
        and not is_fully_redacted(value)
    ):
        return "serial_number"
    mac_forms = (words,) if "hmac" in written else (words, written)
    if any(MAC_KEY_RE.search(form) for form in mac_forms) and is_mac_value(value):
        return "mac_address"
    return None


def unredacted_identity(
    key: str, value: object, custom_patterns: str | dict[str, Any] | None = None
) -> str | None:
    """Classify an identity field ``validate`` and ``check_for_pii`` report.

    ``classify_identity_field`` without the values the sanitizer's own output
    can hold under a MAC-named key: a MAC placeholder in any layout, a
    constant MAC (which it keeps), or an allowlisted value.

    Args:
        key: Field name, in any case convention
        value: Field value
        custom_patterns: Optional custom patterns for the allowlist check

    Returns:
        ``"serial_number"``, ``"mac_address"``, or None when the field is clean
    """
    identity = classify_identity_field(key, value)
    if identity == "mac_address" and isinstance(value, str):
        if is_redacted(value, custom_patterns) or is_mac_placeholder(value) or is_constant_mac(value):
            return None
    return identity


# How deep the key rules reach into a JSON body: the sanitizer's walker, the
# validator's check_json_fields and check_for_pii's identity fields all stop
# here. Past it, the sanitizer still applies its text patterns to every string
# and key.
JSON_MAX_DEPTH = 50


def iter_json_strings(data: dict[str, Any] | list[Any]) -> Iterator[str]:
    r"""Yield every string in a parsed JSON container — values and object keys — at any depth.

    A JSON body's unit of text is the decoded string: the sanitizer's text
    passes and validate's text checks both read these, never the raw JSON
    text, so escapes (``\u003c``) hide nothing and no match can run from one
    string into the next.

    Args:
        data: A parsed JSON object or array

    Yields:
        Each object key and string value
    """
    stack: list[Any] = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in json_members(node):
                yield key
                if isinstance(value, str):
                    yield value
                elif isinstance(value, dict | list):
                    stack.append(value)
        else:  # the stack holds only objects and arrays
            for item in node:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, dict | list):
                    stack.append(item)


# The value regexes both sanitizer engines — the HTML passes and the string
# patterns JSON values, JSON keys and text bodies take — and validate share,
# so a body's route never decides whether an address is redacted. pii.json
# carries all four verbatim for check_for_pii (a test pins them), which skips
# what the engines keep: preserved gateway addresses, version strings, and
# IPv6 candidates that are not host addresses.
PRIVATE_IP_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}"
    r")\b"
)
PUBLIC_IP_RE = re.compile(
    r"\b(?!10\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!127\.)(?!0\.)(?!255\.)"
    r"(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
)
# An IPv6 candidate: two to seven colon-terminated hex groups and a last
# group — hex, or the dotted quad of an IPv4-mapped address (`::ffff:1.2.3.4`)
# — not glued to a word or another colon on either side (`(?<![:\w])` rather
# than `\b`, so a compressed `::ffff:…` is found), and not running on into a
# dotted number. A sentence-ending period is not part of it. Candidates are
# addresses only when is_ipv6_host_address accepts them, which rejects clock
# times, MACs and the constants `::` and `::1`.
IPV6_RE = re.compile(
    r"(?<![:\w])(?:[0-9a-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4})(?![:\w])(?!\.\d)",
    re.IGNORECASE,
)
# An email's local part and domain (dot-separated labels ending in an
# alphabetic TLD), as regex source: the labeled-serial value rule uses them to
# tell an email after a serial label (not a serial) from a serial followed by
# `@host` (a serial).
EMAIL_LOCAL_PART = r"[A-Za-z0-9._%+-]+"
EMAIL_DOMAIN = (
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b"
)
EMAIL_RE = re.compile(r"\b" + EMAIL_LOCAL_PART + "@" + EMAIL_DOMAIN)


def luhn_valid(number: str) -> bool:
    """Check a digit string against the Luhn checksum every payment card number carries.

    The card patterns' value test for the text path and ``check_for_pii``:
    a card-shaped number that fails it is a counter or an ID, and is kept.

    Args:
        number: Digit-only string

    Returns:
        True if the number passes the Luhn check
    """
    checksum = 0
    for i, digit in enumerate(int(c) for c in reversed(number)):
        value = digit * 2 if i % 2 == 1 else digit
        checksum += value - 9 if value > 9 else value
    return checksum % 10 == 0


def ipv6_host_spans(text: str) -> list[tuple[int, int]]:
    """Return the spans of the IPv6 host addresses in text (``IPV6_RE`` + ``is_ipv6_host_address``).

    A checker skips an IPv4 match inside one: an IPv4-mapped address
    (``::ffff:1.2.3.4``) is one address, which the sanitizer hashes whole.

    Args:
        text: Text to scan

    Returns:
        ``(start, end)`` of each address, in order
    """
    if ":" not in text:
        return []
    return [match.span() for match in IPV6_RE.finditer(text) if is_ipv6_host_address(match.group(0))]


def is_ipv6_host_address(candidate: str) -> bool:
    """Check if an ``IPV6_RE`` candidate is an IPv6 address that names a host.

    The unspecified ``::`` ("none configured") and loopback ``::1`` are
    protocol constants, like IPv4's ``0.x`` and ``127.x`` that the IPv4
    regexes exclude: they identify no device, and a placeholder in their
    place would read as a real address.

    Args:
        candidate: Text ``IPV6_RE`` matched

    Returns:
        True if ``ipaddress`` parses it as an IPv6 address other than ``::`` or ``::1``
    """
    # An IPv4-mapped tail with zero-padded octets (`::ffff:192.168.001.100`),
    # as some devices print IPv4, is still one address: ipaddress rejects the
    # padding, and the IPv4 passes read the padded quad as an address too.
    head, _, tail = candidate.rpartition(":")
    octets = tail.split(".")
    if len(octets) == 4 and all(octet.isdigit() and len(octet) <= 3 for octet in octets):
        candidate = f"{head}:{'.'.join(str(int(octet)) for octet in octets)}"
    try:
        address = ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return not (address.is_unspecified or address.is_loopback)


# `type/subtype` at the start of a Content-Type. The type is not checked
# against the registered set: DM1000 serves `applation/json`.
_MIME_RE = re.compile(r"^\s*([^\s/;]+)/([^\s;]+)")
_SCRIPT_SUBTYPES = frozenset({"javascript", "x-javascript", "ecmascript", "x-ecmascript"})


def mime_kind(mime: str) -> str | None:
    """Name what a mime type declares its body to be.

    The one mime vocabulary for routing and decoding. The subtype decides,
    bare or as a structured-syntax ``+suffix`` (``image/svg+xml``,
    ``application/problem+json``); parameters and case are ignored.

    Args:
        mime: A Content-Type value

    Returns:
        ``"markup"`` (HTML, XML), ``"json"``, ``"text"`` (any other text/*,
        JavaScript, form data), or None when the type says nothing about text
        (``application/octet-stream``, ``x-unknown``, images, fonts)
    """
    match = _MIME_RE.match(mime)
    if match is None:
        return None
    main, subtype = match.group(1).lower(), match.group(2).lower()
    suffix = subtype.rpartition("+")[2]
    if subtype in ("html", "xhtml") or suffix == "xml":
        return "markup"
    if suffix in ("json", "x-json"):
        return "json"
    if main == "text" or suffix in _SCRIPT_SUBTYPES or subtype == "x-www-form-urlencoded":
        return "text"
    return None


def is_text_mime(mime: str) -> bool:
    """Check if a mime type declares its body to be text (see :func:`mime_kind`).

    Args:
        mime: A Content-Type value, parameters allowed

    Returns:
        True for text/*, JSON, XML, JavaScript and form-urlencoded types
    """
    return mime_kind(mime) is not None


def route_body(mime_type: str, text: str) -> tuple[str, dict[str, Any] | list[Any] | None]:
    """Pick the engine for a response body's text, with the JSON it parsed to.

    The one routing decision for the sanitizer and the validator. Text that
    parses as a JSON object or array (``parse_json_container``) is JSON
    whatever its type declares — HNAP answers JSON as ``text/html``, and a
    markup engine reads no keys. Otherwise a markup type goes to the HTML
    engine and any other text type to the text path (``mime_kind``); a type
    that says nothing about text (``application/octet-stream``,
    ``x-unknown``, none) is sniffed: markup, else text. ``validate`` scans
    every body whatever its type, so every text a body can carry must reach
    an engine. The parsed JSON comes back so neither tool parses twice.

    Args:
        mime_type: The body's declared Content-Type
        text: The body's text

    Returns:
        ``("json", data)``, ``("html", None)`` or ``("text", None)``
    """
    data = parse_json_container(text)
    if data is not None:
        return "json", data
    kind = mime_kind(mime_type)
    if kind == "markup":
        return "html", None
    if kind is not None:
        return "text", None
    return ("html" if text.lstrip().startswith("<") else "text"), None


# Deepest nesting either tool accepts as JSON. Past it a body is text: the
# sanitizer re-serializes changed JSON with the pure-Python encoder, whose
# recursion would otherwise run out near the parser's own limit (~990).
JSON_MAX_NESTING = 400


class JsonObjectWithDuplicates(dict):  # type: ignore[type-arg]
    """A parsed JSON object whose text repeats a key.

    The mapping holds the last value of each key, as every JSON parser (and
    so every consumer of the capture) reads it; ``shadowed`` holds the
    earlier ``(key, value)`` pairs, which the validator still checks and the
    sanitizer drops by re-serializing.
    """

    shadowed: list[tuple[str, Any]]


def _object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) == len(pairs):
        return obj
    last = {key: index for index, (key, _) in enumerate(pairs)}
    duplicated = JsonObjectWithDuplicates(obj)
    duplicated.shadowed = [pair for index, pair in enumerate(pairs) if last[pair[0]] != index]
    return duplicated


def _nesting_exceeds(data: Any, limit: int) -> bool:
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        children = node.values() if isinstance(node, dict) else node  # only objects and arrays are stacked
        stack.extend((child, depth + 1) for child in children if isinstance(child, dict | list))
    return False


def parse_json_container(text: str) -> dict[str, Any] | list[Any] | None:
    """Parse text that is a JSON object or array.

    The one test for "this text is JSON" across the sanitizer and the
    validator. Nesting too deep for the parser (a ``RecursionError``), or
    deeper than ``JSON_MAX_NESTING``, is treated like any other text that
    does not parse — hostile input must not crash either tool. An object
    that repeats a key parses to a ``JsonObjectWithDuplicates``.

    Args:
        text: Candidate JSON text

    Returns:
        The parsed object or array, or None
    """
    if not text.lstrip().startswith(("{", "[")):
        return None
    try:
        parsed = json.loads(text, object_pairs_hook=_object_hook)
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict | list) or _nesting_exceeds(parsed, JSON_MAX_NESTING):
        return None
    return parsed


def json_members(obj: dict[str, Any]) -> list[tuple[str, Any]]:
    """Every ``(key, value)`` member of a parsed object, shadowed duplicates included."""
    members = list(obj.items())
    if isinstance(obj, JsonObjectWithDuplicates):
        members.extend(obj.shadowed)
    return members


# A UTF-16 surrogate code unit on its own: JSON can carry one (`"\ud800"`), and
# no encoder accepts it.
_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def parse_xml(text: str) -> ET.Element | None:
    """Parse an XML document for the field checks the sanitizer and ``validate`` both run.

    The one parse for both tools, so they read the same fields from a body.
    A lone surrogate cannot be encoded for the parser; it is read as U+FFFD,
    so one stray code unit elsewhere in a body does not switch off the check
    of every field in it.

    Args:
        text: Candidate XML text

    Returns:
        The root element, or None when the text is not well-formed XML
    """
    try:
        return ET.fromstring(_LONE_SURROGATE_RE.sub("\ufffd", text))  # noqa: S314
    except ET.ParseError:
        return None


# `charset=` parameter of a Content-Type, quoted or bare.
_CHARSET_PARAM_RE = re.compile(r";\s*charset\s*=\s*\"?([^\";\s]+)", re.IGNORECASE)


def decode_transport_body(content: Mapping[str, Any]) -> str | None:
    """Return the text a HAR body carries, undoing its transport encoding.

    A body without ``encoding`` is already text. A ``base64`` body is decoded
    with the mime type's declared charset — or strictly as UTF-8 when none is
    declared, or the declared one is unknown or not a text encoding (``hex``,
    ``zlib``). When that fails and the mime type says the body is text
    (:func:`is_text_mime`), it is read as latin-1: capture writes a page
    base64 exactly when its bytes are not UTF-8, whatever charset it declares,
    and latin-1 maps every byte, so the original bytes stay recoverable.
    Otherwise bytes that do not decode, or that decode to text holding NUL,
    are binary: text never holds NUL, fonts and images do.

    The one decoder for the sanitizer and the validator, so both read the
    same text from a body and leave the same bodies alone.

    Args:
        content: HAR ``content`` (or ``postData``) object

    Returns:
        The body's text, or None when it is empty or binary
    """
    text = content.get("text")
    if not isinstance(text, str) or not text:
        return None
    if content.get("encoding") != "base64":
        return text
    try:
        raw = base64.b64decode("".join(text.split()), validate=True)
    except ValueError:
        return None
    mime = str(content.get("mimeType", ""))
    declared = _CHARSET_PARAM_RE.search(mime)
    # A NUL in a codec name raises ValueError from the lookup itself.
    charset = declared.group(1) if declared and "\x00" not in declared.group(1) else "utf-8"
    try:
        try:
            decoded = raw.decode(charset)
        except LookupError:
            decoded = raw.decode("utf-8")
    except UnicodeError:
        if not is_text_mime(mime):
            return None
        decoded = raw.decode("latin-1")
    return decoded if decoded and "\x00" not in decoded else None


# Decoded text that is a URL (scheme://) or opens a JSON object/array: it has
# a colon, but it is data, never user:pass — whether or not it parses.
_STRUCTURED_TEXT_RE = re.compile(r"^\s*(?:[A-Za-z][A-Za-z0-9+.-]*://|[{\[])")

# Base64 charset pattern for quick pre-filtering
_BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# Reserved Set-Cookie attribute names (RFC 6265 sec. 4.1.1, plus the deployed
# Partitioned/Priority extensions). In the attribute position of a Set-Cookie
# header these words scope the cookie — they are not cookie data, and their
# values (a path, a domain, a date) carry no secret. Matching is
# case-insensitive per RFC 6265 sec. 5.2.
COOKIE_ATTRIBUTE_NAMES = (
    "HttpOnly",
    "Secure",
    "SameSite",
    "Path",
    "Domain",
    "Max-Age",
    "Expires",
    "Partitioned",
    "Priority",
)
_COOKIE_ATTRIBUTE_NAMES_LOWER = frozenset(name.lower() for name in COOKIE_ATTRIBUTE_NAMES)


def _decode_base64_text(value: str) -> str | None:
    """Strictly decode a value as base64 to UTF-8 text.

    Args:
        value: String to decode

    Returns:
        The decoded text, or None if the value is not valid base64 or does
        not decode to valid UTF-8
    """
    if not value or len(value) < 4:
        return None

    # Quick pre-filter: must be valid base64 characters
    if not _BASE64_CHARS_RE.match(value):
        return None

    # Canonical padding only. Python 3.10's b64decode(validate=True) accepts
    # excess padding that 3.11+ rejects; recognition must not depend on the
    # interpreter.
    stripped = value.rstrip("=")
    if len(stripped) < 4 or len(value) - len(stripped) != -len(stripped) % 4:
        return None

    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return None


def is_base64_credential(value: str) -> bool:
    """Check if a value is a base64-encoded user:pass credential.

    Detects URL token authentication patterns where base64(username:password)
    is passed as a bare query parameter or parameter value.

    Args:
        value: String to check

    Returns:
        True if value decodes to a user:pass pattern

    Examples:
        >>> is_base64_credential("YWRtaW46cGFzc3dvcmQ=")  # admin:password
        True
        >>> is_base64_credential("aGVsbG8gd29ybGQ=")  # hello world (no colon)
        False
        >>> is_base64_credential("not-base64!")
        False
    """
    decoded = _decode_base64_text(value)
    if decoded is None or _STRUCTURED_TEXT_RE.match(decoded):
        return False

    # Check for user:pass pattern — at least one char on each side of colon
    if ":" not in decoded:
        return False

    parts = decoded.split(":", 1)
    return len(parts) == 2 and len(parts[0]) >= 1 and len(parts[1]) >= 1


class QueryCredential(NamedTuple):
    """A base64(user:pass) credential located inside one URL query segment.

    The segment reads ``prefix`` followed by the credential. ``prefix`` is kept
    verbatim when redacting: ``""`` for a bare segment, ``"key="`` for a keyed
    one, or a marker such as ``"login_"``. ``credential`` is the base64 text as
    the client produced it, with any URL transport encoding undone.
    """

    prefix: str
    credential: str
    keyed: bool


# URL-token firmware can glue a short marker onto the bare token
# (``?login_<base64>``). '_' is outside the standard base64 alphabet, so the
# marker boundary is unambiguous.
_QUERY_CREDENTIAL_MARKER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*_)(.+)$")

# The shape Hasher.hash_generic writes: an uppercase prefix, '_', lowercase hex.
_HASH_PLACEHOLDER_RE = re.compile(r"[A-Z][A-Z0-9_]*_[0-9a-f]{8,}")

# A credential whose padding was stripped is only accepted from this many
# characters up — the unpadded length of base64("admin:pw"). Below it, short
# hex and alphanumeric tokens (cache-busters, short commit SHAs) decode to a
# colon-bearing string by chance often enough to matter.
_MIN_UNPADDED_CREDENTIAL_LENGTH = 11

# Headers whose value is a URL (RFC 9110). A credential or sensitive
# parameter in the request URL is repeated in the next request's Referer and
# can appear in a redirect's Location, so these get the same query treatment
# as the request URL itself.
URL_VALUED_HEADERS: frozenset[str] = frozenset({"referer", "location", "content-location"})


def decode_base64_payload(value: str) -> str | None:
    """Return the text of a base64-wrapped structured payload: a JSON object or array, or a URL.

    Such text always has a colon, so :func:`is_base64_credential` alone reads
    it as ``user:pass``. It is data — field names, a redirect target — and is
    sanitized inside rather than replaced whole. Padding may be missing or
    miscounted, as a URL leaves it.

    Args:
        value: Candidate base64 text (surrounding whitespace ignored)

    Returns:
        The decoded payload, or None when ``value`` is not one
    """
    stripped = value.strip()
    unpadded = stripped.rstrip("=")
    if not unpadded or not _BASE64_CHARS_RE.match(stripped):
        return None
    decoded = _decode_base64_text(unpadded + "=" * (-len(unpadded) % 4))
    if decoded is None or not _STRUCTURED_TEXT_RE.match(decoded):
        return None
    if decoded.lstrip().startswith(("{", "[")) and parse_json_container(decoded) is None:
        return None
    return decoded


def _as_base64_credential(raw: str) -> str | None:
    """Return ``raw`` as a base64 credential, undoing what URL transport did to it.

    A query value can arrive percent-encoded (``%3D`` padding, ``%2B``), with
    '+' decoded to a space (URLSearchParams, and so Playwright's
    ``queryString`` array), or with its padding stripped or miscounted.
    ``unquote`` is used rather than ``unquote_plus``: a raw '+' in a query is
    a base64 character far more often than an encoded space.
    """
    verbatim = list(dict.fromkeys([raw, urllib.parse.unquote(raw), raw.replace(" ", "+")]))
    for candidate in verbatim:
        if is_base64_credential(candidate):
            return candidate
    # Restoring padding reaches values the verbatim check never has, so it
    # only accepts a decoded value that could be nothing but user:pass: long
    # enough and printable.
    for candidate in verbatim:
        unpadded = candidate.rstrip("=")
        if len(unpadded) < _MIN_UNPADDED_CREDENTIAL_LENGTH:
            continue
        padded = unpadded + "=" * (-len(unpadded) % 4)
        decoded = _decode_base64_text(padded)
        if decoded is not None and decoded.isprintable() and is_base64_credential(padded):
            return padded
    return None


def is_blank_query_value(value: str) -> bool:
    """True for a query value with nothing in it to redact.

    Empty, or only '=' — the padding remnant a query parser leaves in
    ``value`` when it splits a bare token at its first '='.

    Args:
        value: Decoded query parameter value

    Returns:
        True if the value carries no content
    """
    return not value.strip("=")


def query_param_segment(param: dict[str, Any]) -> str:
    """Rejoin a HAR ``queryString`` entry into the query segment it was parsed from.

    The parser splits at the first '=', so a bare credential's base64 padding
    lands in ``value``. Rejoining lets one segment reader serve both the URL
    string and the parsed array.

    Args:
        param: One ``{"name": ..., "value": ...}`` entry

    Returns:
        ``name=value``, or ``name`` when the value is empty
    """
    name = str(param.get("name", ""))
    value = str(param.get("value", ""))
    return f"{name}={value}" if value else name


def find_query_credential(segment: str) -> QueryCredential | None:
    """Locate a base64(user:pass) credential in one raw URL query segment.

    The single definition of "URL credential" for the sanitizer, the
    validator and the credential annotation, so the three cannot disagree
    about which query shapes carry one. Recognized shapes: a bare segment
    (``?<b64>``), a keyed value (``?auth=<b64>``), and a marker-prefixed
    segment (``?login_<b64>``).

    Args:
        segment: One ``&``-separated query segment, undecoded

    Returns:
        The located credential, or None
    """
    # A hash placeholder the sanitizer wrote (``AUTH_d2c6b8e4``) is itself
    # marker-shaped, and 8 hex characters sometimes decode to a colon.
    if not segment or _HASH_PLACEHOLDER_RE.fullmatch(segment):
        return None
    # A doubled separator (``/a??<b64>``, ``k==<b64>``) is kept in the prefix
    # rather than read as part of the credential.
    body = segment.lstrip("?")
    lead = segment[: len(segment) - len(body)]
    credential = _as_base64_credential(body)
    if credential:
        return QueryCredential(prefix=lead, credential=credential, keyed=False)
    key, sep, value = body.partition("=")
    stripped = value.lstrip("=")
    if sep and stripped:
        credential = _as_base64_credential(stripped)
        if credential:
            separator = value[: len(value) - len(stripped)]
            return QueryCredential(prefix=f"{lead}{key}={separator}", credential=credential, keyed=True)
    marker = _QUERY_CREDENTIAL_MARKER_RE.match(body)
    if marker:
        credential = _as_base64_credential(marker.group(2))
        if credential:
            return QueryCredential(prefix=lead + marker.group(1), credential=credential, keyed=False)
    return None


class QueryPayload(NamedTuple):
    """A base64-wrapped JSON or URL payload located inside one URL query segment.

    The segment reads ``prefix`` followed by the payload: ``prefix`` is
    ``""`` for a bare segment or ``"key="`` for a keyed one, kept verbatim.
    ``encoded`` is the base64 as the client produced it, URL transport
    encoding undone; ``text`` is what it decodes to. ``quoted`` records that
    the segment carried it percent-encoded, so a rewrite can do the same.
    """

    prefix: str
    encoded: str
    text: str
    quoted: bool


def find_query_payload(segment: str) -> QueryPayload | None:
    """Locate a base64 JSON or URL payload in one raw URL query segment.

    The payload counterpart of :func:`find_query_credential`, and exclusive
    with it: a payload is never a credential. Shared by the sanitizer, which
    sanitizes inside the payload, and the validator, which checks inside it.

    Args:
        segment: One ``&``-separated query segment, undecoded

    Returns:
        The located payload, or None
    """
    body = segment.lstrip("?")
    lead = segment[: len(segment) - len(body)]
    key, sep, value = body.partition("=")
    readings = [(lead, body)]
    if sep:
        stripped = value.lstrip("=")
        readings.append((f"{lead}{key}={value[: len(value) - len(stripped)]}", stripped))
    for prefix, raw in readings:
        for candidate in dict.fromkeys([raw, urllib.parse.unquote(raw).replace(" ", "+")]):
            text = decode_base64_payload(candidate) if candidate else None
            if text is not None:
                return QueryPayload(prefix=prefix, encoded=candidate, text=text, quoted="%" in raw)
    return None


def split_url_query(url: str) -> tuple[str, str, str]:
    """Split a URL around its raw query, so that ``url == before + query + after``.

    The query runs from the first '?' to the next '#': ``before`` ends with
    that '?' (it is the whole URL when there is none) and ``after`` is the
    '#' and what follows. A '?' after a '#' therefore opens a query too —
    hash-routed pages carry their parameters there (``#/login?password=…``),
    and a URL-valued header can repeat them. Split by hand rather than with
    ``urlparse``, which raises on input it cannot parse (an unbalanced IPv6
    bracket) and does not give back the bytes it read. Every reader and
    rewriter of a query uses this split.

    Args:
        url: Any URL string

    Returns:
        ``(before, query, after)``; ``query`` is undecoded and ``""`` when
        there is none
    """
    head, question, rest = url.partition("?")
    query, hash_mark, fragment = rest.partition("#")
    return head + question, query, hash_mark + fragment


# The authority runs from '//' — after a scheme, or opening a scheme-relative
# reference, which a Location header may carry — to the first '/', '?' or '#'; its
# userinfo is everything before the authority's last '@' — WHATWG parsing,
# which is what browsers do, so a password or an email-address username may
# itself hold '@'. The password starts after the userinfo's first ':'.
_URL_USERINFO_RE = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/?#]*)@")


def split_url_password(url: str) -> tuple[str, str, str] | None:
    """Split out the password a URL's userinfo carries (``user:password`` ahead of the host).

    Browsers strip userinfo from the requests they send, but a ``Location``
    header or a wrapped URL can still carry it, and the password is a
    credential by position. Shared by the sanitizer and ``check_url``.

    Args:
        url: Any URL string

    Returns:
        ``(before, password, after)`` with ``url == before + password + after``,
        or None when the URL has no userinfo password
    """
    match = _URL_USERINFO_RE.match(url)
    if match is None:
        return None
    user, colon, password = match.group(2).partition(":")
    if not colon or not password:
        return None
    return match.group(1) + user + colon, password, url[match.end(2) :]


def url_query(url: str) -> str:
    """Return a URL's raw, undecoded query (see :func:`split_url_query`)."""
    return split_url_query(url)[1]


def iter_url_credentials(request: Mapping[str, Any]) -> Iterator[QueryCredential]:
    """Yield every base64(user:pass) credential in a HAR request's query.

    The URL string's segments first, then the ``queryString`` array's — the
    same query recorded twice, so one credential usually appears in both.
    Malformed parts (a non-string URL, a non-list array) are skipped.

    Args:
        request: HAR request object

    Yields:
        Each credential ``find_query_credential`` locates
    """
    url = request.get("url")
    segments: list[str] = url_query(url).split("&") if isinstance(url, str) else []
    params = request.get("queryString")
    if isinstance(params, list):
        segments.extend(query_param_segment(p) for p in params if isinstance(p, dict))
    for segment in segments:
        found = find_query_credential(segment)
        if found is not None:
            yield found


def is_base64_decodable_text(value: str) -> bool:
    """Check if a value is base64 that decodes to printable text.

    Weaker signal than :func:`is_base64_credential` (no user:pass shape
    required) — callers must supply the credential context, e.g. a
    login-shaped form POST. Exists because vendor firmware base64-encodes
    bare passwords with no recognizable shape of their own.

    Args:
        value: String to check

    Returns:
        True if value decodes to printable UTF-8 text of plausible
        credential length

    Examples:
        >>> is_base64_decodable_text("ZXhhbXBsZS1ub3QtcmVhbA==")  # example-not-real
        True
        >>> is_base64_decodable_text("admin")  # not valid base64 length
        False
    """
    decoded = _decode_base64_text(value)
    if decoded is None or len(decoded) < 4:
        return False
    return decoded.isprintable()


def is_cookie_attribute_name(name: str) -> bool:
    """Check if a Set-Cookie segment key is a reserved attribute name.

    A Set-Cookie header is one ``name=value`` cookie pair followed by
    ``;``-separated attributes (RFC 6265 sec. 4.1.1). Only the pair is cookie
    data; a segment keyed by one of these reserved names describes the
    cookie's scope and must survive sanitization intact.

    Args:
        name: The key half of one ``;``-separated Set-Cookie segment
            (surrounding whitespace is ignored)

    Returns:
        True if the key is a reserved cookie attribute name

    Examples:
        >>> is_cookie_attribute_name(" Path")
        True
        >>> is_cookie_attribute_name("httponly")
        True
        >>> is_cookie_attribute_name("csrfp_token")
        False
    """
    return name.strip().lower() in _COOKIE_ATTRIBUTE_NAMES_LOWER


# Response cookie headers. RFC 6265 sec. 4.1.1 gives these a different grammar
# from the request `Cookie` header: one `name=value` cookie pair followed by
# `;`-separated attributes, rather than a list of cookie pairs. Every other
# cookie header (request `Cookie`, custom `cookie_redact` names) is a list of
# pairs. Hardcoded rather than pattern-configured for the same reason as
# `KNOWN_AUTH_SCHEMES`: it is protocol structure, not a domain pattern.
SET_COOKIE_HEADERS = frozenset({"set-cookie", "set-cookie2"})

# The valueless attributes. In a request Cookie header one of these is
# recorder output (the fleet's captures write `Secure` there), not a cookie.
_COOKIE_FLAGS = frozenset({"secure", "httponly", "partitioned"})
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)"
# RFC 1123 (`Wed, 21 Oct 2026 07:28:00 GMT`), its Netscape dashed form, RFC 850
# two-digit years, and asctime (`Wed Oct 21 07:28:00 2026`).
_COOKIE_DATE_RE = re.compile(
    rf"(?:[a-z]{{3,9}},?\s*)?(?:\d{{1,2}}[\s-]{_MONTH}[\s-]\d{{2,4}}\s+\d{{1,2}}:\d{{2}}:\d{{2}}(?:\s*(?:gmt|utc))?"
    rf"|{_MONTH}\s+\d{{1,2}}\s+\d{{1,2}}:\d{{2}}:\d{{2}}\s+\d{{4}})",
    re.IGNORECASE,
)
_COOKIE_DOMAIN_RE = re.compile(
    r"\.?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.?", re.IGNORECASE
)
_COOKIE_ATTRIBUTE_VALUE_RULES: dict[str, Callable[[str], bool]] = {
    "path": lambda value: value.startswith("/"),
    "max-age": lambda value: re.fullmatch(r"-?\d+", value) is not None,
    "samesite": lambda value: value.lower() in {"strict", "lax", "none"},
    "priority": lambda value: value.lower() in {"low", "medium", "high"},
    "expires": lambda value: _COOKIE_DATE_RE.fullmatch(value) is not None,
    "domain": lambda value: _COOKIE_DOMAIN_RE.fullmatch(value) is not None,
}


def is_set_cookie_attribute(segment: str) -> bool:
    """Check if one ``;``-separated segment is a valid RFC 6265 Set-Cookie attribute.

    A valueless ``Secure``, ``HttpOnly`` or ``Partitioned``; a ``Path``
    starting with ``/``; a ``Max-Age`` of digits; a ``SameSite`` or
    ``Priority`` from its enumeration; an ``Expires`` date; a ``Domain``
    hostname. Names are case-insensitive (sec. 5.2).

    Args:
        segment: One segment of a Set-Cookie value

    Returns:
        True if the segment is an attribute a user agent would apply
    """
    name, eq, value = segment.partition("=")
    name, value = name.strip().lower(), value.strip()
    if not eq:
        return name in _COOKIE_FLAGS
    rule = _COOKIE_ATTRIBUTE_VALUE_RULES.get(name)
    return rule is not None and bool(value) and rule(value)


def cookie_segment_actions(value: str, *, set_cookie: bool) -> list[str]:
    """Classify each ``;``-separated segment of a cookie header: what is cookie data.

    One rule for the sanitizer, which rewrites the data, and ``validate``,
    which checks it. Each segment is ``"keep"``, ``"value"`` (a
    ``name=value`` pair whose value is data) or ``"token"`` (a valueless
    segment that is data whole: a nameless cookie).

    - Request ``Cookie``: every pair is a cookie, an attribute name included
      (``path=s3cr3t``); a valueless ``Secure``/``HttpOnly``/``Partitioned`` is
      kept, any other valueless segment is a nameless cookie.
    - ``Set-Cookie``: when every segment is a valid attribute
      (``is_set_cookie_attribute``) there is no cookie and all is kept.
      Otherwise the first segment is the cookie (``Secure=abc123`` included),
      reserved attributes after it are kept by name, as are valueless
      tokens, and an unreserved pair after it is data.

    Args:
        value: The header value
        set_cookie: The header is a Set-Cookie (``SET_COOKIE_HEADERS``)

    Returns:
        One action per ``value.split(";")`` segment
    """
    segments = value.split(";")
    filled = [index for index, segment in enumerate(segments) if segment.strip()]
    if set_cookie and filled and all(is_set_cookie_attribute(segments[index]) for index in filled):
        return ["keep"] * len(segments)
    actions = []
    for index, segment in enumerate(segments):
        key, eq, _ = segment.partition("=")
        if not segment.strip():
            actions.append("keep")
        elif set_cookie and index != filled[0]:
            actions.append("value" if eq and not is_cookie_attribute_name(key) else "keep")
        elif eq:
            actions.append("value")
        elif not set_cookie and key.strip().lower() in _COOKIE_FLAGS:
            actions.append("keep")
        else:
            actions.append("token")
    return actions
