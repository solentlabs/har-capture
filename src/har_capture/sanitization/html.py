"""HTML sanitization utilities.

This module provides PII removal from HTML content with ZERO external
dependencies (stdlib only). Designed for sanitizing device web interface
HTML before inclusion in diagnostics or fixture files.

PII Categories Removed:
    - MAC addresses (all formats)
    - Serial numbers
    - Account/Subscriber IDs
    - Private/Public IP addresses (except common gateway IPs)
    - IPv6 addresses
    - Passwords and passphrases
    - Session tokens and cookies
    - CSRF tokens
    - Email addresses
    - Config file paths (may contain ISP/customer info)
    - WiFi credentials in JavaScript variables
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from typing import TYPE_CHECKING

from har_capture.patterns import (
    Hasher,
    is_allowlisted,
    load_allowlist,
    load_pii_patterns,
    load_sensitive_patterns,
)
from har_capture.patterns.redaction import is_redacted

if TYPE_CHECKING:
    from typing import Any

    from har_capture.sanitization.collector import RedactionCollector
    from har_capture.sanitization.report import HeuristicMode
else:
    from har_capture.sanitization.collector import RedactionCollector
    from har_capture.sanitization.report import HeuristicMode


# Serial number pattern for pipe-delimited values (SN-XXXXX, S/N-XXXXX)
# Requires a separator (- or _) after the prefix to avoid false positives on
# SNMP-related values like SNMPv3Auth, SNMPCommunityString, etc.
_PIPE_SERIAL_RE = re.compile(r"^(?:SN|S/N|S-N)[-_][A-Za-z0-9]{5,}$", re.IGNORECASE)

# Already-redacted hash pattern for pipe-delimited values (MAC_a1b2c3d4, SERIAL_deadbeef)
_ALREADY_REDACTED_HASH_RE = re.compile(r"^[A-Z_]+_[a-f0-9]{8}$")

# MAC address pattern for pipe-delimited values (exact match)
_PIPE_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


# Sibling-element label/value pairs where the value occupies its OWN element.
# Technicolor .jst (XB6/XB7/XB8/XB10 family) renders the "Device Label
# Information" sticker block on network_setup.jst as:
#
#     <span class="readonlyLabel">Default Password:</span>
#     <span class="value">orange4213table</span>
#
# Passes 2/2b/2d reach their values with a bare tag chain `(?:<[^>]*>\s*)*`,
# but a bare chain is too loose for credential labels: its `\s*` also runs
# through ordinary prose, so gateway help text such as
#
#     $.i18n("<strong>Password:</strong> Enter the Password you registered")
#
# matches the word "Enter". The discriminator is structural, not lexical —
# help-text prose shares a text node with its label element, while a sticker
# value opens its own element and is that element's entire text content.
#
# The value may not contain whitespace. Every sticker value across the
# committed fleet is a single token, while every hint, status, and prose
# false positive is not:
#
#     <label>Password:</label><div class="hint">Must be at least 8 characters</div>
#     <dt>Password:</dt><dd>Not set</dd>
#
# Requiring the element's entire text to be one whitespace-free token rejects
# those without needing to know what the words mean. The cost is a genuine
# limitation: an SSID containing a space is not matched by these rules. That is
# the deliberate side of the ADR-12 trade — a space-containing element text
# cannot be told apart from prose structurally, and over-redacting gateway UI
# copy is the worse failure.
#
# The optional `\([^)]{0,24}\)` group carries the parenthetical qualifier
# Technicolor puts between label and colon ("Default Network Name (SSID):").
#
# Exported (not underscore-private) because `validation/secrets.py` imports
# these: the sanitizer and the validator must not diverge on what counts as a
# labeled default credential. See ADR-14.
def _sibling_label_value_pattern(labels: str, separators: str = ":") -> re.Pattern[str]:
    """Build a pattern matching `<tag>LABEL:</tag><tag>VALUE</tag>` pairs.

    Args:
        labels: Regex alternation of label texts (already escaped/grouped).
        separators: Accepted label/value separator characters. Each is escaped
            individually — interpolating them raw would let a future addition
            silently form a range (``":-="`` becoming ``[:-=]``, which matches
            ``;`` and ``<``).

    Returns:
        Compiled pattern with group 1 = label through the value element's
        opening tag (re-emitted verbatim so markup is preserved) and group 2 =
        the value itself.
    """
    separator_class = "[" + "".join(re.escape(c) for c in separators) + "]"
    return re.compile(
        r"((?:" + labels + r")\s*(?:\([^)]{0,24}\))?\s*" + separator_class + r"\s*"
        r"</[a-zA-Z][^>]*>\s*"  # label element closes
        r"<[a-zA-Z][^>]*>\s*)"  # value element opens
        r"([^<>\s]+)"  # value: the element's entire text, one token
        r"(?=\s*</)",  # value element closes
        re.IGNORECASE,
    )


# Label vocabulary mirrors pass 7 minus bare `key`, which is a false-positive
# magnet once the match may cross element boundaries (`metaKey`, `monkey`).
SIBLING_PASSWORD_RE = _sibling_label_value_pattern(r"password|passphrase|psk|wpa[0-9]*\s*key")

# SSID vocabulary extends pass 7a with the connection-status heading form,
# which separates label from value with a hyphen rather than a colon:
#     <span id="priwifinet">Private Wi-Fi Network- </span>
#     <span class="connection_text">Andrew</span>
# That heading renders the *live* SSID, not the sticker default — the xb6
# capture carries a household member's given name there.
SIBLING_SSID_RE = _sibling_label_value_pattern(r"ssid|network\s*name|wi-?fi\s*network", separators=":-")

# Attribute-anchored SSID values: the element naming itself an SSID holder via
# class/id carries the network name as its text, with no adjacent label at all.
#     <td headers="private-Name"><b><font class="wifi_ntwrk">XFSETUP-9210</font></b></td>
#
# The attribute must name a *value* holder. Classes like `ssid_help`,
# `ssid-label`, `ssidTitle`, and `ssid_desc` decorate copy about the SSID rather
# than holding one, and matching `ssid` as a bare substring redacted their text
# ("Choose a name for your network"). Helper suffixes are therefore excluded,
# and `<th>` stays excluded because a column heading is not a value
# ("Source SSID Index").
_SSID_ATTRIBUTE_HELPER_SUFFIX = r"(?:help|label|desc|descr|description|title|tip|hint|note|msg|message|text|error|caption|legend|head|header)"
SSID_ATTRIBUTE_RE = re.compile(
    r"(<(?!th[\s>])[a-zA-Z][\w-]*[^>]*\b(?:class|id)\s*=\s*[\"'][^\"']*"
    r"(?:ssid|wifi_ntwrk|wifi[-_]?network|priwifinet|wireless[-_]?name)"
    r"(?![-_]?" + _SSID_ATTRIBUTE_HELPER_SUFFIX + r")"
    r"[^\"']*[\"'][^>]*>\s*)"
    r"([^<>\s]+)"  # value: the element's entire text, one token
    r"(?=\s*</)",
    re.IGNORECASE,
)

# SSID values listed as the options of an SSID-named <select>. The network name
# has no label and no attribute of its own here — only the enclosing control
# identifies it:
#     <select name="mac_ssid" id="mac_ssid"><option value="17">XFSETUP-9210</option></select>
SSID_SELECT_RE = re.compile(
    r"<select\b[^>]*\b(?:name|id|class)\s*=\s*[\"'][^\"']*ssid[^\"']*[\"'][^>]*>.*?</select>",
    re.IGNORECASE | re.DOTALL,
)
# Group 1 is the opening tag, group 2 the option text. An option whose `value`
# attribute is empty is a chooser placeholder ("-- Select --"), never a network.
SSID_OPTION_RE = re.compile(
    r"(<option\b(?![^>]*\bvalue\s*=\s*[\"']\s*[\"'])[^>]*>\s*)([^<>\s]+)(?=\s*</option>)",
    re.IGNORECASE,
)


def is_structural_value_sensitive(value: str, custom_patterns: str | dict[str, Any] | None = None) -> bool:
    r"""Check whether a structurally-located element value should be redacted.

    The patterns above locate a value by markup position; this decides whether
    the located text is actually a credential or network name. Shared by the
    sanitizer, ``validate``, and ``check_for_pii`` so a value one of them
    redacts is never reported as a leak by another.

    Rejects, in order: labels (text ending in a separator, as in
    ``<span id="priwifinet">Private Wi-Fi Network-</span>``), values already
    redacted, bare integers (row indices — mirroring the universal ``^\\d+$``
    entry in ``SAFE_PATTERNS``), and known-safe status words (``Enabled``,
    ``Disabled``, ``N/A``) that appear in the same element position as a value.

    Args:
        value: The element's text content
        custom_patterns: Optional path to custom patterns file

    Returns:
        True if the value should be treated as sensitive
    """
    from har_capture.sanitization.heuristics import is_safe_value

    if not value or value.endswith((":", "-")):
        return False
    if _OPTION_INDEX_RE.match(value):
        return False
    if is_redacted(value, custom_patterns):
        return False
    return not is_safe_value(value)


# Bare integers are row indices, not network names. This mirrors the universal
# `^\d+$` entry in heuristics.SAFE_PATTERNS.
_OPTION_INDEX_RE = re.compile(r"^\d+$")


def iter_ssid_option_values(
    content: str, custom_patterns: str | dict[str, Any] | None = None
) -> Iterator[tuple[str, int]]:
    """Yield ``(value, offset)`` for sensitive options inside SSID-named selects.

    Shared by the sanitizer, ``validate``, and ``check_for_pii`` so all three
    agree on which option values are network names.

    Args:
        content: HTML content to scan.
        custom_patterns: Optional path to custom patterns file.

    Yields:
        The option's text and its offset **within ``content``**. The offset is
        rebased onto the document — ``SSID_OPTION_RE`` runs against the matched
        ``<select>`` substring, so its own offsets are relative to that element
        and would report the wrong line number.
    """
    for select_match in SSID_SELECT_RE.finditer(content):
        base = select_match.start()
        for option_match in SSID_OPTION_RE.finditer(select_match.group(0)):
            value = option_match.group(2)
            if is_structural_value_sensitive(value, custom_patterns):
                yield value, base + option_match.start(2)


def _sanitize_pipe_value(
    value: str,
    *,
    hasher: Hasher,
    collector: RedactionCollector,
    safe_values: set[str],
    extra_safe_patterns: list[re.Pattern[str]],
    compiled_detectors: list[Any],
    heuristics: HeuristicMode,
    values_context: list[str],
    value_index: int,
    all_values: list[str] | None = None,
) -> str:
    """Process a single pipe-delimited value.

    Returns the sanitized value (hashed), the original value (preserved),
    or the original value with a side-effect flag recorded in the collector.

    Args:
        value: Raw value from pipe-delimited string (stripped)
        hasher: Hasher for correlation-preserving redaction
        collector: Collector for recording redactions and flags
        safe_values: Case-insensitive safe value set from tagValueList config
        extra_safe_patterns: Domain-specific safe value regex patterns
        compiled_detectors: Domain heuristic detectors
        heuristics: Heuristic mode (DISABLED, FLAG, REDACT)
        values_context: Already-processed values (for adjacency detection)
        value_index: Position in the pipe-delimited string
        all_values: Full original value list (for FLAG mode context capture)

    Returns:
        Sanitized or preserved value string
    """
    from har_capture.sanitization.heuristics import (
        analyze_value,
        is_safe_value,
    )

    val_lower = value.lower()

    # Skip empty values, safe values, and already-redacted placeholders
    if not value or is_safe_value(value, extra_safe_patterns):
        return value

    # Skip already-redacted values (e.g., MAC_xxxxx, MODEM_SN_xxxxx)
    if value.startswith("***") or _ALREADY_REDACTED_HASH_RE.match(value) or value == "XX:XX:XX:XX:XX:XX":
        return value

    # Check if value is in safe list
    if val_lower in safe_values:
        return value

    # AUTO-REDACT: Known reliable patterns
    # MAC addresses
    if _PIPE_MAC_RE.match(value):
        collector.record_auto_redaction("mac_address")
        return hasher.hash_mac(value)

    # Serial numbers with SN/S/N prefix
    if _PIPE_SERIAL_RE.match(value):
        collector.record_auto_redaction("serial_number")
        return hasher.hash_generic(value, "SERIAL")

    # HEURISTICS: Analyze unknown values (opt-in)
    if heuristics != HeuristicMode.DISABLED:
        should_flag, confidence, category, reason = analyze_value(
            value,
            values_context=values_context,
            value_index=value_index,
            extra_safe_patterns=extra_safe_patterns,
            compiled_detectors=compiled_detectors,
        )

        if should_flag:
            if heuristics == HeuristicMode.REDACT:
                collector.record_auto_redaction(category)
                return hasher.hash_sensitive_value(value, category)
            if heuristics == HeuristicMode.FLAG:
                from har_capture.cli.interactive import capture_pipe_context

                context = capture_pipe_context(all_values or [], value_index)
                collector.flag_value(
                    value,
                    category,
                    confidence,
                    context,
                    reason,
                )

    # Preserve value (either not flagged, or flagged for review)
    return value


def redact_vendor_serials(
    content: str,
    compiled_detectors: list[Any],
    hasher: Hasher,
    collector: RedactionCollector,
) -> str:
    """Auto-redact vendor-format serials appearing as standalone tokens.

    Applies the high-confidence ``serial_number`` detectors (known vendor
    serial layouts, e.g. Netgear's 13-char format) to delimiter-bounded
    candidate tokens anywhere in ``content``. This is what catches a serial
    inside a pipe-delimited blob (tagValueList) or a bare JS assignment,
    where no label exists for the labeled serial passes to anchor on.

    ``har-capture validate`` applies the same detectors to the same token
    extraction (``validation/secrets.py``) — the two tools must agree on
    what counts as a vendor serial.

    Args:
        content: Text to scan (HTML, JS, or other text content)
        compiled_detectors: Full detector list; filtered internally
        hasher: Hasher for correlation-preserving redaction
        collector: Collector recording each redaction

    Returns:
        Content with vendor-format serial tokens replaced by SERIAL_ hashes
    """
    from har_capture.patterns.loader import (
        VENDOR_SERIAL_TOKEN_RE,
        high_confidence_serial_detectors,
        match_vendor_serial,
    )

    serial_detectors = high_confidence_serial_detectors(compiled_detectors)
    if not serial_detectors:
        return content

    def replace_serial_token(match: re.Match[str]) -> str:
        token = match.group(0)
        if match_vendor_serial(token, serial_detectors) is None:
            return token
        collector.record_auto_redaction("serial_number")
        return hasher.hash_generic(token, "SERIAL")

    return VENDOR_SERIAL_TOKEN_RE.sub(replace_serial_token, content)


def is_valid_ip_address(value: str) -> bool:
    """Check if dotted-decimal string is a valid IPv4 address (not a version string).

    Validates both structure and heuristics to avoid false positives on version strings.

    Args:
        value: Dotted-decimal string (e.g., "192.168.1.1" or "5.7.1.5")

    Returns:
        True if valid IP address, False if likely version string or invalid

    Examples:
        >>> is_valid_ip_address("192.168.1.1")
        True
        >>> is_valid_ip_address("10.0.0.1")
        True
        >>> is_valid_ip_address("8.8.8.8")
        True
        >>> is_valid_ip_address("5.7.1.5")  # Version string
        False
        >>> is_valid_ip_address("2.4.6.8")  # Version string
        False
    """
    try:
        # Validate it's a structurally valid IPv4 address
        ipaddress.IPv4Address(value)

        octets = [int(x) for x in value.split(".")]
        first_octet = octets[0]

        # Heuristic: Distinguish between IP addresses and version strings
        # Version strings typically have ALL small octets (e.g., 5.7.1.5, 2.4.6.8)
        # Real IPs usually have some larger octets or follow known patterns

        # Rule 1: Common IP patterns that should always be treated as IPs
        # - 10.x.x.x (private range)
        # - Any IP with first octet >= 20 (public ranges)
        if first_octet == 10 or first_octet >= 20:
            return True

        # Rule 2: Special case for DNS servers with repeated octets
        # 8.8.8.8 (Google), 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9)
        # These have all identical octets, which is very rare for version strings
        if len(set(octets)) == 1:
            return True

        # Rule 3: For IPs with low first octets (1-9, 11-19), analyze all octets
        # Version strings typically have all or most small numbers (< 20)
        small_octets = sum(1 for octet in octets if octet < 20)

        # If all 4 octets are small (< 20), it's likely a version string
        # (Already handled repeated octets above, so this won't affect 8.8.8.8)
        if small_octets == 4:
            return False

        # If 3 or more octets are small, likely a version string
        # Otherwise, treat as IP (has enough larger octets to be realistic)
        return small_octets < 3
    except (ipaddress.AddressValueError, ValueError, IndexError):
        return False


def sanitize_html(
    html: str,
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    collector: RedactionCollector | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> str:
    """Remove sensitive information from HTML.

    This function sanitizes device HTML to remove PII before inclusion in
    diagnostics or fixture files. It's designed to be thorough while
    preserving data structure for debugging.

    By default, only **known patterns** (MACs, IPs, emails, serial numbers)
    are redacted. Enable heuristics to analyze pipe-delimited values that
    lack field labels (e.g., tagValueList in router HTML).

    Args:
        html: Raw HTML from device
        salt: Salt for hashed redaction. Options:
            - "auto" (default): Random salt, correlates within this call
            - None: Static placeholders (legacy behavior)
            - Any string: Consistent hashing across calls with same salt
            (ignored if collector is provided)
        custom_patterns: Custom patterns to apply. Extends the built-in
            ``pii.patterns``, ``allowlist``, and sensitive-field sets
            (``fields.auto_redact_patterns`` / ``fields.flag_patterns``) for
            THIS CALL ONLY. Options:

            - String: Path to JSON patterns file
            - Dict: Pattern definitions directly (e.g., from modem.yaml)
            - None: Use built-in patterns only

            Field-name extensions reach the inline-script scanner
            (``localStorage.setItem`` / ``sessionStorage.setItem``) via a
            ``ContextVar``-scoped override, so e.g. ``{"fields":
            {"auto_redact_patterns": ["vendorpw"]}}`` causes values associated
            with ``"vendorpw"`` keys in inline scripts to be redacted. Module-
            global patterns are never mutated; concurrent threads / asyncio
            tasks observe their own patterns.
        collector: Optional collector for tracking redactions
        heuristics: How to handle unlabeled pipe-delimited values:
            - DISABLED (default): Skip heuristics, only redact known patterns
            - FLAG: Flag suspicious values for manual review (interactive)
            - REDACT: Auto-redact suspicious values (may over-redact)

    Returns:
        Sanitized HTML with personal info removed

    Example:
        >>> from har_capture.sanitization.report import HeuristicMode
        >>> sanitize_html("MAC: AA:BB:CC:DD:EE:FF")  # doctest: +SKIP
        'MAC: MAC_a1b2c3d4'
        >>> sanitize_html("MAC: AA:BB:CC:DD:EE:FF", salt=None)
        'MAC: ***MAC***'
        >>> # Enable heuristics for pipe-delimited values
        >>> sanitize_html(html, heuristics=HeuristicMode.REDACT)  # doctest: +SKIP
    """
    # Use collector's hasher if provided, otherwise create one
    if collector is not None:
        hasher = collector.hasher
    else:
        hasher = Hasher.create(salt)
        collector = RedactionCollector(hasher=hasher)

    # Enter the field-pattern + header-set scopes so is_sensitive_field() and
    # sanitize_header_value() calls inside the HTML scanner honor custom_patterns.
    # Lazy import: har imports html at module level, so we'd cycle if this were
    # top-level.
    from har_capture.sanitization.har import (
        _FIELD_PATTERNS_CTX,
        _HEADER_SETS_CTX,
        _resolve_field_patterns,
        _resolve_header_sets,
    )

    _field_token = _FIELD_PATTERNS_CTX.set(_resolve_field_patterns(custom_patterns))
    _header_token = _HEADER_SETS_CTX.set(_resolve_header_sets(custom_patterns))
    try:
        return _sanitize_html_impl(
            html,
            hasher=hasher,
            collector=collector,
            custom_patterns=custom_patterns,
            heuristics=heuristics,
        )
    finally:
        _HEADER_SETS_CTX.reset(_header_token)
        _FIELD_PATTERNS_CTX.reset(_field_token)


def _sanitize_html_impl(
    html: str,
    *,
    hasher: Hasher,
    collector: RedactionCollector,
    custom_patterns: str | dict[str, Any] | None,
    heuristics: HeuristicMode,
) -> str:
    """Inner body of :func:`sanitize_html` — runs inside the active field-pattern scope."""
    pii = load_pii_patterns(custom_patterns)
    sensitive = load_sensitive_patterns(custom_patterns)

    # Compile domain-specific safe-value patterns and detectors from loaded sensitive data
    from har_capture.patterns.loader import compile_detectors, compile_safe_value_patterns

    extra_safe_patterns = compile_safe_value_patterns(sensitive)
    compiled_detectors = compile_detectors(sensitive)

    # Lazy imports — must stay inside function body to avoid circular import
    # (har.py imports html.py at module level; html.py needs har.py's field matcher)
    from har_capture.sanitization.har import is_sensitive_field
    from har_capture.sanitization.heuristics import analyze_value

    # 0. Custom patterns (apply first so they take precedence over built-in patterns)
    # Skip built-in patterns that have dedicated replacement logic below
    BUILTIN_PATTERNS = {
        "mac_address",
        "serial_number",
        "wps_pin",
        "account_id",
        "private_ip",
        "public_ip",
        "ipv6",
        "email",
        "password_field",
        "password_input",
        "session_token",
        "csrf_token",
        "config_path",
        "motorola_password",
    }

    for pattern_name, pattern_def in pii.get("patterns", {}).items():
        # Skip built-in patterns with special handling
        if pattern_name in BUILTIN_PATTERNS:
            continue

        if not isinstance(pattern_def, dict) or "regex" not in pattern_def:
            continue

        regex = pattern_def["regex"]
        prefix = pattern_def.get("replacement_prefix", "CUSTOM")

        # Handle regex flags
        flags = 0
        if "flags" in pattern_def:
            for flag_name in pattern_def["flags"]:
                if flag_name == "IGNORECASE":
                    flags |= re.IGNORECASE

        def make_replacer(prefix: str, pname: str) -> Any:
            def replace_custom(match: re.Match[str]) -> str:
                collector.record_auto_redaction(pname)
                return hasher.hash_generic(match.group(0), prefix)

            return replace_custom

        html = re.sub(regex, make_replacer(prefix, pattern_name), html, flags=flags)

    # 0b. Web Storage setItem() calls in inline <script> blocks
    # Catches: localStorage.setItem("key", "value") and sessionStorage.setItem("key", "value")
    # Must run BEFORE general PII passes so sensitive-key values are fully replaced
    # (otherwise IP/MAC passes partially mangle values like "http://10.0.1.1/firmware.bin")
    def replace_setitem(match: re.Match[str]) -> str:
        prefix = match.group(1)
        key = match.group(2)
        sep = match.group(3)
        value = match.group(4)
        suffix = match.group(5)

        # Tier A: Key matches sensitive field patterns -> auto-redact value
        if is_sensitive_field(key):
            collector.record_auto_redaction("web_storage")
            redacted = hasher.hash_generic(value, "STORAGE")
            return f"{prefix}{key}{sep}{redacted}{suffix}"

        # Tier B: Value PII (IPs, MACs, emails) is handled by subsequent passes.
        # No action needed here.

        # Tier C: Heuristic analysis on opaque values
        if heuristics != HeuristicMode.DISABLED:
            should_flag, confidence, category, reason = analyze_value(
                value,
                extra_safe_patterns=extra_safe_patterns,
                compiled_detectors=compiled_detectors,
            )
            if should_flag:
                if heuristics == HeuristicMode.REDACT:
                    collector.record_auto_redaction(category)
                    redacted = hasher.hash_sensitive_value(value, category)
                    return f"{prefix}{key}{sep}{redacted}{suffix}"
                if heuristics == HeuristicMode.FLAG:
                    context = f'setItem("{key}", ">>>{value}<<<")'
                    collector.flag_value(value, category, confidence, context, reason)

        return match.group(0)

    html = re.sub(
        r"""((?:local|session)Storage\.setItem\s*\(\s*["'])([^"']+)(["']\s*,\s*["'])([^"']+)(["']\s*\))""",
        replace_setitem,
        html,
        flags=re.IGNORECASE,
    )

    # Idempotency boundary: passes that emit a `PREFIX_<hash>` placeholder skip
    # values `is_redacted()` already recognizes, so re-sanitizing is a no-op and
    # a placeholder can never be re-hashed into a compounding
    # `SERIAL_<hash>_<hash>` chain. The format-preserving passes below (MAC, IPs,
    # IPv6, email) deliberately do NOT take that guard: their placeholders are
    # valid-looking values in reserved ranges, indistinguishable from real ones.
    # `02:aa:bb:cc:dd:ee` is a legitimate locally-administered MAC and
    # `10.255.62.183` a legitimate private address — skipping them to buy
    # cosmetic stability would leak real values. They stay non-idempotent by
    # design; ADR-12 puts the burden of proof on redacting less, not more.
    # 1. MAC Addresses (various formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
    def replace_mac(match: re.Match[str]) -> str:
        collector.record_auto_redaction("mac_address")
        return hasher.hash_mac(match.group(0))

    html = re.sub(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", replace_mac, html)

    # 2. Serial Numbers (various label formats)
    # The tag chain `(?:<[^>]*>\s*)*` tolerates whitespace between tags so
    # label/value pairs in sibling elements match (Technicolor .jst renders
    # <span>Serial Number:</span>\n<span class="value">\nVALUE</span>).
    # The separator + tag run is captured and re-emitted verbatim so redaction
    # replaces only the value and preserves the surrounding markup.
    def replace_serial(match: re.Match[str]) -> str:
        if is_redacted(match.group(3), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("serial_number")
        label = match.group(1)
        sep = match.group(2)
        serial = match.group(3)
        return f"{label}{sep}{hasher.hash_generic(serial, 'SERIAL')}"

    html = re.sub(
        r"\b(Serial\s*Number|SerialNum|SN|S/N)\b(\s*[:\s=]*(?:<[^>]*>\s*)*)([a-zA-Z0-9\-_]{5,})",
        replace_serial,
        html,
        flags=re.IGNORECASE,
    )

    # 2b. Serial numbers in HTML table cells (label in one <td>, value in next <td>)
    # Handles: <td>...<strong>Serial Number</strong>...</td>\s*<td>VALUE</td>
    def replace_serial_table(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("serial_number")
        prefix = match.group(1)
        serial = match.group(2)
        hashed = hasher.hash_generic(serial, "SERIAL")
        return f"{prefix}{hashed}"

    html = re.sub(
        r"(<td[^>]*>\s*(?:<[^>]*>\s*)*(?:Serial\s*Number|SerialNum|SN|S/N)\b\s*(?:<[^>]*>\s*)*</td>\s*<td[^>]*>\s*(?:<[^>]*>\s*)*)([a-zA-Z0-9\-_]{5,})(?=\s*(?:<[^>]*>\s*)*</td>)",
        replace_serial_table,
        html,
        flags=re.IGNORECASE,
    )

    # 2d. WPS / pairing / default PIN — 8-digit value anchored by a known label.
    # Pure-digit values can't be flagged heuristically (the universal `^\d+$`
    # safe pattern would have to be relaxed, drowning the review UI in counter
    # noise). The label is what makes the regex layer's 100% confidence bar
    # achievable. See issue #47 and docs/ARCHITECTURE.md § Confidence boundary.
    # Tag chain and separator handling mirror pass 2: whitespace-tolerant
    # sibling-element matching, with the separator + tag run preserved.
    def replace_wps_pin(match: re.Match[str]) -> str:
        if is_redacted(match.group(3), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("wps_pin")
        label = match.group(1)
        sep = match.group(2)
        pin = match.group(3)
        return f"{label}{sep}{hasher.hash_generic(pin, 'PIN')}"

    html = re.sub(
        r"(WPS[\s_-]*PIN|PIN[\s_-]*Code|Pairing[\s_-]*PIN|Default[\s_-]*PIN)\b(\s*[:\s=]*(?:<[^>]*>\s*)*)(\d{8})\b",
        replace_wps_pin,
        html,
        flags=re.IGNORECASE,
    )

    # 2c. JavaScript serial number variables
    # Matches: names containing serial+number/num/no (e.g., serialNumber, serial_num, SerialNo)
    # Matches: names ending with "serial" (e.g., deviceSerial, modem_serial)
    # Does NOT match: serial+Port, serial+Protocol, serial+Baud, serialization, serialized
    def replace_js_serial(match: re.Match[str]) -> str:
        if is_redacted(match.group(4), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("serial_number")
        label = match.group(1)
        sep = match.group(2)
        quote1 = match.group(3)
        quote2 = match.group(5)
        return f"{label}{sep}{quote1}{hasher.hash_generic(match.group(4), 'SERIAL')}{quote2}"

    html = re.sub(
        r'(\w*serial[-_]?(?:num(?:ber)?|no)\w*|\w+serial)\s*([=:])\s*(["\'])([^"\']+)(["\'])',
        replace_js_serial,
        html,
        flags=re.IGNORECASE,
    )

    # 2e. Vendor-format serials as standalone tokens — delimiter-aware.
    # Netgear firmware ships the serial inside pipe-delimited blobs
    # (RouterStatus.htm tagValueList) where no label exists for passes 2-2c
    # to anchor on, and FLAG-mode review is the only thing between the raw
    # serial and the shared artifact (CM2500 round-1 leak, 2026-08-19). A
    # high-confidence serial_number detector asserts a vendor layout tight
    # enough for the scanner pipeline's 100%-confidence bar, so those
    # formats auto-redact here. Token extraction bounds the match at
    # delimiters; a serial-shaped substring of a longer token never fires.
    html = redact_vendor_serials(html, compiled_detectors, hasher, collector)

    # 3. Account/Subscriber IDs
    def replace_account(match: re.Match[str]) -> str:
        prefix = match.group(1)
        suffix = match.group(2)
        value = match.group(3)

        # Skip if value is already redacted (contains "_" indicating a hash prefix like TEST_xxxxx)
        if "_" in value and re.match(r"^[A-Z]+_[a-f0-9]+$", value):
            return match.group(0)  # Return unchanged

        collector.record_auto_redaction("account")
        return f"{prefix} {suffix}: {hasher.hash_generic(match.group(0), 'ACCOUNT')}"

    html = re.sub(
        r"(Account|Subscriber|Customer|Device)\s*(ID|Number)\s*[:\s=]+(\S+)",
        replace_account,
        html,
        flags=re.IGNORECASE,
    )

    # 4. Private IP addresses (keep common gateway IPs for context)
    preserved_ips = set(pii.get("preserved_gateway_ips", []))

    def replace_private_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if ip in preserved_ips:
            return ip
        # Private IP regex only matches 10.x/172.16-31.x/192.168.x — all have
        # first octets (10, 172, 192) that pass is_valid_ip_address() unconditionally,
        # so no version-string check is needed here (unlike public IPs in pass 5).
        collector.record_auto_redaction("private_ip")
        return hasher.hash_ip(ip, is_private=True)

    html = re.sub(
        r"\b(?:"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"  # 10.x.x.x
        r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|"  # 172.16-31.x.x
        r"192\.168\.\d{1,3}\.\d{1,3}"  # 192.168.x.x
        r")\b",
        replace_private_ip,
        html,
    )

    # 5. Public IP addresses (any non-private, non-localhost IP)
    def replace_public_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        # Validate it's actually an IP, not a version string
        if not is_valid_ip_address(ip):
            return ip  # Preserve version strings
        collector.record_auto_redaction("public_ip")
        return hasher.hash_ip(ip, is_private=False)

    html = re.sub(
        r"\b(?!10\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)"
        r"(?!127\.)(?!0\.)(?!255\.)"
        r"(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
        r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
        r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
        r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b",
        replace_public_ip,
        html,
    )

    # 6. IPv6 Addresses (full and compressed) - strict validation
    def replace_ipv6(match: re.Match[str]) -> str:
        text: str = match.group(0)
        # Skip if it looks like a MAC address (6 groups of 2 hex chars)
        if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", text, re.IGNORECASE):
            return text
        # Use strict validation via ipaddress module
        try:
            ipaddress.IPv6Address(text)
            collector.record_auto_redaction("ipv6")
            return hasher.hash_ipv6(text)
        except ipaddress.AddressValueError:
            # Not a valid IPv6 address (e.g., time format "12:34:56")
            return text

    # Match potential IPv6 addresses including compressed forms like ::1
    # Use (?<![:\w]) instead of \b to handle addresses starting with ::
    html = re.sub(
        r"(?<![:\w])([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![:\w])",
        replace_ipv6,
        html,
        flags=re.IGNORECASE,
    )

    # 7. Passwords/Passphrases in HTML forms or text
    def replace_password(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("password")
        label = match.group(1)
        return f"{label}={hasher.hash_generic(match.group(2), 'PASS')}"

    html = re.sub(
        r'(password|passphrase|psk|key|wpa[0-9]*key)\s*[=:]\s*["\'\\]?([^"\'<>\s]+)',
        replace_password,
        html,
        flags=re.IGNORECASE,
    )

    # 7a. SSID labels in HTML text (<p>SSID: MyNetwork</p>)
    def replace_ssid_text(match: re.Match[str]) -> str:
        if is_redacted(match.group(3), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("wifi")
        label = match.group(1)
        sep = match.group(2)
        return f"{label}{sep}{hasher.hash_generic(match.group(3), 'WIFI')}"

    html = re.sub(
        r'\b(SSID|Network\s*Name)\s*([=:])\s*([^\s<>"\']+)',
        replace_ssid_text,
        html,
        flags=re.IGNORECASE,
    )

    # 7b. JavaScript object password fields (password_24g: 'value', guest_password: 'value')  # pragma: allowlist secret
    def replace_js_password(match: re.Match[str]) -> str:
        if is_redacted(match.group(4), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("password")
        label = match.group(1)
        sep = match.group(2)
        quote1 = match.group(3)
        quote2 = match.group(5)
        return f"{label}{sep}{quote1}{hasher.hash_generic(match.group(4), 'PASS')}{quote2}"

    html = re.sub(
        r'(\w*password\w*)\s*([=:])\s*(["\'])([^"\']+)(["\'])',
        replace_js_password,
        html,
        flags=re.IGNORECASE,
    )

    # 7c. Sibling-element sticker labels (Device Label Information block).
    # The value lives in its own element rather than inline after the label, so
    # the inline passes above cannot reach it: their value class stops at `<`.
    # Runs after passes 7/7a/7b so an already-redacted inline match is not
    # re-processed; it is otherwise independent of them. The label run and the
    # value element's opening tag are re-emitted verbatim (mirroring passes 2
    # and 2d), so redaction replaces only the value and sanitized fixtures keep
    # their DOM structure.
    #
    # A default Wi-Fi password printed on the device sticker is a live
    # credential, not device metadata: XB7/XB10 captures reached a public issue
    # with it in plain text (issue #194). The default SSID is redacted
    # alongside it — the pair together identifies the household's network, and
    # the SSID is what makes the password usable.
    html = redact_structural_credentials(html, hasher, collector, custom_patterns)

    # 8. Password input fields
    def replace_password_input(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("password")
        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}{hasher.hash_generic(match.group(2), 'PASS')}{suffix}"

    html = re.sub(
        r'(<input[^>]*type=["\'\\]?password["\'\\]?[^>]*value=["\'\\]?)([^"\'\\]+)(["\'\\]?)',
        replace_password_input,
        html,
        flags=re.IGNORECASE,
    )

    # 8b. SSID input fields (input following SSID label)
    # Matches: <label>...SSID...</label><input value="...">
    def replace_ssid_input(match: re.Match[str]) -> str:
        if is_redacted(match.group(3), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("wifi")
        prefix = match.group(1)
        value_start = match.group(2)
        value_end = match.group(4)
        return f"{prefix}{value_start}{hasher.hash_generic(match.group(3), 'WIFI')}{value_end}"

    html = re.sub(
        r'(<label>[^<]*SSID[^<]*</label>\s*<input[^>]*)(value=["\'\\]?)([^"\'\\>]+)(["\'\\]?)',
        replace_ssid_input,
        html,
        flags=re.IGNORECASE,
    )

    # 9. Session tokens/cookies (long alphanumeric strings)
    def replace_token(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("token")
        label = match.group(1)
        return f"{label}={hasher.hash_generic(match.group(2), 'TOKEN')}"

    html = re.sub(
        r'(session|token|auth|cookie)\s*[=:]\s*["\'\\]?([^"\'<>\s]{20,})',
        replace_token,
        html,
        flags=re.IGNORECASE,
    )

    # 10. CSRF tokens in meta tags
    def replace_csrf(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("csrf")
        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}{hasher.hash_generic(match.group(2), 'CSRF')}{suffix}"

    html = re.sub(
        r'(<meta[^>]*name=["\'\\]?csrf-token["\'\\]?[^>]*content=["\'\\]?)([^"\'\\]+)(["\'\\]?)',
        replace_csrf,
        html,
        flags=re.IGNORECASE,
    )

    # 11. Email addresses (RFC 5321 simplified)
    def replace_email(match: re.Match[str]) -> str:
        collector.record_auto_redaction("email")
        return hasher.hash_email(match.group(0))

    # Pattern supports: user@domain.tld, user.name+tag@sub.domain.co.uk
    html = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b",
        replace_email,
        html,
    )

    # 12. Config file paths (may contain ISP/customer identifiers)
    def replace_config(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("config")
        label = match.group(1)
        return f"{label}: {hasher.hash_generic(match.group(2), 'CONFIG')}"

    html = re.sub(
        r"(Config\s*File\s*Name|config\s*file)\s*[:\s=]+([^\s<>]+\.cfg)",
        replace_config,
        html,
        flags=re.IGNORECASE,
    )

    # 13. Motorola JavaScript password variables
    def replace_motorola_pw(match: re.Match[str]) -> str:
        if is_redacted(match.group(2), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("password")
        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}{hasher.hash_generic(match.group(2), 'PASS')}{suffix}"

    html = re.sub(
        r"(var\s+Current(?:Pw|Password)[A-Za-z]*\s*=\s*['\"])([^'\"]+)(['\"])",
        replace_motorola_pw,
        html,
        flags=re.IGNORECASE,
    )

    # 14. WiFi credentials and device names in Netgear tagValueList
    safe_values = set(v.lower() for v in sensitive.get("tagValueList", {}).get("safe_values", []))

    def sanitize_tag_value_list(match: re.Match[str]) -> str:
        """Sanitize pipe-delimited values in tagValueList.

        Splits by ``|``, delegates each value to ``_sanitize_pipe_value()``,
        and reassembles.
        """
        prefix = match.group(1)
        values_str = match.group(2)
        suffix = match.group(3)

        values = values_str.split("|")
        sanitized_values: list[str] = []

        for val in values:
            result = _sanitize_pipe_value(
                val.strip(),
                hasher=hasher,
                collector=collector,
                safe_values=safe_values,
                extra_safe_patterns=extra_safe_patterns,
                compiled_detectors=compiled_detectors,
                heuristics=heuristics,
                values_context=sanitized_values,
                value_index=len(sanitized_values),
                all_values=values,
            )
            sanitized_values.append(result)

        return prefix + "|".join(sanitized_values) + suffix

    html = re.sub(
        r"(var\s+tagValueList\s*=\s*['\"])([^'\"]+)(['\"])",
        sanitize_tag_value_list,
        html,
    )

    # 15. Other pipe-delimited variables (connectedDevices, deviceList, systemInfo, etc.)
    html = re.sub(
        r"(var\s+(?:(?:connected)?[Dd]evice(?:s|List)?|(?:system|wifi|network|modem|router|wan|lan)[Ii]nfo)\s*=\s*['\"])([^'\"]+)(['\"])",
        sanitize_tag_value_list,
        html,
    )

    # 16. SSID fields in JavaScript objects (ssid_24g: 'value', guest_ssid: 'value')
    def replace_js_ssid(match: re.Match[str]) -> str:
        if is_redacted(match.group(4), custom_patterns):
            return match.group(0)
        collector.record_auto_redaction("wifi")
        label = match.group(1)
        sep = match.group(2)
        quote1 = match.group(3)
        quote2 = match.group(5)
        return f"{label}{sep}{quote1}{hasher.hash_generic(match.group(4), 'WIFI')}{quote2}"

    html = re.sub(
        r'(\w*ssid\w*)\s*([=:])\s*(["\'])([^"\']+)(["\'])',
        replace_js_ssid,
        html,
        flags=re.IGNORECASE,
    )

    return html


def redact_structural_credentials(
    content: str,
    hasher: Hasher,
    collector: RedactionCollector,
    custom_patterns: str | dict[str, Any] | None = None,
) -> str:
    """Redact structurally-located credentials and network names (pass 7c).

    All four patterns share a shape: group 1 is the markup run up to the value
    (re-emitted verbatim so the DOM survives), group 2 is the value. Whether the
    located text is actually sensitive is decided by
    :func:`is_structural_value_sensitive`, the same predicate ``validate`` and
    :func:`check_for_pii` use.

    Exposed separately from :func:`sanitize_html` because ``validate`` checks
    **every** response body while ``sanitize_html`` runs only for HTML/XML
    mime types. A body carrying this markup under any other mime type would
    otherwise be flagged as an error that no sanitize run could clear.

    Args:
        content: Text to scan (HTML, or any body that may embed it)
        hasher: Hasher for placeholder generation
        collector: Redaction collector for counts
        custom_patterns: Optional path to custom patterns file

    Returns:
        Content with structurally-located credentials replaced
    """

    def make_replacer(prefix: str, category: str) -> Any:
        def replace(match: re.Match[str]) -> str:
            value = match.group(2)
            if not is_structural_value_sensitive(value, custom_patterns):
                return match.group(0)
            collector.record_auto_redaction(category)
            return f"{match.group(1)}{hasher.hash_generic(value, prefix)}"

        return replace

    content = SIBLING_PASSWORD_RE.sub(make_replacer("PASS", "password"), content)
    content = SIBLING_SSID_RE.sub(make_replacer("WIFI", "wifi"), content)
    content = SSID_ATTRIBUTE_RE.sub(make_replacer("WIFI", "wifi"), content)

    def replace_select(match: re.Match[str]) -> str:
        return SSID_OPTION_RE.sub(make_replacer("WIFI", "wifi"), match.group(0))

    return SSID_SELECT_RE.sub(replace_select, content)


def check_for_pii(
    content: str,
    filename: str = "",
    custom_patterns: str | None = None,
) -> list[dict[str, Any]]:
    """Check content for potential PII that should be sanitized.

    This function is intended for CI/PR validation to catch unsanitized
    fixtures before they are committed.

    Args:
        content: Text content to check (HTML, etc.)
        filename: Optional filename for context in warnings
        custom_patterns: Optional path to custom patterns JSON file

    Returns:
        List of dicts with 'pattern', 'match', 'line', and 'filename' for each PII found

    Example:
        >>> findings = check_for_pii("MAC: DE:AD:BE:EF:CA:FE")
        >>> findings[0]["pattern"]
        'mac_address'
    """
    pii = load_pii_patterns(custom_patterns)
    allowlist = load_allowlist(custom_patterns)
    findings: list[dict[str, Any]] = []

    # Labeled default credentials in sibling-element label/value pairs. These
    # live as compiled patterns rather than pii.json entries because the pass-0
    # generic replacer substitutes the whole match, which would flatten the
    # label markup this pattern deliberately preserves. Sharing the compiled
    # patterns keeps all three detection paths — sanitizer pass 7c, `validate`,
    # and this CI fixture gate — from drifting apart (issue #194).
    for sibling_pattern, sibling_name in (
        (SIBLING_PASSWORD_RE, "default_password_label"),
        (SIBLING_SSID_RE, "default_ssid_label"),
        (SSID_ATTRIBUTE_RE, "ssid_attribute"),
    ):
        for match in sibling_pattern.finditer(content):
            value = match.group(2)
            # No separate allowlist check: is_structural_value_sensitive()
            # already runs is_redacted(), and both resolve to the same
            # _check_patterns() over the same loaded allowlist.
            if not is_structural_value_sensitive(value, custom_patterns):
                continue
            findings.append(
                {
                    "pattern": sibling_name,
                    "match": value,
                    "line": content.count("\n", 0, match.start(2)) + 1,
                    "filename": filename,
                }
            )

    for option_value, option_offset in iter_ssid_option_values(content, custom_patterns):
        findings.append(
            {
                "pattern": "ssid_select_option",
                "match": option_value,
                "line": content.count("\n", 0, option_offset) + 1,
                "filename": filename,
            }
        )

    for pattern_name, pattern_def in pii.get("patterns", {}).items():
        if not isinstance(pattern_def, dict) or "regex" not in pattern_def:
            continue

        regex = pattern_def["regex"]
        flags = 0
        if "flags" in pattern_def:
            for flag_name in pattern_def["flags"]:
                if flag_name == "IGNORECASE":
                    flags |= re.IGNORECASE

        matches = re.finditer(regex, content, flags)
        for match in matches:
            matched_text = match.group(0)

            # Skip if it's an allowlisted placeholder
            if is_allowlisted(matched_text, allowlist):
                continue

            # For IPv6 pattern, skip if it doesn't contain hex letters (a-f)
            if pattern_def.get("require_hex_letter") and not re.search(r"[a-f]", matched_text, re.IGNORECASE):
                continue

            # Find line number
            line_num = content.count("\n", 0, match.start()) + 1

            findings.append(
                {
                    "pattern": pattern_name,
                    "match": matched_text,
                    "line": line_num,
                    "filename": filename,
                }
            )

    return findings
