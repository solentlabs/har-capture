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
from typing import TYPE_CHECKING

from har_capture.patterns import (
    Hasher,
    is_allowlisted,
    load_allowlist,
    load_pii_patterns,
    load_sensitive_patterns,
)

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
            {"auto_redact_patterns": ["pws"]}}`` causes values associated
            with ``"pws"`` keys in inline scripts to be redacted. Module-
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

    # 1. MAC Addresses (various formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
    def replace_mac(match: re.Match[str]) -> str:
        collector.record_auto_redaction("mac_address")
        return hasher.hash_mac(match.group(0))

    html = re.sub(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", replace_mac, html)

    # 2. Serial Numbers (various label formats)
    def replace_serial(match: re.Match[str]) -> str:
        collector.record_auto_redaction("serial_number")
        label = match.group(1)
        serial = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
        hashed = hasher.hash_generic(serial, "SERIAL") if serial else "***SERIAL***"
        return f"{label}: {hashed}"

    html = re.sub(
        r"\b(Serial\s*Number|SerialNum|SN|S/N)\b\s*[:\s=]*(?:<[^>]*>)*\s*([a-zA-Z0-9\-]{5,})",
        replace_serial,
        html,
        flags=re.IGNORECASE,
    )

    # 2b. Serial numbers in HTML table cells (label in one <td>, value in next <td>)
    # Handles: <td>...<strong>Serial Number</strong>...</td>\s*<td>VALUE</td>
    def replace_serial_table(match: re.Match[str]) -> str:
        collector.record_auto_redaction("serial_number")
        prefix = match.group(1)
        serial = match.group(2)
        hashed = hasher.hash_generic(serial, "SERIAL")
        return f"{prefix}{hashed}"

    html = re.sub(
        r"(<td[^>]*>(?:<[^>]*>)*\s*(?:Serial\s*Number|SerialNum|SN|S/N)\b\s*(?:<[^>]*>)*\s*</td>\s*<td[^>]*>(?:<[^>]*>)*\s*)([a-zA-Z0-9\-]{5,})(?=\s*(?:<[^>]*>)*\s*</td>)",
        replace_serial_table,
        html,
        flags=re.IGNORECASE,
    )

    # 2d. WPS / pairing / default PIN — 8-digit value anchored by a known label.
    # Pure-digit values can't be flagged heuristically (the universal `^\d+$`
    # safe pattern would have to be relaxed, drowning the review UI in counter
    # noise). The label is what makes the regex layer's 100% confidence bar
    # achievable. See issue #47 and CLAUDE.md principle #7.
    def replace_wps_pin(match: re.Match[str]) -> str:
        collector.record_auto_redaction("wps_pin")
        label = match.group(1)
        pin = match.group(2)
        hashed = hasher.hash_generic(pin, "PIN")
        return f"{label}: {hashed}"

    html = re.sub(
        r"(WPS[\s_-]*PIN|PIN[\s_-]*Code|Pairing[\s_-]*PIN|Default[\s_-]*PIN)\b\s*[:\s=]*(?:<[^>]*>)*\s*(\d{8})\b",
        replace_wps_pin,
        html,
        flags=re.IGNORECASE,
    )

    # 2c. JavaScript serial number variables
    # Matches: names containing serial+number/num/no (e.g., serialNumber, serial_num, SerialNo)
    # Matches: names ending with "serial" (e.g., deviceSerial, modem_serial)
    # Does NOT match: serial+Port, serial+Protocol, serial+Baud, serialization, serialized
    def replace_js_serial(match: re.Match[str]) -> str:
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

    # 8. Password input fields
    def replace_password_input(match: re.Match[str]) -> str:
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
