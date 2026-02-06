"""Tests for IPv4 sanitization bugs discovered by Cable Modem Monitor team.

Bug #1: 5-Octet Bug - IPv4 addresses corrupted to invalid 5-octet format
Bug #2: Version String Bug - Firmware versions incorrectly sanitized as IPs

Reference: docs/har-capture-bug-report.md
"""

from __future__ import annotations

import re

import pytest

from har_capture.sanitization import sanitize_html
from har_capture.sanitization.report import HeuristicMode


def test_private_ip_four_octets_not_five():
    """Bug #1: Private IPs should produce valid 4-octet format, not 5-octet.

    Before fix: "10.123.45.67" -> "10.255.129.240.67" (5 octets - INVALID!)
    After fix:  "10.123.45.67" -> "10.255.129.240" (4 octets - valid)
    """
    html = "<td>IP Address: 10.123.45.67</td>"
    result = sanitize_html(html, heuristics=HeuristicMode.DISABLED)

    # Should NOT contain original IP
    assert "10.123.45.67" not in result

    # Should NOT have 5 octets anywhere in the result
    assert not re.search(r"\d+\.\d+\.\d+\.\d+\.\d+", result)

    # Should have exactly 4 octets in the replacement starting with 10.255
    match = re.search(r"10\.255\.\d+\.\d+", result)
    assert match is not None, f"Expected 4-octet replacement, got: {result}"

    # Verify it's a valid 4-octet format
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", result)
    assert ip_match is not None
    ip_parts = ip_match.group(1).split(".")
    assert len(ip_parts) == 4, f"Expected 4 octets, got {len(ip_parts)}: {ip_match.group(1)}"


def test_private_ip_examples():
    """Test various private IP addresses are sanitized correctly.

    Note: Some IPs like 10.0.0.1 and 192.168.1.1 are preserved as common gateway IPs.
    """
    test_cases = [
        ("10.0.0.1", False),  # Preserved gateway IP
        ("10.123.45.67", True),  # Should be sanitized
        ("192.168.1.1", False),  # Preserved gateway IP
        ("192.168.1.100", True),  # Should be sanitized
        ("172.16.0.1", True),  # Should be sanitized
        ("172.31.255.254", True),  # Should be sanitized
    ]

    for ip, should_sanitize in test_cases:
        html = f"<td>Gateway: {ip}</td>"
        result = sanitize_html(html)

        if should_sanitize:
            # Should be sanitized
            assert ip not in result, f"IP {ip} should be sanitized"
            # Should have valid 4-octet IP
            assert re.search(r"10\.255\.\d+\.\d+", result), f"Expected sanitized IP for {ip}"
            # Should NOT have 5 octets
            assert not re.search(r"\d+\.\d+\.\d+\.\d+\.\d+", result), f"5-octet bug for {ip}"
        else:
            # Preserved gateway IP - should remain unchanged
            assert ip in result, f"Gateway IP {ip} should be preserved"


def test_version_strings_preserved():
    """Bug #2: Firmware version strings should be preserved, not sanitized.

    Version strings like "5.7.1.5" are NOT PII and must be preserved for
    support diagnostics.
    """
    test_cases = [
        ("Software Version: 7621-5.7.1.5", "5.7.1.5"),
        ("Firmware: 2.4.6.8", "2.4.6.8"),
        ("Build: 8.1.0.24-GA", "8.1.0.24"),
        ("Version: V1.2.3.4", "1.2.3.4"),
        ("Hardware: 3.0.0.1", "3.0.0.1"),
        ("Bootloader: 1.0.0.0", "1.0.0.0"),
    ]

    for html_input, expected_version in test_cases:
        result = sanitize_html(f"<td>{html_input}</td>", heuristics=HeuristicMode.REDACT)
        assert expected_version in result, (
            f"Version {expected_version} should be preserved in '{html_input}', got: {result}"
        )


def test_real_public_ips_still_sanitized():
    """Ensure real public IP addresses are still properly sanitized.

    Public IPs should be sanitized, including special cases like DNS servers.
    """
    test_cases = [
        "8.8.8.8",  # Google DNS (repeated octets - should be treated as IP)
        "1.1.1.1",  # Cloudflare DNS (repeated octets - should be treated as IP)
        "20.0.0.1",  # First octet = 20 (boundary)
        "50.60.70.80",  # Mid-range public IP
        "203.0.113.1",  # TEST-NET-3
    ]

    for ip in test_cases:
        html = f"<td>DNS Server: {ip}</td>"
        result = sanitize_html(html)

        assert ip not in result, f"Public IP {ip} should be sanitized"


def test_version_strings_in_various_contexts():
    """Test version strings in different HTML contexts."""
    test_cases = [
        # Motorola modem examples from bug report
        "<td>Software Version</td><td>7621-5.7.1.5</td>",
        "<div>Firmware: MB7621-5.7.1.5</div>",
        # Other common patterns
        "<span>Version 2.4.6.8</span>",
        "<p>Build: 8.1.0.24-GA</p>",
        "Hardware Version: 3.0.0.1",
        # JavaScript variables
        'var firmwareVersion = "5.7.1.5";',
        'version: "2.4.6.8"',
    ]

    for html in test_cases:
        result = sanitize_html(html)

        # Extract version numbers from original
        versions = re.findall(r"\b[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}\b", html)
        for version in versions:
            # Version strings with first octet < 20 should be preserved
            first_octet = int(version.split(".")[0])
            if first_octet < 20 and first_octet != 10:
                assert version in result, f"Version {version} should be preserved in: {html}\nGot: {result}"


def test_mixed_ips_and_versions():
    """Test HTML with both real IPs and version strings.

    Note: 192.168.1.1 is a preserved gateway IP and won't be sanitized.
    """
    html = """
    <table>
        <tr><td>Gateway IP:</td><td>192.168.1.1</td></tr>
        <tr><td>Firmware Version:</td><td>5.7.1.5</td></tr>
        <tr><td>DNS Server:</td><td>8.8.8.8</td></tr>
        <tr><td>Hardware Version:</td><td>3.0.0.1</td></tr>
        <tr><td>Device IP:</td><td>10.50.100.200</td></tr>
    </table>
    """

    result = sanitize_html(html)

    # Version strings should be preserved
    assert "5.7.1.5" in result, "Firmware version should be preserved"
    assert "3.0.0.1" in result, "Hardware version should be preserved"

    # 192.168.1.1 is a preserved gateway IP
    assert "192.168.1.1" in result, "Gateway IP 192.168.1.1 is preserved"

    # Public IP should be sanitized
    assert "8.8.8.8" not in result, "Public IP should be sanitized"

    # Non-gateway private IP should be sanitized
    assert "10.50.100.200" not in result, "Private IP should be sanitized"

    # Should have sanitized IPs (4 octets)
    assert re.search(r"10\.255\.\d+\.\d+", result), "Should have sanitized private IPs"

    # Should NOT have 5 octets anywhere
    assert not re.search(r"\d+\.\d+\.\d+\.\d+\.\d+", result), "Should not have 5-octet corruption"


def test_edge_case_10_network():
    """Test that 10.x.x.x IPs are sanitized (not treated as versions).

    Note: 10.0.0.1 is a preserved gateway IP in the default config.
    """
    # Test with non-gateway 10.x.x.x IP
    html = "<td>IP: 10.50.100.200</td>"
    result = sanitize_html(html)

    # Non-gateway 10.x.x.x should be sanitized
    assert "10.50.100.200" not in result, "10.x.x.x should be sanitized"
    assert re.search(r"10\.255\.\d+\.\d+", result), "Should have sanitized IP"


def test_edge_case_boundary_octets():
    """Test boundary cases around first octet = 20."""
    test_cases = [
        ("19.0.0.1", True),  # < 20, treat as version, preserve
        ("20.0.0.1", False),  # >= 20, treat as IP, sanitize
        ("21.0.0.1", False),  # > 20, treat as IP, sanitize
    ]

    for ip, should_preserve in test_cases:
        html = f"<td>Address: {ip}</td>"
        result = sanitize_html(html)

        if should_preserve:
            assert ip in result, f"{ip} should be preserved (likely version)"
        else:
            assert ip not in result, f"{ip} should be sanitized (public IP)"


def test_no_five_octet_corruption():
    """Comprehensive test that NO input produces 5-octet output."""
    test_ips = [
        "10.0.0.1",
        "10.123.45.67",
        "10.255.255.255",
        "192.168.0.1",
        "192.168.1.100",
        "192.168.255.254",
        "172.16.0.1",
        "172.31.255.254",
    ]

    for ip in test_ips:
        html = f"<td>Test IP: {ip}</td>"
        result = sanitize_html(html)

        # Should NOT have 5 octets
        five_octet_match = re.search(r"\d+\.\d+\.\d+\.\d+\.\d+", result)
        assert five_octet_match is None, (
            f"5-octet corruption detected for {ip}: {five_octet_match.group(0) if five_octet_match else 'N/A'}\nResult: {result}"
        )


def test_version_string_with_prefix():
    """Test version strings with prefixes like 'V' or model numbers."""
    html = """
    <td>Firmware: MB7621-5.7.1.5</td>
    <td>Version: V1.2.3.4</td>
    <td>Software: ARRIS-2.4.6.8</td>
    """
    result = sanitize_html(html)

    # Version numbers should be preserved
    assert "5.7.1.5" in result
    assert "1.2.3.4" in result
    assert "2.4.6.8" in result


@pytest.mark.parametrize(
    ("value", "expected", "reason"),
    [
        # Valid IPs that should be sanitized (return True)
        ("192.168.1.100", True, "Private IP"),
        ("8.8.8.8", True, "Repeated octets (DNS)"),
        ("1.1.1.1", True, "Repeated octets (DNS)"),
        ("50.60.70.80", True, "All octets >= 20"),
        ("20.0.0.1", True, "First octet == 20 (boundary)"),
        ("10.50.100.200", True, "First octet == 10"),
        ("11.12.200.201", True, "2 small octets (< 3)"),
        ("5.50.60.70", True, "1 small octet (< 3)"),
        # Version strings that should be preserved (return False)
        ("5.7.1.5", False, "4 small octets (version)"),
        ("2.4.6.8", False, "4 small octets (version)"),
        ("1.2.3.4", False, "4 small octets (version)"),
        ("11.12.13.200", False, "3 small octets (version)"),
        # Invalid IP strings (return False via exception)
        ("not.an.ip.address", False, "Invalid format"),
        ("999.999.999.999", False, "Out of range"),
        ("1.2.3", False, "Too few octets"),
        ("", False, "Empty string"),
        ("invalid", False, "Not an IP"),
    ],
)
def test_is_valid_ip_address_edge_cases(value, expected, reason):
    """Test edge cases for is_valid_ip_address() helper function.

    This ensures full coverage of the heuristic logic.
    """
    from har_capture.sanitization.html import is_valid_ip_address

    assert is_valid_ip_address(value) is expected, f"{value} ({reason})"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
