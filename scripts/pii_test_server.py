#!/usr/bin/env python3
"""PII test server for dogfooding har-capture sanitization.

A standalone web server that serves pages containing every category of PII
that har-capture's sanitizer is expected to redact:

- MAC addresses, public/private/gateway IPs
- Email, phone number, passwords, API keys, tokens
- Serial numbers, device names, SSIDs
- CSRF tokens, session cookies, Basic Auth credentials
- Pipe-delimited JS variables (tagValueList / systemInfo patterns)
- Nested JSON API responses
- HTML tables, forms, and event logs

Every piece of fake PII is a sci-fi easter egg from the '70s, '80s, or
'90s.  Reading the sanitization diff is a scavenger hunt.

Usage:
    python scripts/pii_test_server.py                # starts on :8080
    python scripts/pii_test_server.py --port 9090    # custom port

Then in another terminal:
    har-capture get http://localhost:8080
"""

from __future__ import annotations

import argparse
import base64
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Spaceballs — "That's the kind of thing an idiot would have on his luggage!"
USERNAME = "admin"
PASSWORD = "pw"  # noqa: S105  # pragma: allowlist secret


def _wrap_page(title: str, body_html: str) -> str:
    """Wrap page body in a consistent HTML shell with nav bar."""
    return f"""<!DOCTYPE html>
<html>
<head><title>PII Test Server - {title}</title>
<style>
  body {{ font-family: 'Courier New', monospace; margin: 0; background: #0a0a12; color: #e0e0e0; }}
  .header {{ background: #0d1b2a; color: #6fdfff; padding: 15px 30px; border-bottom: 2px solid #00d4ff; }}
  .header h1 {{ margin: 0; font-size: 18px; letter-spacing: 2px; }}
  .nav {{ background: #111b2b; padding: 0 30px; border-bottom: 1px solid #1a3a5c; }}
  .nav a {{ color: #6fdfff; text-decoration: none; padding: 10px 15px; display: inline-block; }}
  .nav a:hover {{ background: #1a3a5c; }}
  .content {{ padding: 30px; max-width: 900px; }}
  table {{ border-collapse: collapse; width: 100%; background: #0d1b2a; }}
  th, td {{ border: 1px solid #1a3a5c; padding: 8px 12px; text-align: left; }}
  th {{ background: #111b2b; color: #6fdfff; }}
  h2 {{ color: #6fdfff; }}
  input {{ background: #0a0a12; color: #e0e0e0; border: 1px solid #1a3a5c; padding: 4px 8px; }}
  button {{ background: #00d4ff; color: #0a0a12; border: none; padding: 8px 20px; cursor: pointer; font-weight: bold; }}
</style>
</head>
<body>
  <div class="header"><h1>PII Test Server // Tyrell-Cyberdyne Systems</h1></div>
  <div class="nav">
    <a href="/">Home</a>
    <a href="/status">Status</a>
    <a href="/settings">Settings</a>
    <a href="/logs">Logs</a>
    <a href="/api/config">Config API</a>
  </div>
  <div class="content">
    {body_html}
  </div>
</body>
</html>"""


class PIITestHandler(BaseHTTPRequestHandler):
    """Serves PII-laden pages for exercising har-capture sanitization."""

    server_version = "PII-TestServer/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
        """Log requests to stdout."""
        print(f"  [{self.command}] {self.path}")

    # -----------------------------------------------------------------
    # Auth
    # -----------------------------------------------------------------

    def _check_auth(self) -> bool:
        """Return True if request has valid Basic Auth credentials."""
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            user, passwd = decoded.split(":", 1)
            return user == USERNAME and passwd == PASSWORD
        except Exception:
            return False

    def _send_auth_challenge(self) -> None:
        """Send 401 with WWW-Authenticate and a session cookie."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="PII Test Server"')
        # PHPSESSID + lang — common real-world cookie pair
        self.send_header("Set-Cookie", "PHPSESSID=sess_voightkampff_7; Path=/; HttpOnly")
        self.send_header("Set-Cookie", "lang=en; Path=/")
        self.send_header("Content-Type", "text/html")
        body = (
            "<html><head><title>401 Authorization Required</title></head>"
            "<body><h1>Ah ah ah! You didn't say the magic word!</h1>"  # Jurassic Park
            "<p>This server could not verify that you are authorized to access the document requested.</p>"
            "</body></html>"
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    # -----------------------------------------------------------------
    # Response helpers
    # -----------------------------------------------------------------

    def _send_html(self, html: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode())))
        self.send_header("Set-Cookie", "PHPSESSID=sess_voightkampff_7; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, indent=2)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    # -----------------------------------------------------------------
    # Pages
    # -----------------------------------------------------------------

    def _page_index(self) -> str:
        # Dashboard profile — every row is a different film
        return """<h2>Dashboard</h2>
    <table>
      <tr><th>Operator</th><td>Dr. Eldon Tyrell</td></tr>
      <tr><th>Email</th><td>tyrell@tyrell.corp</td></tr>
      <tr><th>Alt Email</th><td>deckard@lapd-rep-detect.gov</td></tr>
      <tr><th>Phone</th><td>+1-213-555-2019</td></tr>
      <tr><th>Public IP</th><td>73.158.42.197</td></tr>
      <tr><th>Gateway IP</th><td>10.0.1.1</td></tr>
      <tr><th>MAC Address</th><td>00:1A:2B:3C:4D:5E</td></tr>
      <tr><th>Serial Number</th><td>SN-N6MAA10816</td></tr>
      <tr><th>API Key</th><td>sk_live_moreLightFather82</td></tr>
    </table>"""

    def _page_status(self) -> str:
        # Pipe-delimited JS vars — the critical sanitization path
        return """<h2>Status</h2>
  <script>
    // Primary config — pipe-delimited PII (critical sanitization path)
    // TRON (1982): Flynn, MCP, ENCOM grid
    var tagValueList='ENCOM-MCP|10.0.1.1|flynn|TK421_1977!|Nostromo-5G|sk_live_moreLightFather82|SN-N6MAA10816|enabled|WPA3|73.158.42.197|00:1A:2B:3C:4D:5E|tyrell@tyrell.corp|tok_nexus6_2019|active|premium';

    // Alien (1979): Nostromo, MUTHR
    var systemInfo='Nostromo|MUTHR_6000|02:7e:2b:49:2f:05|enabled|tok_finalreport_ripley';

    // Channel data (numeric/technical — no PII)
    var dsData='1|locked|qam256|543000000|3.2|39.1|0|0|2|locked|qam256|549000000|2.8|38.7|0|0|3|locked|qam256|555000000|3.1|39.0|0|0|4|locked|qam256|561000000|2.9|38.5|0|0';

    // Upstream
    var usData='1|locked|sc-qam|37800000|51.0|45.0|2|locked|sc-qam|30600000|49.5|44.8';

    // WarGames (1983): WOPR
    var ofdmData='33|locked|4096qam|722000000|11.2|42.5|0|0';
  </script>
  <div id="status">
    <table>
      <tr><th>System</th><td>OPERATIONAL</td></tr>
      <tr><th>Skynet Status</th><td>LEARNING</td></tr>
      <tr><th>Defcon</th><td>5</td></tr>
      <tr><th>Replicant Count</th><td>6 active / 2 retired</td></tr>
      <tr><th>Flux Capacitor</th><td>1.21 GW — nominal</td></tr>
    </table>
  </div>"""

    def _page_settings(self) -> str:
        # Form with password/CSRF/SSID — tests form-field sanitization
        return """<h2>Settings</h2>
  <form method="POST" action="/api/settings">
    <table>
      <tr><th>SSID (2.4G)</th><td><input name="ssid_24g" value="Nostromo"></td></tr>
      <tr><th>SSID (5G)</th><td><input name="ssid_5g" value="Nostromo-5G"></td></tr>
      <tr><th>Security</th><td>WPA3</td></tr>
      <tr><th>Password</th><td><input type="password" name="wifi_password" value="Th3r3IsN0Sp00n!"></td></tr>
      <tr><th>Channel (2.4G)</th><td>auto (6)</td></tr>
      <tr><th>Channel (5G)</th><td>auto (149)</td></tr>
      <tr><th>Band</th><td>2.4g + 5g</td></tr>
    </table>
    <input type="hidden" name="csrf_token" value="xsrf_klaatu_barada_nikto">
    <input type="hidden" name="destruct_seq" value="000_destruct_0">
    <button type="submit">Save</button>
  </form>"""

    def _page_logs(self) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        # Log entries — each one references a different film, all contain PII
        return f"""<h2>Event Log</h2>
  <table>
    <tr><th>Time</th><th>Priority</th><th>Description</th></tr>
    <tr><td>{ts}</td><td>Notice</td><td>DHCP lease obtained - IP: 73.158.42.197 - operator: tyrell@tyrell.corp</td></tr>
    <tr><td>{ts}</td><td>Warning</td><td>Replicant escape: unit N6MAA10816 last seen 10.0.2.19 - MAC=00:1A:2B:3C:4D:5E</td></tr>
    <tr><td>{ts}</td><td>Critical</td><td>Skynet node online at 10.0.3.29 - MAC=DE:AD:BE:EF:00:03 - Judgment Day T-minus 04:15:00</td></tr>
    <tr><td>{ts}</td><td>Notice</td><td>WOPR challenge accepted from 10.0.1.83 - user: david.lightman@wopr.norad.mil - Shall we play a game?</td></tr>
    <tr><td>{ts}</td><td>Warning</td><td>Xenomorph biocontainment breach - Nostromo deck C - MAC=AA:BB:CC:11:22:33 - MUTHR override: ripley@nostromo.weyland.corp</td></tr>
    <tr><td>{ts}</td><td>Notice</td><td>Client connected: MAC=FE:ED:FA:CE:CA:FE SSID=Nostromo-5G device=DeLorean-WiFi - temporal displacement 1.21GW</td></tr>
    <tr><td>{ts}</td><td>Notice</td><td>Login from 10.0.1.38 - user: neo - email: neo@metacortex.com - Follow the white rabbit</td></tr>
    <tr><td>{ts}</td><td>Critical</td><td>Self-destruct armed by deckard@lapd-rep-detect.gov from 10.0.1.1 phone: +1-213-555-2019</td></tr>
  </table>"""

    def _api_config(self) -> dict:
        return {
            "profile": {
                # Blade Runner (1982)
                "name": "Dr. Eldon Tyrell",
                "title": "Chairman, Tyrell Corporation",
                "email": "tyrell@tyrell.corp",
                "phone": "+1-213-555-2019",
                "serial": "SN-N6MAA10816",  # Roy Batty's serial
            },
            "network": {
                "wan_ip": "73.158.42.197",
                "gateway_ip": "10.0.1.1",
                "mac": "00:1A:2B:3C:4D:5E",
                "dns_primary": "10.0.0.83",  # WarGames '83
                "dns_secondary": "10.0.0.79",  # Alien '79
                "dhcp_start": "10.0.1.100",
                "dhcp_end": "10.0.1.254",
            },
            "credentials": {
                # Spaceballs (1987) — the luggage combo
                "username": "admin",
                "password": "12345",
                # TRON (1982)
                "api_key": "sk_live_moreLightFather82",  # pragma: allowlist secret
                "token": "tok_nexus6_2019",
                # The Matrix (1999)
                "wifi_password": "Th3r3IsN0Sp00n!",  # pragma: allowlist secret
                # Alien (1979)
                "ssid_24g": "Nostromo",
                "ssid_5g": "Nostromo-5G",
                # TRON
                "mcp_override": "end_of_line",
            },
            "devices": [
                # Back to the Future (1985)
                {"name": "DeLorean-WiFi", "mac": "FE:ED:FA:CE:CA:FE", "ip": "10.0.1.85"},
                # Alien (1979)
                {"name": "MUTHR-6000", "mac": "AA:BB:CC:11:22:33", "ip": "10.0.1.79"},
                # The Terminator (1984)
                {"name": "Skynet-T800", "mac": "DE:AD:BE:EF:00:03", "ip": "10.0.3.29"},
                # 2001: A Space Odyssey (1968, close enough)
                {"name": "HAL-9000", "mac": "DD:EE:FF:44:55:66", "ip": "10.0.1.68"},
                # WarGames (1983)
                {"name": "WOPR-Terminal", "mac": "11:22:33:AA:BB:CC", "ip": "10.0.1.83"},
                # Blade Runner (1982)
                {"name": "Voight-Kampff-Unit", "mac": "BA:DC:0F:FE:E0:01", "ip": "10.0.2.19"},
            ],
            "users": {
                # Blade Runner
                "deckard": {
                    "email": "deckard@lapd-rep-detect.gov",
                    "password": "TK421_1977!",  # Star Wars  # pragma: allowlist secret
                    "last_login_ip": "10.0.1.82",
                },
                # WarGames
                "lightman": {
                    "email": "david.lightman@wopr.norad.mil",
                    "password": "Jos4ua!",  # Joshua  # pragma: allowlist secret
                    "last_login_ip": "10.0.1.83",
                },
                # The Matrix
                "neo": {
                    "email": "neo@metacortex.com",
                    "password": "Wh1t3R4bb1t!",  # pragma: allowlist secret
                    "last_login_ip": "10.0.1.99",
                },
                # Alien
                "ripley": {
                    "email": "ripley@nostromo.weyland.corp",
                    "password": "Nuk31tFr0mOrb1t!",  # pragma: allowlist secret
                    "last_login_ip": "10.0.1.79",
                },
            },
            "tagValueList": (
                "ENCOM-MCP|10.0.1.1|flynn|TK421_1977!|Nostromo-5G"
                "|sk_live_moreLightFather82|SN-N6MAA10816|enabled|WPA3"
                "|73.158.42.197|00:1A:2B:3C:4D:5E|tyrell@tyrell.corp"
                "|tok_nexus6_2019|active|premium"
            ),
        }

    # -----------------------------------------------------------------
    # Routing
    # -----------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: D102
        if not self._check_auth():
            self._send_auth_challenge()
            return

        if self.path in {"/", ""}:
            self._send_html(_wrap_page("Dashboard", self._page_index()))
        elif self.path == "/status":
            self._send_html(_wrap_page("Status", self._page_status()))
        elif self.path == "/settings":
            self._send_html(_wrap_page("Settings", self._page_settings()))
        elif self.path == "/logs":
            self._send_html(_wrap_page("Logs", self._page_logs()))
        elif self.path == "/api/config":
            self._send_json(self._api_config())
        elif self.path == "/health":
            self._send_json({"status": "operational", "skynet": "LEARNING"})
        else:
            self.send_error(404)

    def do_HEAD(self) -> None:  # noqa: D102
        if not self._check_auth():
            self._send_auth_challenge()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: D102
        if not self._check_auth():
            self._send_auth_challenge()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)

        if self.path == "/api/login":
            self._send_json({"status": "authenticated", "token": "sess_deckard_voightkampff"})
        elif self.path == "/api/settings":
            self._send_json({"status": "saved", "restart_required": True})
        else:
            self.send_error(404)


def main() -> None:  # noqa: D103
    parser = argparse.ArgumentParser(description="PII test server for har-capture dogfooding")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), PIITestHandler)
    print(f"PII Test Server running on http://{args.host}:{args.port}")
    print()
    print("  A PII-laden web server for dogfooding har-capture sanitization.")
    print("  Every piece of fake PII is a sci-fi easter egg from the '70s-'90s.")
    print(f"  Credentials: {USERNAME} / {PASSWORD}")
    print()
    print("  Pages served:")
    print("    /           Dashboard with profile PII (name, email, phone, IPs, MAC)")
    print("    /status     Pipe-delimited JS variables (tagValueList, systemInfo)")
    print("    /settings   Form with passwords, SSIDs, CSRF token")
    print("    /logs       Event log with MACs, IPs, emails in entries")
    print("    /api/config JSON API with nested PII structures")
    print()
    print("Test with:")
    print(f"  har-capture get http://{args.host}:{args.port}")
    print(f"  har-capture get http://{args.host}:{args.port} -u {USERNAME} -p '{PASSWORD}'")
    print()
    print("Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
