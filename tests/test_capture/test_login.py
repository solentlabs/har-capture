"""Tests for login strategies: the seam, the two built-ins, and their use from ``get``."""

from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from har_capture.capture.login import (
    Credentials,
    FormCookieLogin,
    LoginError,
    LoginTransport,
    create_login_strategy,
    login_strategy_names,
    parse_login_options,
    perform_login,
    register_login_strategy,
    session_cookie,
)
from har_capture.cli.capture import _prepare_login, _run_login
from har_capture.cli.main import app

_FIXTURE = json.loads((Path(__file__).parent.parent / "fixtures" / "test_login.json").read_text("utf-8"))
OPTION_CASES = _FIXTURE["strategy_option_cases"]
CLI_CASES = _FIXTURE["cli_error_cases"]

USER, PASSWORD, TOKEN = "device-admin", "pw-for-tests-only", "tok-0123456789abcdef"
CREDS = Credentials(USER, PASSWORD)


class _Handler(BaseHTTPRequestHandler):
    """A made-up device: a form login that sets a cookie, a token endpoint, and misbehaving ones."""

    seen: list[str] = []

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        self.seen.append(f"POST {self.path} {sorted(form)}")
        if (
            self.path == "/login.cgi"
            and form.get("username") == [USER]
            and form.get("password") == [PASSWORD]
        ):
            self._send(302, headers={"Set-Cookie": "sid=abc123; Path=/", "Location": "/home"})
        elif self.path == "/nocookie":
            self._send(200, b"ok")
        else:
            self._send(403, b"denied")

    def do_GET(self) -> None:
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)
        self.seen.append(f"GET {parts.path} {sorted(query)}")
        expected = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if parts.path == "/home":
            self._send(200, b"home")
        elif parts.path == "/token" and query.get("auth") == [expected]:
            self._send(200, f"{TOKEN}\n".encode())
        elif parts.path == "/empty":
            self._send(200, b"")
        elif parts.path == "/page":
            self._send(200, b"<html> not a token </html>")
        elif parts.path == "/huge":
            self._send(200, b"a" * 5000)
        else:
            self._send(401, b"nope")


@pytest.fixture
def device() -> Iterator[str]:
    _Handler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("case", OPTION_CASES, ids=[c["id"] for c in OPTION_CASES])
def test_strategy_options(case: dict) -> None:
    if case["error"] is None:
        assert create_login_strategy(case["strategy"], parse_login_options(case["options"])) is not None
    else:
        with pytest.raises(LoginError, match=case["error"].replace("(", r"\(").replace(")", r"\)")):
            create_login_strategy(case["strategy"], parse_login_options(case["options"]))


def test_form_cookie_signs_in(device: str) -> None:
    strategy = create_login_strategy("form-cookie", {"path": "/login.cgi"})
    cookies = perform_login(strategy, device, CREDS)
    assert [(c["name"], c["value"], c["domain"], c["path"]) for c in cookies] == [
        ("sid", "abc123", "127.0.0.1", "/")
    ]
    assert cookies[0]["expires"] == -1 and cookies[0]["secure"] is False


def test_form_cookie_custom_field_names_and_extras(device: str) -> None:
    strategy = create_login_strategy(
        "form-cookie", {"path": "/login.cgi", "user_field": "u", "pass_field": "p", "field.act": "go"}
    )
    with pytest.raises(LoginError, match="HTTP 403"):
        perform_login(strategy, device, CREDS)
    assert _Handler.seen == ["POST /login.cgi ['act', 'p', 'u']"]


def test_form_cookie_without_cookie_is_a_failed_login(device: str) -> None:
    with pytest.raises(LoginError, match="set no cookie"):
        perform_login(create_login_strategy("form-cookie", {"path": "/nocookie"}), device, CREDS)


def test_form_cookie_wrong_credentials(device: str) -> None:
    with pytest.raises(LoginError, match="HTTP 403"):
        perform_login(
            create_login_strategy("form-cookie", {"path": "/login.cgi"}), device, Credentials("x", "y")
        )


def test_query_token_cookie_signs_in(device: str) -> None:
    strategy = create_login_strategy(
        "query-token-cookie", {"path": "/token", "param": "auth", "cookie": "session", "cookie_path": "/app"}
    )
    cookies = perform_login(strategy, device, CREDS)
    assert [(c["name"], c["value"], c["path"]) for c in cookies] == [("session", TOKEN, "/app")]


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("/empty", "did not answer with a token"),
        ("/page", "did not answer with a token"),
        ("/huge", "did not answer with a token"),
        ("/missing", "HTTP 401"),
    ],
)
def test_query_token_cookie_rejects_non_tokens(device: str, path: str, message: str) -> None:
    strategy = create_login_strategy(
        "query-token-cookie", {"path": path, "param": "auth", "cookie": "session"}
    )
    with pytest.raises(LoginError, match=message):
        perform_login(strategy, device, CREDS)


def test_secure_flag_follows_scheme() -> None:
    assert session_cookie("a", "b", "h", secure=True)["secure"] is True


def test_secrets_never_reach_messages_or_repr(device: str) -> None:
    """No error text, repr or str carries a credential, the base64 token or a query string."""
    strategy = create_login_strategy(
        "query-token-cookie", {"path": "/missing", "param": "auth", "cookie": "s"}
    )
    with pytest.raises(LoginError) as raised:
        perform_login(strategy, device, CREDS)
    unreachable = LoginTransport("http://127.0.0.1:1")
    with pytest.raises(LoginError) as refused:
        unreachable.request("GET", "/token", query={"auth": CREDS.basic_token()})
    for text in (str(raised.value), str(refused.value), repr(CREDS), str(CREDS)):
        for secret in (USER, PASSWORD, CREDS.basic_token(), "auth="):
            assert secret not in text
    assert "ConnectionRefusedError" in str(refused.value)


def test_foreign_exception_is_reported_by_type_only(device: str) -> None:
    class Leaky:
        def login(self, transport: LoginTransport, credentials: Credentials) -> list[dict[str, Any]]:
            raise RuntimeError(f"bad {credentials.password}")

    with pytest.raises(LoginError) as raised:
        perform_login(Leaky(), device, CREDS)
    assert str(raised.value) == "Login strategy failed: RuntimeError"
    assert PASSWORD not in str(raised.value)


def test_register_custom_strategy(device: str) -> None:
    class Fixed:
        def login(self, transport: LoginTransport, credentials: Credentials) -> list[dict[str, Any]]:
            transport.request("GET", "/home")
            return [session_cookie("k", "v", "127.0.0.1")]

    register_login_strategy("fixed-test", lambda options: Fixed())
    try:
        assert "fixed-test" in login_strategy_names()
        cookies = perform_login(create_login_strategy("fixed-test", {}), device, CREDS)
        assert cookies[0]["name"] == "k"
    finally:
        from har_capture.capture import login

        login._STRATEGIES.pop("fixed-test")


def test_transport_rejects_other_schemes() -> None:
    with pytest.raises(LoginError, match="http:// or https://"):
        LoginTransport("file:///etc/passwd")


def test_credentials_from_env() -> None:
    creds = Credentials.from_env({"HAR_CAPTURE_USERNAME": "a", "HAR_CAPTURE_PASSWORD": "b"})
    assert (creds.username, creds.password) == ("a", "b")
    assert creds.basic_token() == base64.b64encode(b"a:b").decode()


def test_credentials_from_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HAR_CAPTURE_USERNAME", "a")
    monkeypatch.setenv("HAR_CAPTURE_PASSWORD", "b")
    assert Credentials.from_env().username == "a"


@pytest.mark.parametrize("case", CLI_CASES, ids=[c["id"] for c in CLI_CASES])
def test_get_rejects_bad_login_setup_before_anything_else(
    case: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HAR_CAPTURE_USERNAME", "HAR_CAPTURE_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    for name, value in case["env"].items():
        monkeypatch.setenv(name, value)
    result = CliRunner().invoke(
        app, ["get", "http://192.0.2.1", "--patterns", "network-device", *case["argv"]]
    )
    assert result.exit_code == 1
    assert case["message"] in result.output
    assert "Checking connectivity" not in result.output and "HAR CAPTURE" not in result.output


def test_run_login_installs_cookies(device: str, capsys: pytest.CaptureFixture[str]) -> None:
    strategy = create_login_strategy("form-cookie", {"path": "/login.cgi"})
    cookies = _run_login((strategy, CREDS), device, None, "form-cookie")
    out = capsys.readouterr().out
    assert cookies is not None and cookies[0]["name"] == "sid"
    assert "Signed in: 1 session cookie(s) installed" in out
    assert PASSWORD not in out and USER not in out


def test_run_login_uses_detected_url_over_target(device: str) -> None:
    strategy = create_login_strategy("form-cookie", {"path": "/login.cgi"})
    assert _run_login((strategy, CREDS), "192.0.2.1", device, "form-cookie") is not None


def test_run_login_without_strategy_is_a_noop() -> None:
    assert _run_login(None, "192.0.2.1", None, None) is None


def test_run_login_needs_a_scheme() -> None:
    import typer

    strategy = create_login_strategy("form-cookie", {"path": "/login.cgi"})
    with pytest.raises(typer.Exit):
        _run_login((strategy, CREDS), "192.0.2.1", None, "form-cookie")


def test_run_login_failure_exits(device: str, capsys: pytest.CaptureFixture[str]) -> None:
    import typer

    strategy = create_login_strategy("form-cookie", {"path": "/login.cgi"})
    with pytest.raises(typer.Exit):
        _run_login((strategy, Credentials("x", "y")), device, None, "form-cookie")
    assert "HTTP 403" in capsys.readouterr().err


def test_https_transport_installs_a_handler_and_reports_refusal_by_type() -> None:
    transport = LoginTransport("https://127.0.0.1:1")
    with pytest.raises(LoginError, match="GET /x failed: ConnectionRefusedError"):
        transport.request("GET", "/x")


def test_prepare_login_without_strategy_is_a_noop() -> None:
    assert _prepare_login(None, None, None, None) is None


def test_prepare_login_builds_strategy_and_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HAR_CAPTURE_USERNAME", USER)
    monkeypatch.setenv("HAR_CAPTURE_PASSWORD", PASSWORD)
    prepared = _prepare_login("form-cookie", ["path=/login.cgi"], None, None)
    assert prepared is not None
    strategy, credentials = prepared
    assert isinstance(strategy, FormCookieLogin)
    assert (credentials.username, credentials.password) == (USER, PASSWORD)
