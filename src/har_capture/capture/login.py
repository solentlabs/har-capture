"""Login strategies for ``har-capture get``: sign in to a device before the browser opens.

HTTP Basic Auth is answered by the browser itself (``http_credentials``). Many
devices instead sign in through a page: a form POST that answers with a
cookie, or a GET whose query carries the credentials and whose body is the
token the page script then stores as a cookie. A **login strategy** performs
that exchange and returns the session cookies, which the capture installs in
the browser context before the first navigation.

The seam is small:

* ``LoginStrategy`` — one method, ``login(transport, credentials)``, that
  returns session cookies. Implement it and ``register_login_strategy`` it to
  add a device family.
* ``LoginTransport`` — a cookie-keeping HTTP client bound to the device's base
  URL (self-signed certificates accepted, like the connectivity probes).
* ``FormCookieLogin`` and ``QueryTokenCookieLogin`` — the two built-ins.

Credentials come from the environment only (``HAR_CAPTURE_USERNAME`` and
``HAR_CAPTURE_PASSWORD``), never from the command line, and are held in a
``Credentials`` value whose ``repr`` shows nothing. The login runs outside the
browser, so neither the credentials nor the login request ever enter the
recorded HAR, and no error message carries a request URL, body or credential.
The cost is that the HAR does not show the login exchange itself; the session
cookie appears on the requests that follow.
"""

from __future__ import annotations

import base64
import http.cookiejar
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from har_capture.capture.probes import make_ssl_context

ENV_USERNAME = "HAR_CAPTURE_USERNAME"
ENV_PASSWORD = "HAR_CAPTURE_PASSWORD"  # noqa: S105  # pragma: allowlist secret - the variable name

# A token longer than this is a page, not a token.
MAX_TOKEN_BYTES = 4096

SessionCookie = dict[str, Any]


class LoginError(Exception):
    """A login that failed. The message never carries a credential, request URL query or body."""


@dataclass(frozen=True)
class Credentials:
    """A username and password, shown nowhere: not in ``repr``, ``str`` or a log line."""

    username: str = field(repr=False)
    password: str = field(repr=False)

    def __repr__(self) -> str:
        """Nothing of the credentials."""
        return "Credentials(<hidden>)"

    __str__ = __repr__

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Credentials:
        """Read the credentials from ``HAR_CAPTURE_USERNAME`` and ``HAR_CAPTURE_PASSWORD``.

        Raises:
            LoginError: When either variable is missing or empty (the message names the variables)
        """
        source = os.environ if env is None else env
        username, password = source.get(ENV_USERNAME, ""), source.get(ENV_PASSWORD, "")
        missing = [name for name, value in ((ENV_USERNAME, username), (ENV_PASSWORD, password)) if not value]
        if missing:
            raise LoginError(f"Set {' and '.join(missing)} in the environment to use a login strategy")
        return cls(username=username, password=password)

    def basic_token(self) -> str:
        """``base64("user:password")``, the token some devices take in a query."""
        return base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")


@dataclass(frozen=True)
class LoginResponse:
    """What a strategy sees of one response: its status and body."""

    status: int
    body: bytes


class LoginTransport:
    """A cookie-keeping HTTP client for one device, handed to a strategy.

    Redirects are followed and cookies kept across requests. Every failure is
    raised as ``LoginError`` naming the path only, so no query string (which
    can carry credentials) reaches a message.
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        if not base_url.lower().startswith(("http://", "https://")):
            raise LoginError("The login URL must start with http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._jar = http.cookiejar.CookieJar()
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPCookieProcessor(self._jar)]
        if self.base_url.startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=make_ssl_context()))
        self._opener = urllib.request.build_opener(*handlers)

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        form: Mapping[str, str] | None = None,
    ) -> LoginResponse:
        """Send one request.

        Args:
            method: ``GET`` or ``POST``
            path: Path on the device, with a leading ``/``
            query: Query parameters, percent-encoded here
            form: Form fields, sent urlencoded

        Raises:
            LoginError: On a connection failure or a non-2xx status
        """
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = urllib.parse.urlencode(form).encode("ascii") if form is not None else None
        request = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - scheme checked in __init__
        if data is not None:
            request.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return LoginResponse(status=response.status, body=response.read(MAX_TOKEN_BYTES * 16))
        except urllib.error.HTTPError as exc:
            exc.close()
            raise LoginError(f"{method} {path} answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise LoginError(f"{method} {path} failed: {type(reason).__name__}") from None

    def cookies(self) -> list[SessionCookie]:
        """The cookies the device has set, in the shape Playwright's storage state takes."""
        host = urllib.parse.urlsplit(self.base_url).hostname or ""
        return [
            session_cookie(c.name, c.value or "", host, c.path or "/", secure=c.secure) for c in self._jar
        ]


def session_cookie(
    name: str, value: str, host: str, path: str = "/", *, secure: bool = False
) -> SessionCookie:
    """A session cookie (no expiry) for ``host``, as Playwright's storage state spells it."""
    return {
        "name": name,
        "value": value,
        "domain": host,
        "path": path,
        "expires": -1,
        "httpOnly": False,
        "secure": secure,
        "sameSite": "Lax",
    }


class LoginStrategy(Protocol):
    """Signs in to a device and returns the session cookies the browser should start with."""

    def login(self, transport: LoginTransport, credentials: Credentials) -> list[SessionCookie]:
        """Perform the login.

        Raises:
            LoginError: When the device does not sign the session in
        """
        ...


class FormCookieLogin:
    """POST a login form; the cookies the device sets are the session.

    Options: ``path`` (required), ``user_field`` (default ``username``),
    ``pass_field`` (default ``password``), and ``field.NAME=VALUE`` for any
    constant extra form field.
    """

    def __init__(self, path: str, user_field: str, pass_field: str, extra: Mapping[str, str]) -> None:
        self.path, self.user_field, self.pass_field, self.extra = path, user_field, pass_field, dict(extra)

    def login(self, transport: LoginTransport, credentials: Credentials) -> list[SessionCookie]:
        """POST the form and return the cookies the device set."""
        form = {**self.extra, self.user_field: credentials.username, self.pass_field: credentials.password}
        transport.request("POST", self.path, form=form)
        cookies = transport.cookies()
        if not cookies:
            raise LoginError(f"POST {self.path} set no cookie; the device did not sign in")
        return cookies


class QueryTokenCookieLogin:
    """GET a URL whose query holds ``base64(user:password)``; the body is the token, stored as a cookie.

    Options: ``path`` (required), ``param`` (query parameter name, required),
    ``cookie`` (cookie name the token is stored under, required),
    ``cookie_path`` (default ``/``).
    """

    def __init__(self, path: str, param: str, cookie: str, cookie_path: str) -> None:
        self.path, self.param, self.cookie, self.cookie_path = path, param, cookie, cookie_path

    def login(self, transport: LoginTransport, credentials: Credentials) -> list[SessionCookie]:
        """GET the token and return it as the named cookie."""
        response = transport.request("GET", self.path, query={self.param: credentials.basic_token()})
        token = response.body.decode("utf-8", "replace").strip()
        if not token or len(response.body) > MAX_TOKEN_BYTES or any(ch.isspace() for ch in token):
            raise LoginError(f"GET {self.path} did not answer with a token")
        host = urllib.parse.urlsplit(transport.base_url).hostname or ""
        secure = transport.base_url.startswith("https://")
        return [session_cookie(self.cookie, token, host, self.cookie_path, secure=secure)]


StrategyFactory = Callable[[Mapping[str, str]], LoginStrategy]


def _take(
    options: Mapping[str, str],
    required: tuple[str, ...],
    optional: Mapping[str, str],
    *,
    prefixes: tuple[str, ...] = (),
) -> dict[str, str]:
    """Check a strategy's options: all required present, none unknown. Returns them with defaults filled."""
    unknown = [
        key for key in options if key not in required and key not in optional and not key.startswith(prefixes)
    ]
    if unknown:
        raise LoginError(f"Unknown login option(s): {', '.join(sorted(unknown))}")
    missing = [key for key in required if not options.get(key)]
    if missing:
        raise LoginError(f"Missing login option(s): {', '.join(missing)}")
    return {**optional, **options}


def _form_cookie(options: Mapping[str, str]) -> LoginStrategy:
    taken = _take(
        options, ("path",), {"user_field": "username", "pass_field": "password"}, prefixes=("field.",)
    )
    extra = {key[len("field.") :]: value for key, value in taken.items() if key.startswith("field.")}
    return FormCookieLogin(taken["path"], taken["user_field"], taken["pass_field"], extra)


def _query_token(options: Mapping[str, str]) -> LoginStrategy:
    taken = _take(options, ("path", "param", "cookie"), {"cookie_path": "/"})
    return QueryTokenCookieLogin(taken["path"], taken["param"], taken["cookie"], taken["cookie_path"])


_STRATEGIES: dict[str, StrategyFactory] = {
    "form-cookie": _form_cookie,
    "query-token-cookie": _query_token,
}


def register_login_strategy(name: str, factory: StrategyFactory) -> None:
    """Add a strategy under ``name`` (replacing one of that name). ``factory`` takes the ``--login-option`` map."""
    _STRATEGIES[name] = factory


def login_strategy_names() -> list[str]:
    """The registered strategy names, sorted."""
    return sorted(_STRATEGIES)


def parse_login_options(items: list[str] | None) -> dict[str, str]:
    """Turn repeated ``KEY=VALUE`` items into a map.

    Raises:
        LoginError: On an item with no ``=`` or an empty key
    """
    options: dict[str, str] = {}
    for item in items or []:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise LoginError("A login option must be written KEY=VALUE")
        options[key] = value
    return options


def create_login_strategy(name: str, options: Mapping[str, str]) -> LoginStrategy:
    """Build the named strategy from its options.

    Raises:
        LoginError: On an unknown strategy name or bad options
    """
    factory = _STRATEGIES.get(name)
    if factory is None:
        raise LoginError(
            f"Unknown login strategy {name!r}; choose one of: {', '.join(login_strategy_names())}"
        )
    return factory(options)


def perform_login(
    strategy: LoginStrategy, base_url: str, credentials: Credentials, *, timeout: float = 10.0
) -> list[SessionCookie]:
    """Run ``strategy`` against ``base_url`` and return the session cookies.

    Any error a strategy raises other than ``LoginError`` is reported as a
    ``LoginError`` naming only its type, so a third-party strategy cannot leak
    a request or credential through an exception message.
    """
    transport = LoginTransport(base_url, timeout=timeout)
    try:
        return strategy.login(transport, credentials)
    except LoginError:
        raise
    except Exception as exc:
        raise LoginError(f"Login strategy failed: {type(exc).__name__}") from None
