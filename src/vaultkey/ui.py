"""Local web UI: a small HTTP server bound to localhost, serving one page and a JSON API."""

import hmac
import json
import secrets
import threading
import time
import webbrowser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from . import generator
from .crypto import CryptoError
from .vault import Vault, VaultError

IDLE_LOCK_SECONDS = 300
COOKIE = "vaultkey_session"
MAX_BODY = 64 * 1024


class State:
    """Server-side session: the unlocked vault, auto-locked after idle time."""

    def __init__(self, path: Path, idle: int = IDLE_LOCK_SECONDS):
        self.path = path
        self.idle = idle
        self.token = secrets.token_urlsafe(32)   # one-time bootstrap token (in the URL)
        self.session = secrets.token_urlsafe(32)  # cookie value
        self.bootstrapped = False
        self.vault: Vault | None = None
        self.touched = time.monotonic()
        self.lock = threading.RLock()

    def current(self) -> Vault | None:
        with self.lock:
            if self.vault and time.monotonic() - self.touched > self.idle:
                self.vault = None
            if self.vault:
                self.touched = time.monotonic()
            return self.vault


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def make_handler(state: State, port_getter):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vaultkey"
        sys_version = ""

        def log_message(self, *args):  # keep request noise (and paths) out of the terminal
            pass

        # -- helpers --------------------------------------------------------

        def _host_ok(self) -> bool:
            # Defends against DNS rebinding: only accept our own loopback origin.
            port = port_getter()
            return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _authed(self) -> bool:
            jar = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = jar.get(COOKIE)
            return bool(morsel) and hmac.compare_digest(morsel.value, state.session)

        def _send(self, status, body: bytes, ctype: str, extra=()):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self' 'unsafe-inline'; "
                "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
            )
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, obj):
            self._send(status, json.dumps(obj).encode(), "application/json")

        # -- routing --------------------------------------------------------

        def do_GET(self):
            if not self._host_ok():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
            path, _, query = self.path.partition("?")
            if path == "/" and query.startswith("t="):
                given = query[2:]
                with state.lock:
                    ok = not state.bootstrapped and hmac.compare_digest(given, state.token)
                    if ok:
                        state.bootstrapped = True
                if not ok:
                    return self._json(HTTPStatus.FORBIDDEN, {"error": "invalid or used link"})
                cookie = f"{COOKIE}={state.session}; HttpOnly; SameSite=Strict; Path=/"
                return self._send(HTTPStatus.SEE_OTHER, b"", "text/plain",
                                  [("Location", "/"), ("Set-Cookie", cookie)])
            if path == "/" and self._authed():
                page = resources.files("vaultkey").joinpath("static/index.html").read_bytes()
                return self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
            if path == "/api/state" and self._authed():
                return self._json(HTTPStatus.OK, {
                    "exists": state.path.exists(), "unlocked": state.current() is not None,
                    "path": str(state.path),
                })
            self._json(HTTPStatus.FORBIDDEN, {"error": "open the link printed by 'vaultkey ui'"})

        def do_POST(self):
            if not self._host_ok() or not self._authed():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            if self.headers.get("X-Vaultkey") != "1":
                return self._json(HTTPStatus.FORBIDDEN, {"error": "missing header"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_BODY:
                    raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request too large")
                data = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(data, dict):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "expected a JSON object")
                result = self._dispatch(self.path, data)
                self._json(HTTPStatus.OK, result)
            except ApiError as exc:
                self._json(exc.status, {"error": str(exc)})
            except CryptoError as exc:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            except (VaultError, ValueError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def _dispatch(self, route: str, data: dict):
            def text(key, required=False):
                value = data.get(key, "")
                if not isinstance(value, str):
                    raise ApiError(HTTPStatus.BAD_REQUEST, f"{key} must be a string")
                if required and not value:
                    raise ApiError(HTTPStatus.BAD_REQUEST, f"{key} is required")
                return value

            def need_vault() -> Vault:
                vault = state.current()
                if vault is None:
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "vault is locked")
                return vault

            with state.lock:
                if route == "/api/init":
                    state.vault = Vault.create(state.path, text("password", True))
                    state.touched = time.monotonic()
                    return {}
                if route == "/api/unlock":
                    state.vault = Vault.open(state.path, text("password", True))
                    state.touched = time.monotonic()
                    return {}
                if route == "/api/lock":
                    state.vault = None
                    return {}
                if route == "/api/generate":
                    length = data.get("length", 20)
                    if not isinstance(length, int) or isinstance(length, bool) or length > 256:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid length")
                    return {"password": generator.generate(
                        length, symbols=bool(data.get("symbols", True)),
                        ambiguous=not data.get("noAmbiguous", False))}
                vault = need_vault()
                if route == "/api/entries":
                    return {"entries": vault.list()}
                if route == "/api/get":
                    return {"entry": vault.get(text("name", True))}
                if route == "/api/add":
                    vault.add(text("name", True), text("password", True),
                              username=text("username"), url=text("url"), notes=text("notes"),
                              overwrite=bool(data.get("overwrite", False)))
                    return {}
                if route == "/api/remove":
                    vault.remove(text("name", True))
                    return {}
                if route == "/api/passwd":
                    vault.change_master(text("password", True))
                    return {}
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown route")

    return Handler


def serve(path: Path, port: int = 0, open_browser: bool = True, idle: int = IDLE_LOCK_SECONDS) -> int:
    state = State(path, idle)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), None)
    httpd.RequestHandlerClass = make_handler(state, lambda: httpd.server_address[1])
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?t={state.token}"
    print(f"vaultkey UI running for {path}")
    print(f"Open this one-time link: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        httpd.server_close()
    return 0
