import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from vaultkey import ui, vault as vault_mod

from conftest import CHEAP_KDF, MASTER


@pytest.fixture
def server(path, monkeypatch):
    monkeypatch.setattr(vault_mod.crypto, "DEFAULT_KDF", CHEAP_KDF)
    state = ui.State(path)
    httpd = ui.ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = ui.make_handler(state, lambda: port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield state, port
    httpd.shutdown()
    httpd.server_close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(port, route, body=None, cookie=None, headers=None, host=None):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = f"{ui.COOKIE}={cookie}"
    if host:
        h["Host"] = host
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("X-Vaultkey", "1")
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{route}", data=data, headers=h)
    try:
        with urllib.request.build_opener(NoRedirect).open(req) as r:
            return r.status, json.loads(r.read() or b"{}") if r.headers.get_content_type() == "application/json" else r.read(), r
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else {}, e


def login(state, port):
    status, _, resp = call(port, f"/?t={state.token}")
    assert status == 303
    assert "HttpOnly" in resp.headers["Set-Cookie"]
    return state.session


def test_requires_token_and_cookie(server):
    state, port = server
    assert call(port, "/")[0] == 403
    assert call(port, "/api/state")[0] == 403
    assert call(port, "/?t=wrong")[0] == 403
    assert call(port, "/api/unlock", {"password": MASTER})[0] == 403


def test_token_is_single_use(server):
    state, port = server
    login(state, port)
    assert call(port, f"/?t={state.token}")[0] == 403


def test_rejects_foreign_host(server):
    state, port = server
    cookie = login(state, port)
    assert call(port, "/api/state", cookie=cookie, host="evil.example")[0] == 403


def test_post_needs_custom_header(server):
    state, port = server
    cookie = login(state, port)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/init", data=b"{}", method="POST",
        headers={"Cookie": f"{ui.COOKIE}={cookie}", "Content-Type": "text/plain"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 403


def test_full_flow(server, path):
    state, port = server
    cookie = login(state, port)
    page = call(port, "/", cookie=cookie)
    assert page[0] == 200 and b"vaultkey" in page[1]
    assert call(port, "/api/state", cookie=cookie)[1] == {
        "exists": False, "unlocked": False, "path": str(path)}
    assert call(port, "/api/init", {"password": "short"}, cookie)[0] == 400
    assert call(port, "/api/init", {"password": MASTER}, cookie)[0] == 200
    assert call(port, "/api/add", {"name": "a", "password": "pw1", "username": "u"}, cookie)[0] == 200
    assert call(port, "/api/add", {"name": "a", "password": "pw2"}, cookie)[0] == 400
    assert call(port, "/api/add", {"name": "a", "password": "pw2", "overwrite": True}, cookie)[0] == 200
    assert call(port, "/api/entries", {}, cookie)[1] == {"entries": ["a"]}
    assert call(port, "/api/get", {"name": "a"}, cookie)[1]["entry"]["password"] == "pw2"
    assert call(port, "/api/lock", {}, cookie)[0] == 200
    assert call(port, "/api/entries", {}, cookie)[0] == 401
    assert call(port, "/api/unlock", {"password": "wrong wrong wrong"}, cookie)[0] == 401
    assert call(port, "/api/unlock", {"password": MASTER}, cookie)[0] == 200
    assert call(port, "/api/passwd", {"password": "a different long pw"}, cookie)[0] == 200
    assert call(port, "/api/remove", {"name": "a"}, cookie)[0] == 200
    assert call(port, "/api/get", {"name": "a"}, cookie)[0] == 400


def test_generate(server):
    state, port = server
    cookie = login(state, port)
    status, body, _ = call(port, "/api/generate", {"length": 30, "symbols": False}, cookie)
    assert status == 200 and len(body["password"]) == 30
    assert call(port, "/api/generate", {"length": 99999}, cookie)[0] == 400


def test_idle_autolock(server):
    state, port = server
    state.idle = 0.05
    cookie = login(state, port)
    call(port, "/api/init", {"password": MASTER}, cookie)
    time.sleep(0.1)
    assert call(port, "/api/entries", {}, cookie)[0] == 401
