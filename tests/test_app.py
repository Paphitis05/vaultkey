from pathlib import Path

from vaultkey import app


def test_default_path(monkeypatch):
    monkeypatch.delenv("VAULTKEY_PATH", raising=False)
    assert app.vault_path(None) == Path.home() / ".vaultkey" / "vault.json"


def test_env_var_path(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULTKEY_PATH", str(tmp_path / "v.json"))
    assert app.vault_path(None) == tmp_path / "v.json"


def test_flag_beats_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULTKEY_PATH", str(tmp_path / "env.json"))
    assert app.vault_path(str(tmp_path / "flag.json")) == tmp_path / "flag.json"


def test_main_starts_server(monkeypatch, tmp_path):
    calls = {}
    monkeypatch.setattr(app.ui, "serve", lambda p, port, open_browser: calls.update(
        p=p, port=port, open=open_browser) or 0)
    assert app.main(["--vault", str(tmp_path / "v.json"), "--port", "9", "--no-browser"]) == 0
    assert calls == {"p": tmp_path / "v.json", "port": 9, "open": False}
