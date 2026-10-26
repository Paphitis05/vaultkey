import getpass

import pytest

from vaultkey import cli, vault as vault_mod
from vaultkey.vault import Vault

from conftest import CHEAP_KDF, MASTER


@pytest.fixture(autouse=True)
def cheap_kdf(monkeypatch):
    monkeypatch.setattr(vault_mod.crypto, "DEFAULT_KDF", CHEAP_KDF)


def feed(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(it))


def test_full_flow(monkeypatch, path, capsys):
    v = ["--vault", str(path)]
    feed(monkeypatch, MASTER, MASTER)
    assert cli.main(v + ["init"]) == 0
    feed(monkeypatch, MASTER, "entry-pw-123")
    assert cli.main(v + ["add", "site", "--username", "me"]) == 0
    feed(monkeypatch, MASTER)
    capsys.readouterr()
    assert cli.main(v + ["get", "site"]) == 0
    out = capsys.readouterr().out
    assert "entry-pw-123" not in out and "me" in out
    feed(monkeypatch, MASTER)
    cli.main(v + ["get", "site", "--show"])
    assert "entry-pw-123" in capsys.readouterr().out
    feed(monkeypatch, MASTER)
    cli.main(v + ["list"])
    assert capsys.readouterr().out.strip() == "site"
    feed(monkeypatch, MASTER)
    assert cli.main(v + ["rm", "site"]) == 0


def test_env_var_path(monkeypatch, path):
    monkeypatch.setenv("VAULTKEY_PATH", str(path))
    feed(monkeypatch, MASTER, MASTER)
    assert cli.main(["init"]) == 0
    assert path.exists()


def test_init_refuses_existing(monkeypatch, path, vault, capsys):
    feed(monkeypatch, MASTER, MASTER)
    assert cli.main(["--vault", str(path), "init"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_wrong_password_exit_code(monkeypatch, path, vault, capsys):
    feed(monkeypatch, "wrong wrong wrong")
    assert cli.main(["--vault", str(path), "list"]) == 1
    assert "error:" in capsys.readouterr().err


def test_short_master_rejected(monkeypatch, path, capsys):
    feed(monkeypatch, "short", "short")
    assert cli.main(["--vault", str(path), "init"]) == 1
    assert not path.exists()


def test_add_generate(monkeypatch, path, vault):
    feed(monkeypatch, MASTER)
    assert cli.main(["--vault", str(path), "add", "gen", "--generate", "--length", "24"]) == 0
    assert len(Vault.open(path, MASTER).get("gen")["password"]) == 24


def test_add_duplicate_needs_overwrite(monkeypatch, path, vault, capsys):
    vault.add("dup", "one")
    feed(monkeypatch, MASTER, "two-pw")
    assert cli.main(["--vault", str(path), "add", "dup"]) == 1
    feed(monkeypatch, MASTER, "two-pw")
    assert cli.main(["--vault", str(path), "add", "dup", "--overwrite"]) == 0


def test_passwd(monkeypatch, path, vault):
    new = "another long master"
    feed(monkeypatch, MASTER, new, new)
    assert cli.main(["--vault", str(path), "passwd"]) == 0
    Vault.open(path, new)


def test_gen(capsys):
    assert cli.main(["gen", "--length", "12", "--no-symbols"]) == 0
    assert len(capsys.readouterr().out.strip()) == 12
