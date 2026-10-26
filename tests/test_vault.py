import json
import os
import stat

import pytest

from vaultkey.crypto import CryptoError
from vaultkey.vault import (
    EntryExistsError, EntryNotFoundError, Vault, VaultError, VaultExistsError,
    VaultNotFoundError,
)

from conftest import CHEAP_KDF, MASTER


def test_roundtrip(vault, path):
    vault.add("github", "s3cret-pw", username="kp", url="https://github.com", notes="n")
    again = Vault.open(path, MASTER)
    assert again.get("github") == {
        "username": "kp", "password": "s3cret-pw", "url": "https://github.com", "notes": "n",
    }
    assert again.list() == ["github"]


def test_wrong_password(vault, path):
    with pytest.raises(CryptoError, match="wrong master password"):
        Vault.open(path, "not the right password")


def test_no_plaintext_on_disk(vault, path):
    vault.add("my-bank-login", "hunter2-hunter2", username="alice-the-user")
    raw = path.read_bytes()
    for secret in (b"my-bank-login", b"hunter2-hunter2", b"alice-the-user", b"entries"):
        assert secret not in raw
    doc = json.loads(raw)
    assert set(doc) == {"version", "kdf", "salt", "nonce", "ciphertext"}


def test_file_permissions(vault, path):
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    vault.add("a", "b")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert [p.name for p in path.parent.iterdir()] == [path.name]


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "salt"])
def test_tamper_detection(vault, path, field):
    import base64

    vault.add("a", "b")
    doc = json.loads(path.read_text())
    blob = bytearray(base64.b64decode(doc[field]))
    blob[0] ^= 1
    doc[field] = base64.b64encode(bytes(blob)).decode()
    path.write_text(json.dumps(doc))
    with pytest.raises(CryptoError):
        Vault.open(path, MASTER)


def test_tamper_kdf_params(vault, path):
    vault.add("a", "b")
    doc = json.loads(path.read_text())
    doc["kdf"]["n"] = 2**5
    path.write_text(json.dumps(doc))
    with pytest.raises(CryptoError):
        Vault.open(path, MASTER)


def test_garbage_file(path):
    path.write_text("not json")
    with pytest.raises(VaultError):
        Vault.open(path, MASTER)


def test_nonce_changes_on_every_save(vault, path):
    vault.add("a", "1")
    first = json.loads(path.read_text())["nonce"]
    vault.add("b", "2")
    assert json.loads(path.read_text())["nonce"] != first


def test_duplicate_add_refused_then_overwrite(vault):
    vault.add("x", "one")
    with pytest.raises(EntryExistsError):
        vault.add("x", "two")
    assert vault.get("x")["password"] == "one"
    vault.add("x", "two", overwrite=True)
    assert vault.get("x")["password"] == "two"


def test_remove(vault, path):
    vault.add("x", "one")
    vault.remove("x")
    assert Vault.open(path, MASTER).list() == []
    with pytest.raises(EntryNotFoundError):
        vault.remove("x")
    with pytest.raises(EntryNotFoundError):
        vault.get("x")


def test_list_sorted(vault):
    for name in ("b", "c", "a"):
        vault.add(name, "p")
    assert vault.list() == ["a", "b", "c"]


def test_create_refuses_overwrite(vault, path):
    with pytest.raises(VaultExistsError):
        Vault.create(path, MASTER, kdf=CHEAP_KDF)


def test_open_missing(tmp_path):
    with pytest.raises(VaultNotFoundError):
        Vault.open(tmp_path / "nope.json", MASTER)


def test_short_master_rejected(path):
    with pytest.raises(VaultError, match="at least 12"):
        Vault.create(path, "short", kdf=CHEAP_KDF)
    assert not path.exists()


def test_change_master(vault, path):
    vault.add("x", "one")
    old_salt = json.loads(path.read_text())["salt"]
    vault.change_master("a brand new master pw")
    assert json.loads(path.read_text())["salt"] != old_salt
    with pytest.raises(CryptoError):
        Vault.open(path, MASTER)
    assert Vault.open(path, "a brand new master pw").get("x")["password"] == "one"


def test_change_master_short_rejected(vault, path):
    with pytest.raises(VaultError):
        vault.change_master("short")
    assert Vault.open(path, MASTER).list() == []
