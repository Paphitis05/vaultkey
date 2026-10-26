"""Encrypted vault file: one JSON document, everything sensitive in the ciphertext."""

import json
import os
import base64
import tempfile
from pathlib import Path

from . import crypto

VERSION = 1
MIN_MASTER_LEN = 12


class VaultError(Exception):
    """Base error for vault operations."""


class VaultExistsError(VaultError):
    pass


class VaultNotFoundError(VaultError):
    pass


class EntryExistsError(VaultError):
    pass


class EntryNotFoundError(VaultError):
    pass


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def check_master(password: str) -> None:
    if len(password) < MIN_MASTER_LEN:
        raise VaultError(f"Master password must be at least {MIN_MASTER_LEN} characters.")


class Vault:
    def __init__(self, path, key, kdf, salt, entries):
        self.path = Path(path)
        self._key = key
        self._kdf = dict(kdf)
        self._salt = salt
        self._entries = entries

    # -- construction -----------------------------------------------------

    @classmethod
    def create(cls, path, master: str, kdf: dict | None = None) -> "Vault":
        path = Path(path)
        check_master(master)
        if path.exists():
            raise VaultExistsError(f"Vault already exists: {path}")
        kdf = dict(kdf or crypto.DEFAULT_KDF)
        salt = crypto.new_salt()
        key = crypto.derive_key(master, salt, **kdf)
        vault = cls(path, key, kdf, salt, {})
        vault._save()
        return vault

    @classmethod
    def open(cls, path, master: str) -> "Vault":
        path = Path(path)
        if not path.exists():
            raise VaultNotFoundError(f"No vault at {path}. Run 'vaultkey init' first.")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            kdf = {k: int(doc["kdf"][k]) for k in ("n", "r", "p")}
            salt = _b64d(doc["salt"])
            nonce = _b64d(doc["nonce"])
            ciphertext = _b64d(doc["ciphertext"])
            version = doc["version"]
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultError(f"Vault file is corrupt or not a vaultkey vault: {exc}") from None
        if version != VERSION:
            raise VaultError(f"Unsupported vault version: {version}")
        if len(salt) != crypto.SALT_LEN or len(nonce) != crypto.NONCE_LEN:
            raise VaultError("Vault file is corrupt: bad salt or nonce length.")
        if not (kdf["n"] > 1 and kdf["n"] & (kdf["n"] - 1) == 0 and kdf["n"] <= 2**20):
            raise VaultError("Vault file is corrupt: invalid KDF parameters.")
        if not (1 <= kdf["r"] <= 32 and 1 <= kdf["p"] <= 16):
            raise VaultError("Vault file is corrupt: invalid KDF parameters.")

        key = crypto.derive_key(master, salt, **kdf)
        plaintext = crypto.decrypt(key, nonce, ciphertext, _aad(version, kdf, salt))
        try:
            entries = json.loads(plaintext.decode("utf-8"))["entries"]
        except (ValueError, KeyError) as exc:
            raise VaultError(f"Vault contents are corrupt: {exc}") from None
        return cls(path, key, kdf, salt, entries)

    # -- operations -------------------------------------------------------

    def add(self, name: str, password: str, username: str = "", url: str = "",
            notes: str = "", overwrite: bool = False) -> None:
        if not name:
            raise VaultError("Entry name must not be empty.")
        if name in self._entries and not overwrite:
            raise EntryExistsError(f"Entry already exists: {name} (use overwrite to replace).")
        self._entries[name] = {
            "username": username, "password": password, "url": url, "notes": notes,
        }
        self._save()

    def get(self, name: str) -> dict:
        try:
            return dict(self._entries[name])
        except KeyError:
            raise EntryNotFoundError(f"No such entry: {name}") from None

    def remove(self, name: str) -> None:
        if name not in self._entries:
            raise EntryNotFoundError(f"No such entry: {name}")
        del self._entries[name]
        self._save()

    def list(self) -> list[str]:
        return sorted(self._entries)

    def change_master(self, new_master: str) -> None:
        check_master(new_master)
        salt = crypto.new_salt()
        self._key = crypto.derive_key(new_master, salt, **self._kdf)
        self._salt = salt
        self._save()

    # -- persistence ------------------------------------------------------

    def _save(self) -> None:
        plaintext = json.dumps({"entries": self._entries}).encode("utf-8")
        nonce, ciphertext = crypto.encrypt(
            self._key, plaintext, _aad(VERSION, self._kdf, self._salt)
        )
        doc = {
            "version": VERSION,
            "kdf": {"name": "scrypt", **self._kdf},
            "salt": _b64e(self._salt),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vaultkey-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _aad(version: int, kdf: dict, salt: bytes) -> bytes:
    """Bind the header to the ciphertext so tampering with it is detected."""
    return json.dumps(
        {"version": version, "kdf": {k: kdf[k] for k in ("n", "r", "p")}, "salt": _b64e(salt)},
        sort_keys=True,
    ).encode("utf-8")
