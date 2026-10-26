"""Key derivation and authenticated encryption."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

DEFAULT_KDF = {"n": 2**15, "r": 8, "p": 1}


class CryptoError(Exception):
    """Raised when decryption fails."""


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt with a fresh random nonce. Returns (nonce, ciphertext)."""
    nonce = os.urandom(NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise CryptoError(
            "Decryption failed: wrong master password or the vault file was tampered with."
        ) from None
