"""Secure password generator."""

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o")
MIN_LENGTH = 8


def generate(length: int = 20, symbols: bool = True, ambiguous: bool = True) -> str:
    """Return a random password with at least one character from each class.

    symbols=False drops the symbol class; ambiguous=False drops look-alike
    characters such as I, l, 1, O, 0 and o.
    """
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append(SYMBOLS)
    if not ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]

    if length < max(MIN_LENGTH, len(classes)):
        raise ValueError(f"length must be at least {max(MIN_LENGTH, len(classes))}")

    pool = "".join(classes)
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
