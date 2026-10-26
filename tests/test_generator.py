import string

import pytest

from vaultkey.generator import AMBIGUOUS, SYMBOLS, generate


def test_length():
    for n in (8, 20, 64):
        assert len(generate(n)) == n


def test_every_class_present():
    for _ in range(200):
        pw = generate(8)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_no_symbols():
    for _ in range(100):
        pw = generate(16, symbols=False)
        assert not any(c in SYMBOLS for c in pw)
        assert any(c.isdigit() for c in pw)


def test_no_ambiguous():
    for _ in range(100):
        pw = generate(16, ambiguous=False)
        assert not set(pw) & AMBIGUOUS
        assert any(c.isdigit() for c in pw)
        assert any(c.isupper() for c in pw)


def test_too_short():
    with pytest.raises(ValueError):
        generate(4)


def test_not_constant():
    assert len({generate(20) for _ in range(50)}) == 50
