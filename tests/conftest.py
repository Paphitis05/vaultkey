import pytest

CHEAP_KDF = {"n": 2**4, "r": 1, "p": 1}
MASTER = "correct horse battery"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "vault.json"


@pytest.fixture
def vault(path):
    from vaultkey.vault import Vault

    return Vault.create(path, MASTER, kdf=CHEAP_KDF)
