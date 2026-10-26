# vaultkey

A small, local, encrypted password manager for the command line.

> **Limitations:** vaultkey is an unaudited learning project. It has not been
> reviewed by security professionals. Do not rely on it to protect secrets you
> cannot afford to lose; use a mature, audited password manager instead.

## Features

- Single encrypted vault file; entry names and all fields are encrypted
- scrypt key derivation and AES-256-GCM authenticated encryption
- Wrong passwords and tampered files are detected and reported clearly
- Atomic writes with `0600` file permissions
- Built-in secure password generator
- No network access, no daemon, no telemetry

## Install

Requires Python 3.10+.

```sh
git clone https://github.com/Paphitis05/vaultkey.git
cd vaultkey
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

For development: `pip install -e '.[test]' && pytest`.

## Usage

```sh
vaultkey init                         # create a vault (master password >= 12 chars)
vaultkey add github --username me     # prompts for the entry password
vaultkey add bank --generate --length 24 --no-symbols
vaultkey add github --overwrite       # replace an existing entry
vaultkey get github                   # password hidden
vaultkey get github --show            # reveal the password
vaultkey list
vaultkey rm github
vaultkey passwd                       # change the master password
vaultkey gen --length 32 --no-ambiguous
```

The vault location is chosen in this order: `--vault PATH`, the
`VAULTKEY_PATH` environment variable, then `~/.vaultkey/vault.json`.

`add` accepts `--username`, `--url` and `--notes`. `gen` and `add --generate`
accept `--length`, `--no-symbols` and `--no-ambiguous`.

## How it works

The vault is one JSON file containing a format version, the scrypt parameters
(N=2^15, r=8, p=1), a random 16-byte salt, a 12-byte nonce and the ciphertext.

1. A 256-bit key is derived from the master password with scrypt and the salt.
2. The entries are serialised to JSON and encrypted with AES-256-GCM using a
   fresh random nonce on every save.
3. The version, KDF parameters and salt are bound to the ciphertext as
   associated data, so modifying them is detected.
4. The file is written to a temporary file in the same directory, set to
   `0600`, then renamed over the vault.

Changing the master password generates a new salt and re-encrypts the vault.

## Limitations

- Unaudited; see the note at the top.
- Secrets live in Python strings and cannot be reliably wiped from memory.
- No clipboard integration, sync, or backup; losing the master password means
  losing the vault.
- Anyone who obtains the vault file can attempt offline guesses of the master
  password; choose a strong one.

## License

MIT, see [LICENSE](LICENSE).
