# vaultkey

A small, local, encrypted password manager app with a graphical interface.

> **Limitations:** vaultkey is an unaudited learning project. It has not been
> reviewed by security professionals. Do not rely on it to protect secrets you
> cannot afford to lose; use a mature, audited password manager instead.

## Features

- Single encrypted vault file; entry names and all fields are encrypted
- scrypt key derivation and AES-256-GCM authenticated encryption
- Wrong passwords and tampered files are detected and reported clearly
- Atomic writes with `0600` file permissions
- Built-in secure password generator
- Graphical app that runs locally in your browser; nothing leaves your machine
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
vaultkey
```

This starts the app on `127.0.0.1` and opens it in your browser. On first run
you create a vault with a master password of at least 12 characters; after
that you unlock it. In the app you can:

- search, add, edit and delete entries (name, username, URL, password, notes)
- generate passwords (length, symbols, no look-alike characters)
- show or copy a password (the clipboard is cleared after 20 seconds if it
  still holds that password)
- change the master password, or lock the vault

Options: `--vault PATH`, `--port N`, `--no-browser` (only print the link). The
vault location is chosen in this order: `--vault`, the `VAULTKEY_PATH`
environment variable, then `~/.vaultkey/vault.json`.

The server only listens on `127.0.0.1`, requires a one-time link, rejects
foreign `Host` headers and cross-site requests, locks itself after 5 minutes of
inactivity, and the page loads nothing from the internet.

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
- No sync or backup; losing the master password means
  losing the vault.
- Anyone who obtains the vault file can attempt offline guesses of the master
  password; choose a strong one.

## License

MIT, see [LICENSE](LICENSE).
