"""Command line interface."""

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import generator
from .crypto import CryptoError
from .vault import MIN_MASTER_LEN, Vault, VaultError

DEFAULT_PATH = Path.home() / ".vaultkey" / "vault.json"


def vault_path(arg: str | None) -> Path:
    return Path(arg or os.environ.get("VAULTKEY_PATH") or DEFAULT_PATH).expanduser()


def _open(args) -> Vault:
    return Vault.open(vault_path(args.vault), getpass.getpass("Master password: "))


def cmd_init(args) -> int:
    path = vault_path(args.vault)
    if path.exists():
        raise VaultError(f"Vault already exists: {path}")
    master = getpass.getpass(f"New master password (min {MIN_MASTER_LEN} chars): ")
    if master != getpass.getpass("Repeat master password: "):
        raise VaultError("Passwords do not match.")
    Vault.create(path, master)
    print(f"Created vault at {path}")
    return 0


def cmd_add(args) -> int:
    vault = _open(args)
    if args.generate:
        password = generator.generate(args.length, symbols=not args.no_symbols,
                                      ambiguous=not args.no_ambiguous)
    else:
        password = getpass.getpass("Entry password: ")
        if not password:
            raise VaultError("Password must not be empty.")
    vault.add(args.name, password, username=args.username or "", url=args.url or "",
              notes=args.notes or "", overwrite=args.overwrite)
    print(f"Saved entry '{args.name}'.")
    if args.generate and args.show:
        print(password)
    return 0


def cmd_get(args) -> int:
    entry = _open(args).get(args.name)
    print(f"name:     {args.name}")
    for field in ("username", "url", "notes"):
        if entry.get(field):
            print(f"{field + ':':<9} {entry[field]}")
    print(f"password: {entry['password'] if args.show else '********'}")
    return 0


def cmd_list(args) -> int:
    for name in _open(args).list():
        print(name)
    return 0


def cmd_rm(args) -> int:
    _open(args).remove(args.name)
    print(f"Removed entry '{args.name}'.")
    return 0


def cmd_passwd(args) -> int:
    vault = _open(args)
    new = getpass.getpass(f"New master password (min {MIN_MASTER_LEN} chars): ")
    if new != getpass.getpass("Repeat new master password: "):
        raise VaultError("Passwords do not match.")
    vault.change_master(new)
    print("Master password changed.")
    return 0


def cmd_gen(args) -> int:
    print(generator.generate(args.length, symbols=not args.no_symbols,
                             ambiguous=not args.no_ambiguous))
    return 0


def cmd_ui(args) -> int:
    from . import ui

    path = vault_path(args.vault)
    return ui.serve(path, port=args.port, open_browser=not args.no_browser)


def _gen_options(p) -> None:
    p.add_argument("--length", type=int, default=20, help="password length (default 20)")
    p.add_argument("--no-symbols", action="store_true", help="exclude symbols")
    p.add_argument("--no-ambiguous", action="store_true", help="exclude look-alike characters")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultkey", description="Encrypted CLI password manager.")
    parser.add_argument("--vault", metavar="PATH",
                        help="vault file (default: $VAULTKEY_PATH or ~/.vaultkey/vault.json)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="add an entry")
    p.add_argument("name")
    p.add_argument("--username")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--generate", action="store_true", help="generate the password")
    p.add_argument("--show", action="store_true", help="print the generated password")
    p.add_argument("--overwrite", action="store_true", help="replace an existing entry")
    _gen_options(p)
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("get", help="show an entry")
    p.add_argument("name")
    p.add_argument("--show", action="store_true", help="reveal the password")
    p.set_defaults(func=cmd_get)

    sub.add_parser("list", help="list entry names").set_defaults(func=cmd_list)

    p = sub.add_parser("rm", help="remove an entry")
    p.add_argument("name")
    p.set_defaults(func=cmd_rm)

    sub.add_parser("passwd", help="change the master password").set_defaults(func=cmd_passwd)

    p = sub.add_parser("ui", help="open the local web interface")
    p.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: random)")
    p.add_argument("--no-browser", action="store_true", help="only print the link")
    p.set_defaults(func=cmd_ui)

    p = sub.add_parser("gen", help="generate a password")
    _gen_options(p)
    p.set_defaults(func=cmd_gen)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (VaultError, CryptoError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
