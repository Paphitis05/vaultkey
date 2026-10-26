"""Application entry point: starts the local server and opens the app in the browser."""

import argparse
import os
import sys
from pathlib import Path

from . import ui

DEFAULT_PATH = Path.home() / ".vaultkey" / "vault.json"


def vault_path(arg: str | None) -> Path:
    return Path(arg or os.environ.get("VAULTKEY_PATH") or DEFAULT_PATH).expanduser()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultkey", description="Encrypted password manager app.")
    parser.add_argument("--vault", metavar="PATH",
                        help="vault file (default: $VAULTKEY_PATH or ~/.vaultkey/vault.json)")
    parser.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: random)")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser; only print the link")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return ui.serve(vault_path(args.vault), port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    sys.exit(main())
