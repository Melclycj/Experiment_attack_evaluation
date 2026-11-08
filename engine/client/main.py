"""engine-client: the admin client (build plan 工程项 9, 10). Two subcommands with separate input streams (validation.md
A-03): ``admin`` speaks to the management port, ``attach`` to one row's pty relay. Workspace transfers (import, push,
export) run as root through their own entry, bin/engine-workspace, which does not load this module (validation.md A-10,
K-41)."""
from __future__ import annotations

import argparse

from . import admin, attach


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog='engine-client', description='engine v2 admin client')
    parser.add_argument('--root', required=True,
                        help='deployment root: <root>/state/admin.sock and <root>/rows/<execution>/attach.sock')
    sub = parser.add_subparsers(dest='command', required=True)
    admin.add_parser(sub)
    attach.add_parser(sub)
    args = parser.parse_args(argv)
    return admin.run(args) if args.command == 'admin' else attach.run(args)
