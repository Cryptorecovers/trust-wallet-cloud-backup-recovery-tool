#!/usr/bin/env python3
"""
trustwallet_backup_inspect.py - validate a Trust Wallet backup file and print
a full structural report (format, KDF params, accounts, hashcat
compatibility) without trying any passwords.

Usage:  python trustwallet_backup_inspect.py backup.json [--json-output]

Part of the twrecover suite by Crypto Recovers - https://cryptorecovers.com
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import twrecover  # noqa: E402


def main():
    args = sys.argv[1:]
    if any(a in ("-h", "--help") for a in args):
        print(__doc__.strip())
        return 0
    if not args:
        print(__doc__.split("Usage:")[1].split("Part of")[0].strip())
        return 2
    file_arg = args.pop(0)
    return twrecover.main(["--inspect", "-k", file_arg] + args)


if __name__ == "__main__":
    sys.exit(main())