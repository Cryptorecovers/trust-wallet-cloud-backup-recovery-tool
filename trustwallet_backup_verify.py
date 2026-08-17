#!/usr/bin/env python3
"""
trustwallet_backup_verify.py - check one or more candidate passwords against
a Trust Wallet backup's MAC (no guessing, no attack loop) and report
CORRECT / incorrect for each.

Works with just the Python standard library (MAC verification only).

Usage:
    python trustwallet_backup_verify.py backup.json "candidate1" ["candidate2" ...]

Part of the twrecover crypto suite by Crypto Recovers - https://cryptorecovers.com
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
    if len(args) < 2:
        print(__doc__.split("Usage:")[1].split("Example:")[0].strip())
        return 2
    file_arg = args[0]
    cli = ["-k", file_arg]
    for pw in args[1:]:
        cli += ["--verify-password", pw]
    return twrecover.main(cli)


if __name__ == "__main__":
    sys.exit(main())