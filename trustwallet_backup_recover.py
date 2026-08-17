#!/usr/bin/env python3
"""
trustwallet_backup_recover.py - the full recovery tool: tries candidate
passwords (explicit, dictionary + mutation rules, brute force) against a
Trust Wallet backup file until the MAC matches.

This is the same engine as `twrecover` itself - the entry point exists so
every piece of the suite is a named, runnable tool:

    python trustwallet_backup_recover.py -k backup.json -l words.txt -r medium
    python trustwallet_backup_recover.py -k backup.json -a abc123 --min-length 4

Run `python trustwallet_backup_recover.py --help` for all options.

Part of the twrecover suite by Crypto Recovers - https://cryptorecovers.com
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import twrecover  # noqa: E402


def main():
    return twrecover.main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())