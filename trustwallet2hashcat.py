#!/usr/bin/env python3
"""
trustwallet2hashcat.py - convert a Trust Wallet backup file into a hashcat
'Ethereum Wallet' hash line for GPU-powered cracking.

    mode 15700 (scrypt):   $ethereum$s*N*r*p*salt*ciphertext*mac
    mode 15600 (pbkdf2):   $ethereum$p*iterations*salt*ciphertext*mac

Usage:
    python trustwallet2hashcat.py backup.json            # print to stdout
    python trustwallet2hashcat.py backup.json -o out.hc  # write to a file

Then, on the GPU machine:

    hashcat -m 15700 out.hc wordlist.txt          # scrypt backup
    hashcat -m 15600 out.hc wordlist.txt          # pbkdf2 backup

NOTE: hashcat's Ethereum modes require a 32-byte salt. Legacy Trust Wallet
cloud backups with an EMPTY salt are not loadable by hashcat (its parser
locks the salt field to exactly 64 hex chars) - for those use
trustwallet_backup_recover.py instead.

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
        print(__doc__.split("Usage:")[1].split("Then, on the GPU")[0].strip())
        return 2
    file_arg = args.pop(0)
    out = "-"
    rest = []
    if "-o" in args:
        i = args.index("-o")
        out = args[i + 1]
        args = args[:i] + args[i + 2:]
    rest = args
    return twrecover.main(["-k", file_arg, "--export-hashcat", out] + rest)


if __name__ == "__main__":
    sys.exit(main())