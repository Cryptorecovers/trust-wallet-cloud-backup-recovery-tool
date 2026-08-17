#!/usr/bin/env python3
"""
trustwallet_backup_decrypt.py - decrypt a Trust Wallet backup with a password
you know: verifies the MAC, decrypts the payload with AES-128-CTR, classifies
it (private key or mnemonic phrase), and cross-checks the derived Ethereum
address against the backup's account list.

For the mnemonic payload the recovery phrase is written to disk (truncated
to the first 4 words on screen unless --show-secrets is given).

Usage:
    python trustwallet_backup_decrypt.py backup.json PASSWORD [-o OUT] [--show-secrets]

Options:
    -o, --export-decrypted OUT   also write the decrypted payload to OUT
    --show-secrets               print the full recovery phrase / private key

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
    if len(args) < 2:
        print(__doc__.split("Usage:")[1].split("Options:")[0].strip())
        return 2
    file_arg = args[0]
    pw = args[1]
    cli = ["-k", file_arg, "--decrypt-password", pw]
    rest = args[2:]
    if "-o" in rest:
        i = rest.index("-o")
        cli += ["--export-decrypted", rest[i + 1]]
        rest = rest[:i] + rest[i + 2:]
    cli += rest  # e.g. --show-secrets, --json-output
    return twrecover.main(cli)


if __name__ == "__main__":
    sys.exit(main())