#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
twrecover - offline password recovery for Trust Wallet backup files (.json).

This tool recovers the password of a Trust Wallet backup - the
password-protected .json file the Trust Wallet app creates when you back
up a wallet. It uses the Web3 Secret Storage ("keystore v3") format.

How it works
------------
The keystore is loaded once. Every candidate password is checked by
re-deriving the key with the keystore's KDF (scrypt or PBKDF2-HMAC-SHA256)
and comparing the message authentication code (Keccak-256 of
derived_key[16:32] || ciphertext) against the stored MAC. Nothing ever
leaves your machine - this tool is fully offline.

When a password matches, the payload is decrypted (AES-128-CTR). For
private-key backups the derived Ethereum address is cross-checked against
the keystore's address; for mnemonic ("cloud backup") files the recovery
phrase is shown and the Ethereum address at m/44'/60'/0'/0/0 is derived
and checked against the backup's account list.

Only use this tool on wallet files you own.

Made by Crypto Recovers - https://cryptorecovers.com

Exit codes:
0  password found
1  password not found
2  usage / keystore / environment error
130 interrupted (Ctrl-C)
"""

import argparse
import bisect
import gzip
import hashlib
import hmac
import json
import multiprocessing
import os
import sys
import time
import unicodedata

__version__ = "1.4.0"
PROG = "twrecover"
BRAND = "Crypto Recovers"
BRAND_URL = "https://cryptorecovers.com"
BRAND_LINE = "%s (%s)" % (BRAND, BRAND_URL)
VERSION_LINE = "%(prog)s " + __version__ + " \u2014 by " + BRAND_LINE

EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KeystoreError(Exception):
    """Unsupported or malformed keystore."""


# ---------------------------------------------------------------------------
# Tiny console UI (colors only when stderr is a TTY)
# ---------------------------------------------------------------------------

_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_BOLD = "\033[1m"
_BLUE = "\033[34m"
_RESET = "\033[0m"


class UI:
    def __init__(self, quiet=False, tty=None):
        self.quiet = quiet
        self.tty = sys.stderr.isatty() if tty is None else tty

    def _c(self, text, color):
        return color + text + _RESET if self.tty else text

    def info(self, text):
        if not self.quiet:
            print(text, file=sys.stderr)

    def ok(self, text):
        if not self.quiet:
            print(self._c("[+] ", _GREEN) + text, file=sys.stderr)

    def warn(self, text):
        print(self._c("[!] ", _YELLOW) + text, file=sys.stderr)

    def err(self, text):
        print(self._c("[x] ", _RED) + text, file=sys.stderr)

    def head(self, text):
        if not self.quiet:
            print(self._c(text, _BOLD + _BLUE), file=sys.stderr)


# ---------------------------------------------------------------------------
# Keccak-256 (pycryptodome when available, otherwise pure Python)
# ---------------------------------------------------------------------------

try:
    from Crypto.Hash import keccak as _pyc_keccak

    def keccak256(data):
        return _pyc_keccak.new(digest_bits=256, data=data).digest()

    _KECCAK_IMPL = "pycryptodome"
except Exception:  # pragma: no cover - environment dependent
    try:
        from Cryptodome.Hash import keccak as _pyc_keccak  # pycryptodomex

        def keccak256(data):
            return _pyc_keccak.new(digest_bits=256, data=data).digest()

        _KECCAK_IMPL = "pycryptodomex"
    except Exception:
        def keccak256(data):
            return _keccak256(data)

        _KECCAK_IMPL = "pure-python"


def _rol(x, n):
    if n == 0:
        return x
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(st):
    """Keccak-f[1600] permutation. `st` is a list of 25 64-bit lanes, lane
    index = x + 5y (x = column, y = row)."""
    rc = (
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    )
    rot = (
        (0, 36, 3, 41, 18),
        (1, 44, 10, 45, 2),
        (62, 6, 43, 15, 61),
        (28, 55, 25, 21, 56),
        (27, 20, 39, 8, 14),
    )
    mask = 0xFFFFFFFFFFFFFFFF
    for r in rc:
        # theta
        c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(5):
                st[x + 5 * y] ^= dx        # rho + pi :  A[x, y] -> B[y, (2x + 3y) mod 5], rotated by r[x, y]
        # (flat lane index = x + 5y, so the destination is y + 5*((2x+3y) mod 5))
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                src = x + 5 * y
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(st[src], rot[x][y])
        # chi (each row must be snapshotted first - in-place updates would
        # corrupt the x+1/x+2 reads)
        for y in range(5):
            row = [b[x + 5 * y] for x in range(5)]
            for x in range(5):
                b[x + 5 * y] = (row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])) & mask
        st[:] = b
        # iota
        st[0] ^= r


def _keccak256(data):
    """Pure-Python Keccak-256 (fallback when pycryptodome is not installed)."""
    rate = 136          # bytes for the 1088-bit rate of Keccak-256
    out_len = 32
    st = [0] * 25

    block = bytearray(data)
    block.append(0x01)                          # Keccak domain padding
    while len(block) % rate != rate - 1:
        block.append(0x00)
    block.append(0x80)

    for off in range(0, len(block), rate):
        chunk = block[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(chunk[8 * i:8 * i + 8], "little")
        _keccak_f(st)

    digest = bytearray()
    while len(digest) < out_len:
        for i in range(rate // 8):
            digest += st[i].to_bytes(8, "little")
        if len(digest) < out_len:
            _keccak_f(st)
    return bytes(digest[:out_len])


# ---------------------------------------------------------------------------
# secp256k1 (pure Python; used to verify a recovered private key)
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    """Add two curve points (tuples or None for the point at infinity)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        m = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P
    else:
        m = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mul(k):
    """k * G for secp256k1."""
    result = None
    addend = _G
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _public_key_uncompressed(privkey_bytes):
    """Uncompressed SEC1 public key (65 bytes, 0x04 prefix) for a private key."""
    k = int.from_bytes(privkey_bytes, "big")
    if k == 0 or k >= _N:
        raise KeystoreError("private key out of range for secp256k1")
    x, y = _scalar_mul(k)
    return bytes([4]) + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _ethereum_address(privkey_bytes):
    """Lowercase 0x-hex Ethereum address for a 32-byte private key, or None."""
    if len(privkey_bytes) != 32:
        return None
    try:
        pub = _public_key_uncompressed(privkey_bytes)
    except KeystoreError:
        return None
    return "0x" + keccak256(pub[1:])[-20:].hex()


def _public_key_compressed(privkey_bytes):
    """Compressed SEC1 public key (33 bytes, 0x02/0x03 prefix)."""
    k = int.from_bytes(privkey_bytes, "big")
    if k == 0 or k >= _N:
        raise KeystoreError("private key out of range for secp256k1")
    x, y = _scalar_mul(k)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# BIP39 / BIP32 (Trust Wallet mnemonic backups)
# ---------------------------------------------------------------------------

# The HD path Trust Wallet uses for Ethereum: m/44'/60'/0'/0/0
_BIP44_ETH_PATH = (44 + 0x80000000, 60 + 0x80000000, 0 + 0x80000000, 0, 0)


def _mnemonic_to_seed(phrase, passphrase=""):
    """BIP39: seed = PBKDF2-HMAC-SHA512(phrase, salt="mnemonic"+passphrase,
    2048 iterations). Standard library only."""
    if isinstance(phrase, bytes):
        phrase = phrase.decode("utf-8", "replace")
    return hashlib.pbkdf2_hmac(
        "sha512",
        phrase.strip().encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048,
        dklen=64,
    )


def _bip32_private_key(seed, path):
    """BIP32: walk `path` (sequence of hardened/normal child indices) from a
    64-byte seed and return the resulting 32-byte private key."""
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(i[:32], "big")
    chain = i[32:]
    for index in path:
        if index >= 0x80000000:  # hardened child: ser256(k_par) || ser32(i)
            data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:  # normal child: serP(K_par) || ser32(i)
            data = _public_key_compressed(key.to_bytes(32, "big")) \
                + index.to_bytes(4, "big")
        i = hmac.new(chain, data, hashlib.sha512).digest()
        key = (int.from_bytes(i[:32], "big") + key) % _N
        chain = i[32:]
    return key.to_bytes(32, "big")


def mnemonic_eth_address(phrase, passphrase=""):
    """Ethereum address (lowercase, no 0x) for a BIP39 recovery phrase at
    m/44'/60'/0'/0/0 - the derivation path Trust Wallet chooses."""
    return _ethereum_address(_bip32_private_key(_mnemonic_to_seed(phrase, passphrase),
                                                _BIP44_ETH_PATH))


# ---------------------------------------------------------------------------
# Keystore parsing and cryptography
# ---------------------------------------------------------------------------

def _unhex(value, what):
    """Tolerantly decode a hex string (with or without 0x prefix)."""
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    if not isinstance(value, str):
        raise KeystoreError("field '%s' is not a hex string" % what)
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise KeystoreError("field '%s' is not valid hex" % what)


def load_keystore(path):
    """Load and normalize a keystore v3 JSON file. Returns a plain dict."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise KeystoreError("no such file: %s" % path)
    except ValueError as exc:
        raise KeystoreError("file %s is not valid JSON: %s" % (path, exc))
    if not isinstance(doc, dict):
        raise KeystoreError("keystore must be a JSON object")

    crypto = doc.get("crypto") or doc.get("Crypto")
    if crypto is None:
        if any(k in doc for k in ("privateKey", "private_key", "address", "mnemonic", "seed")):
            raise KeystoreError(
                "this file is NOT encrypted - it already contains plaintext "
                "secret material, so there is no password to recover"
            )
        raise KeystoreError("not a Trust Wallet backup file: no 'crypto' section found")

    version = doc.get("version")
    if version is not None and str(version) not in ("3", "4"):
        raise KeystoreError(
            "unsupported keystore version %r (only v3-style Web3 Secret "
            "Storage files are supported)" % version
        )

    kdf_name = str(crypto.get("kdf", "")).lower()
    cipher_name = str(crypto.get("cipher", "")).lower()
    if kdf_name not in ("scrypt", "pbkdf2"):
        raise KeystoreError("unsupported kdf %r (expected 'scrypt' or 'pbkdf2')" % kdf_name)
    if cipher_name != "aes-128-ctr":
        raise KeystoreError("unsupported cipher %r (only 'aes-128-ctr' is supported)" % cipher_name)

    kp = crypto.get("kdfparams") or {}
    cp = crypto.get("cipherparams") or {}
    ks = {
        "kdf": kdf_name,
        "cipher": cipher_name,
        # Legacy Trust Wallet backups may carry an EMPTY salt ("salt": "")
        # or omit the key entirely - both mean "empty salt", which the
        # app's wallet-core accepts for backward compatibility.
        "salt": _unhex(kp.get("salt") or "", "kdfparams.salt"),
        "ciphertext": _unhex(crypto.get("ciphertext"), "crypto.ciphertext"),
        "iv": _unhex(cp.get("iv"), "cipherparams.iv"),
        "mac": _unhex(crypto.get("mac"), "crypto.mac"),
        "dklen": int(kp.get("dklen", 32)),
        "address": doc.get("address"),
        # Trust Wallet StoredKey / cloud-backup metadata (absent in plain
        # keystore v3 files - all optional for recovery).
        "type": doc.get("type"),
        "name": doc.get("name"),
        "active_accounts": doc.get("activeAccounts") or [],
        "version": version,
    }
    if ks["dklen"] < 32:
        raise KeystoreError("kdfparams.dklen must be >= 32")
    if kdf_name == "scrypt":
        ks["n"] = int(kp.get("n", 262144))
        ks["r"] = int(kp.get("r", 8))
        ks["p"] = int(kp.get("p", 1))
        if ks["n"] <= 1:
            raise KeystoreError("scrypt 'n' must be > 1")
    else:
        prf = str(kp.get("prf", "hmac-sha256")).lower()
        if prf != "hmac-sha256":
            raise KeystoreError("unsupported pbkdf2 prf %r (only hmac-sha256)" % prf)
        ks["c"] = int(kp.get("c", 262144))
        if ks["c"] < 1:
            raise KeystoreError("pbkdf2 iteration count must be >= 1")
    return ks


def _derive_scrypt(password_bytes, salt, n, r, p, dklen):
    """scrypt via OpenSSL when possible, pycryptodome otherwise."""
    scram = getattr(hashlib, "scrypt", None)
    if scram is not None:
        try:
            maxmem = 128 * n * r * p * 2 + (1 << 20)
            return scram(password_bytes, salt=salt, n=n, r=r, p=p,
                         dklen=dklen, maxmem=maxmem)
        except (TypeError, ValueError, OverflowError):
            pass  # OpenSSL without scrypt support -> pycryptodome below
    try:
        from Crypto.Protocol.KDF import scrypt as _crypto_scrypt
    except ImportError:
        pass
    else:
        return _crypto_scrypt(password_bytes, salt, dklen, n, r, p)
    raise KeystoreError(
        "scrypt is not available on this Python build - install pycryptodome "
        "(`pip install pycryptodome`) or upgrade OpenSSL/Python"
    )


def derive_key(ks, password):
    """Derive `dklen` bytes from `password` (str or bytes) for a keystore."""
    if ks["kdf"] not in ("scrypt", "pbkdf2"):
        raise KeystoreError("unsupported kdf %r" % ks["kdf"])
    if not isinstance(password, bytes):
        password = password.encode("utf-8")
    if ks["kdf"] == "scrypt":
        return _derive_scrypt(password, ks["salt"], ks["n"], ks["r"], ks["p"], ks["dklen"])
    return hashlib.pbkdf2_hmac("sha256", password, ks["salt"], ks["c"], dklen=ks["dklen"])


def compute_mac(ks, derived):
    """Keccak-256(derived_key[16:32] || ciphertext) - the keystore MAC."""
    return keccak256(derived[16:32] + ks["ciphertext"])


def decrypt(ks, password):
    """AES-128-CTR decrypt of the stored ciphertext (MAC must already match).
    Requires pycryptodome; raises KeystoreError if it is not installed."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ImportError:
        raise KeystoreError(
            "decryption needs pycryptodome - install it with `pip install pycryptodome`"
        )
    key = derive_key(ks, password)[:16]
    ctr = Counter.new(128, initial_value=int.from_bytes(ks["iv"], "big"))
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ks["ciphertext"])


_MNEMONIC_WORD_COUNTS = (12, 15, 18, 21, 24)


def _looks_like_mnemonic(data):
    """True if `data` looks like a BIP39 recovery phrase: UTF-8 text of 12,
    15, 18, 21 or 24 lowercase alphabetic words."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    words = text.strip().split()
    if len(words) not in _MNEMONIC_WORD_COUNTS:
        return False
    return all(w.isascii() and w.isalpha() and w.islower() for w in words)


def describe_plaintext(plaintext):
    """Classify decrypted bytes: private-key (32B), seed (64B), json,
    mnemonic phrase, or opaque."""
    if len(plaintext) == 32:
        return "private-key"
    if len(plaintext) == 64:
        return "seed"
    if _looks_like_mnemonic(plaintext):
        return "mnemonic"
    try:
        json.loads(plaintext.decode("utf-8"))
        return "json"
    except (ValueError, UnicodeDecodeError):
        return "opaque"


def _normalize_address(value):
    if not value:
        return None
    value = str(value).strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return value or None


def hashcat_line(ks):
    """Render `ks` as a hashcat 'Ethereum Wallet' line.

    mode 15700 (scrypt):  $ethereum$s*N*r*p*salt*ciphertext*mac
    mode 15600 (pbkdf2):  $ethereum$p*iterations*salt*ciphertext*mac
    (formats verified against hashcat's own module sources and example hashes)
    """
    salt = ks["salt"].hex()
    ct = ks["ciphertext"].hex()
    mac = ks["mac"].hex()
    if ks["kdf"] == "scrypt":
        return "$ethereum$s*%d*%d*%d*%s*%s*%s" % (
            ks["n"], ks["r"], ks["p"], salt, ct, mac)
    return "$ethereum$p*%d*%s*%s*%s" % (ks["c"], salt, ct, mac)


def hashcat_mode(ks):
    """hashcat mode number for this keystore (15700 scrypt, 15600 pbkdf2)."""
    return 15700 if ks["kdf"] == "scrypt" else 15600


def hashcat_compatible(ks):
    """(ok, reasons) - can hashcat load this keystore at all?

    hashcat's Ethereum Wallet modes lock the salt field to exactly 32 bytes
    (64 hex chars, TOKEN_ATTR_FIXED_LENGTH in module_15600/15700.c) and
    require scrypt N to be divisible by 1024 - so legacy Trust Wallet
    backups with an empty salt are rejected by hashcat entirely.
    """
    reasons = []
    if ks["kdf"] == "scrypt" and ks["n"] % 1024:
        reasons.append("scrypt n=%d must be divisible by 1024 for hashcat" % ks["n"])
    if len(ks["salt"]) != 32:
        reasons.append(
            "hashcat requires a 32-byte salt; this backup has %d byte(s) - "
            "legacy empty-salt backups are not loadable by hashcat modes "
            "15600/15700" % len(ks["salt"]))
    return (not reasons), reasons


def inspect_keystore(ks, path):
    """Deep structural report - everything knowable without a password."""
    stored = []
    for acct in ks.get("active_accounts") or []:
        if isinstance(acct, dict) and acct.get("address"):
            stored.append({"address": acct["address"],
                           "derivation_path": acct.get("derivationPath"),
                           "coin": acct.get("coin")})
    legacy_addr = _normalize_address(ks.get("address"))
    if legacy_addr:
        stored.insert(0, {"address": "0x" + legacy_addr, "derivation_path": None,
                          "coin": None})
    hc_ok, hc_reasons = hashcat_compatible(ks)
    report = {
        "file": path,
        "valid": True,
        "format": "Trust Wallet StoredKey (cloud backup)"
                   if ks.get("type") else "keystore v3",
        "version": ks.get("version"),
        "type": ks.get("type"),
        "name": ks.get("name"),
        "accounts": stored,
        "kdf": ks["kdf"],
        "cipher": ks["cipher"],
        "dklen": ks["dklen"],
        "salt_bytes": len(ks["salt"]),
        "iv_bytes": len(ks["iv"]),
        "mac_bytes": len(ks["mac"]),
        "ciphertext_bytes": len(ks["ciphertext"]),
        "hashcat_mode": hashcat_mode(ks),
        "hashcat_loadable": hc_ok,
        "hashcat_reasons": hc_reasons,
        "recoverable": True,
        "by": BRAND_LINE,
    }
    if ks["kdf"] == "scrypt":
        report["scrypt_n"] = ks["n"]
        report["scrypt_r"] = ks["r"]
        report["scrypt_p"] = ks["p"]
    else:
        report["pbkdf2_c"] = ks["c"]
    return report


def keystore_summary(ks):
    """Human-readable one-line description of the keystore parameters."""
    parts = []
    if ks.get("name"):
        parts.append("name=%r" % ks["name"])
    if ks.get("type"):
        parts.append("type=%s" % ks["type"])
    parts.append("kdf=%s" % ks["kdf"])
    if ks["kdf"] == "scrypt":
        parts.append("n=%d r=%d p=%d" % (ks["n"], ks["r"], ks["p"]))
    else:
        parts.append("c=%d" % ks["c"])
    parts.append("dklen=%d" % ks["dklen"])
    parts.append("cipher=%s" % ks["cipher"])
    addr = _normalize_address(ks.get("address"))
    if not addr:
        for acct in ks.get("active_accounts") or []:
            if isinstance(acct, dict):
                addr = _normalize_address(acct.get("address"))
                if addr:
                    break
    if addr:
        parts.append("address=0x%s" % addr)
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Password candidate sources
# ---------------------------------------------------------------------------

_LEET_TABLE = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0",
                             "s": "5", "t": "7", "g": "9", "b": "8"})
_YEARS = [str(y) for y in range(1990, 2027)]
_SYMBOLS = ["!", "@", "#", "$", "%", "^", "&", "*", "?"]


def _typos_candidates(word):
    """bt-recovery-style typos of a hint word (deterministic, fixed size).

    For a word of length n this returns 1 + 3n + max(n - 1, 0) candidates:
    identity, every single-character deletion, every adjacent swap, every
    single-character doubling, and an 's' inserted after every position
    (classic plural/possessive typo). Duplicates are intentionally kept so
    the candidate count depends only on the word length.
    """
    out = [word]  # the exact hint itself
    n = len(word)
    for i in range(n):
        out.append(word[:i] + word[i + 1:])            # delete char i
        out.append(word[:i + 1] + word[i])             # double char i
        out.append(word[:i + 1] + "s" + word[i + 1:])  # insert 's' after char i
    for i in range(n - 1):
        c = list(word)
        c[i], c[i + 1] = c[i + 1], c[i]                # swap adjacent pair
        out.append("".join(c))
    return out


def _candidates_for(word, ruleset):
    """Expand one dictionary word into candidate passwords for a rule set.

    IMPORTANT: for the fixed rulesets the returned list length must not
    depend on the word content (rule application is unconditional, duplicates
    included) - the engine indexes candidates arithmetically. The 'typos'
    ruleset is the exception: its count scales with word length, which the
    engine supports via prefix sums.
    """
    if ruleset == "none":
        return [word]
    if ruleset == "typos":
        return _typos_candidates(word)
    out = []
    raw = word
    lower = word.lower()
    cap = word.capitalize()

    # base variants (raw, lower, upper, capitalized)
    out.extend([word, lower, word.upper(), cap])

    # digit suffixes 0..99 on raw and capitalized
    for d in range(100):
        out.append(raw + str(d))
        out.append(cap + str(d))

    # year suffixes
    for y in _YEARS:
        out.append(raw + y)
        out.append(cap + y)

    # symbol suffixes
    for s in _SYMBOLS:
        out.append(raw + s)
        out.append(cap + s)

    # doubled and reversed
    out.append(raw + raw)
    out.append(cap + cap)
    out.append(raw[::-1])
    out.append(cap[::-1])

    # unicode normalization variants (fixed length: unconditional)
    out.append(unicodedata.normalize("NFC", word))
    out.append(unicodedata.normalize("NFKD", word))

    if ruleset in ("medium", "full", "leet"):
        leet_raw = lower.translate(_LEET_TABLE)
        leet_cap = leet_raw.capitalize()
        out.append(leet_raw)
        out.append(leet_cap)
        for d in range(10):
            out.append(leet_raw + str(d))
            out.append(leet_cap + str(d))
        if ruleset in ("full", "leet"):
            for d in range(100):
                out.append(leet_raw + str(d))
                out.append(leet_cap + str(d))
            if ruleset == "leet":
                for y in _YEARS:
                    out.append(leet_raw + y)

    if ruleset == "full":
        for d in range(100, 1000):
            out.append(raw + str(d))
            out.append(cap + str(d))

    return out


class DirectSource:
    """A short fixed list of explicit passwords."""

    def __init__(self, passwords):
        self.passwords = list(passwords)

    @property
    def total(self):
        return len(self.passwords)

    def at(self, i):
        return self.passwords[i]

    def scan(self, ks, start, end):
        attempts = 0
        for i in range(start, end):
            pw = self.passwords[i]
            attempts += 1
            if _try_password(ks, pw):
                return attempts, pw
        return attempts, None

    def describe(self):
        return "%d explicit password(s)" % len(self.passwords)


class WordlistSource:
    """Dictionary words expanded by a rule set.

    Candidate counts may vary per word (typo rules scale with word length),
    so candidates are indexed through a prefix-sum table: at(i) and scan()
    are deterministic and identical in every process.
    """

    def __init__(self, words, ruleset):
        self.words = list(words)
        self.ruleset = ruleset
        self._cum = None  # [0, c0, c0+c1, ...] - built lazily

    def _cumulative(self):
        if self._cum is None:
            cum = [0]
            for w in self.words:
                cum.append(cum[-1] + len(_candidates_for(w, self.ruleset)))
            self._cum = cum
        return self._cum

    @property
    def total(self):
        return self._cumulative()[-1]

    def _split(self, i):
        cum = self._cumulative()
        wi = bisect.bisect_right(cum, i) - 1
        return wi, i - cum[wi]

    def at(self, i):
        wi, off = self._split(i)
        return _candidates_for(self.words[wi], self.ruleset)[off]

    def scan(self, ks, start, end):
        words = self.words
        cum = self._cumulative()
        cache = {}
        attempts = 0
        wi = bisect.bisect_right(cum, start) - 1
        off = start - cum[wi]
        i = start
        while i < end:
            cands = cache.get(wi)
            if cands is None:
                if len(cache) >= 4096:
                    cache.clear()
                cands = _candidates_for(words[wi], self.ruleset)
                cache[wi] = cands
            n = len(cands)
            while i < end and off < n:
                attempts += 1
                pw = cands[off]
                if _try_password(ks, pw):
                    return attempts, pw
                i += 1
                off += 1
            wi += 1
            off = 0
        return attempts, None

    def describe(self):
        return "wordlist (%d words -> %s candidates, ruleset '%s')" % (
            len(self.words), _fmt_int(self.total), self.ruleset)


class BruteSource:
    """Exhaustive enumeration of all strings over `alphabet`, length min..max."""

    def __init__(self, alphabet, min_len, max_len):
        self.alphabet = list(alphabet)
        self.min_len = int(min_len)
        self.max_len = int(max_len)
        if self.min_len < 1 or self.max_len < self.min_len:
            raise KeystoreError("invalid brute-force lengths (1 <= min <= max)")
        if not self.alphabet:
            raise KeystoreError("empty alphabet")

    @property
    def total(self):
        return sum(len(self.alphabet) ** L
                   for L in range(self.min_len, self.max_len + 1))

    def at(self, i):
        """Deterministic index -> password mapping (length-major order)."""
        base = len(self.alphabet)
        L = self.min_len
        while True:
            size = base ** L
            if i < size:
                break
            i -= size
            L += 1
        chars = []
        for _ in range(L):
            chars.append(self.alphabet[i % base])
            i //= base
        return "".join(reversed(chars))

    def scan(self, ks, start, end):
        attempts = 0
        for i in range(start, end):
            pw = self.at(i)
            attempts += 1
            if _try_password(ks, pw):
                return attempts, pw
        return attempts, None

    def describe(self):
        return "brute force (%d^%d..%d = %s candidates)" % (
            len(self.alphabet), self.min_len, self.max_len,
            _fmt_int(self.total))


def _try_password(ks, password):
    """True if `password` (str) unlocks the keystore (MAC comparison)."""
    try:
        derived = derive_key(ks, password)
    except KeystoreError:
        raise
    except Exception:
        return False
    return hmac.compare_digest(compute_mac(ks, derived), ks["mac"])


# ---------------------------------------------------------------------------
# Attack engine (multiprocessing)
# ---------------------------------------------------------------------------

_WORKER_CFG = {}


def _worker_init(cfg):
    global _WORKER_CFG
    _WORKER_CFG = cfg


def _source_from_cfg(cfg):
    kind = cfg["kind"]
    if kind == "direct":
        return DirectSource(cfg["direct"])
    if kind == "wordlist":
        return WordlistSource(cfg["words"], cfg["ruleset"])
    return BruteSource(cfg["alphabet"], cfg["min_len"], cfg["max_len"])


def _worker_scan(args):
    cfg = _WORKER_CFG
    start, count = args
    ks = cfg["ks"]
    limit = cfg["limit"]
    end = min(start + count, limit)
    if end <= start:
        return 0, None
    source = _source_from_cfg(cfg)
    attempts, found = source.scan(ks, start, end)
    return attempts, found


def run_attack(ks, source, threads, limit=None, progress_cb=None):
    """Try every candidate of `source`; returns (found, attempts, seconds)."""
    total = source.total if limit is None else min(source.total, limit)
    if total <= 0:
        return None, 0, 0.0

    started = time.monotonic()
    found = None
    attempts = 0

    if isinstance(source, DirectSource):
        cfg = {"kind": "direct", "direct": source.passwords, "ks": ks, "limit": total}
    elif isinstance(source, WordlistSource):
        cfg = {"kind": "wordlist", "words": source.words, "ruleset": source.ruleset,
               "ks": ks, "limit": total}
    else:
        cfg = {"kind": "brute", "alphabet": source.alphabet,
               "min_len": source.min_len, "max_len": source.max_len,
               "ks": ks, "limit": total}

    if threads <= 1:
        step = max(2000, total // 200)
        for start in range(0, total, step):
            a, f = source.scan(ks, start, min(start + step, total))
            attempts += a
            if f is not None:
                found = f
                break
            if progress_cb:
                progress_cb(attempts)
    else:
        pool = multiprocessing.Pool(processes=threads,
                                    initializer=_worker_init, initargs=(cfg,))
        try:
            chunk = max(1, min(2000, total // (threads * 40)))
            tasks = ((start, min(chunk, total - start))
                     for start in range(0, total, chunk))
            for a, f in pool.imap_unordered(_worker_scan, tasks, chunksize=1):
                attempts += a
                if f is not None:
                    found = f
                    break
                if progress_cb:
                    progress_cb(attempts)
        finally:
            pool.terminate()
            pool.join()

    return found, attempts, time.monotonic() - started


# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------

class Progress:
    def __init__(self, total, interval=0.4, tty=None):
        self.total = total
        self.interval = interval
        self.tty = sys.stderr.isatty() if tty is None else tty
        self._last = 0.0
        self._t0 = time.monotonic()

    def update(self, n):
        now = time.monotonic()
        if now - self._last < self.interval:
            return
        self._last = now
        rate = n / (now - self._t0) if now > self._t0 else 0.0
        pct = 100.0 * n / self.total if self.total else 100.0
        eta = (self.total - n) / rate if rate > 0 else 0.0
        line = "[%6.2f%%] %s/%s candidates | %s/s | ETA %s" % (
            pct, _fmt_int(n), _fmt_int(self.total), _fmt_int(rate),
            _fmt_duration(eta))
        if self.tty:
            sys.stderr.write("\r" + line + " " * 4)
            sys.stderr.flush()
        else:
            print(line, file=sys.stderr)

    def finish(self):
        if self.tty:
            sys.stderr.write("\r" + " " * 90 + "\r")
            sys.stderr.flush()


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % seconds
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return "%dm %02ds" % (minutes, seconds)
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return "%dh %02dm" % (hours, minutes)
    days, hours = divmod(hours, 24)
    return "%dd %02dh" % (days, hours)


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f PB" % (n / 1024.0)


def _fmt_int(n):
    n = int(n)
    if n >= 1_000_000_000:
        return "%.2fB" % (n / 1e9)
    if n >= 1_000_000:
        return "%.2fM" % (n / 1e6)
    if n >= 10_000:
        return "%.1fK" % (n / 1e3)
    return str(n)


# ---------------------------------------------------------------------------
# Wordlist loading
# ---------------------------------------------------------------------------

def _read_wordlist(path):
    """Read one password per line; supports '-' (stdin) and .gz files."""
    if path == "-":
        fh = sys.stdin
        close = False
    elif path.endswith(".gz"):
        fh = gzip.open(path, "rt", encoding="utf-8", errors="replace")
        close = True
    else:
        fh = open(path, "r", encoding="utf-8", errors="replace")
        close = True
    try:
        return [line.strip() for line in fh if line.strip()]
    finally:
        if close:
            fh.close()


# ---------------------------------------------------------------------------
# Result handling
# ---------------------------------------------------------------------------

def _export_plaintext(path, plaintext):
    kind = describe_plaintext(plaintext)
    if kind == "mnemonic":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(plaintext.decode("utf-8").strip() + "\n")
    elif kind == "json":
        payload = json.dumps(json.loads(plaintext.decode("utf-8")),
                             indent=2, ensure_ascii=False) + "\n"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# twrecover export - %d-byte secret, hex encoded\n"
                     % len(plaintext))
            fh.write(plaintext.hex() + "\n")


def _inspect_and_report(ks, password, args, ui):
    """After a MAC match: decrypt, classify, verify the address, export."""
    result = {}
    try:
        plaintext = decrypt(ks, password)
    except KeystoreError as exc:
        ui.warn("%s - the password itself is verified by the MAC check, "
                "but the payload can't be decrypted without it" % exc)
        return result

    kind = describe_plaintext(plaintext)
    ui.ok("decrypted payload: %s (%d bytes)" % (kind, len(plaintext)))
    result["plaintext_kind"] = kind

    derived = None
    if kind == "private-key":
        derived = _ethereum_address(plaintext)
    elif kind == "mnemonic":
        phrase = plaintext.decode("utf-8").strip()
        try:
            derived = mnemonic_eth_address(phrase)
        except KeystoreError:
            derived = None

    ks_addr = _normalize_address(ks.get("address"))
    if not ks_addr:
        for acct in ks.get("active_accounts") or []:
            if isinstance(acct, dict):
                ks_addr = _normalize_address(acct.get("address"))
                if ks_addr:
                    break
    target = _normalize_address(args.verify_address)
    if derived:
        ui.info("derived address: %s" % derived)
        if ks_addr:
            match = derived[2:] == ks_addr
            ui.info("keystore address: 0x%s %s" % (
                ks_addr, ui._c("(match)" if match else "(MISMATCH)",
                               _GREEN if match else _RED)))
            result["address_match"] = match
        if target and derived[2:] != target:
            ui.warn("decrypted private key does not match --verify-address %s" % target)

    if args.show_secrets:
        if kind == "mnemonic":
            print("recovery phrase: %s" % plaintext.decode("utf-8").strip())
        elif kind == "json":
            print(json.dumps(json.loads(plaintext.decode("utf-8")),
                             indent=2, ensure_ascii=False))
        else:
            print("private key (hex): %s" % plaintext.hex())

    if args.export_decrypted:
        _export_plaintext(args.export_decrypted, plaintext)
        ui.ok("decrypted payload written to %s" % args.export_decrypted)
        result["export_path"] = args.export_decrypted

    if args.show_secrets or args.export_decrypted:
        ui.warn("the recovered secret is sensitive - delete these artifacts "
                "once you have imported the wallet")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    epilog = (
        "Made by %s \u2014 %s\n\n" % (BRAND, BRAND_URL)
        + "Examples:\n"
        + "  %(prog)s -k wallet.json -p \"my guess\"\n"
        + "  %(prog)s -k wallet.json -l rockyou.txt -r basic\n"
        + "  %(prog)s -k wallet.json -a abcd1234 --min-length 4 --max-length 6\n"
        + "  %(prog)s -k wallet.json -l words.txt --export-hashcat hashes.txt\n"
        + "  %(prog)s -k wallet.json -l words.txt --export-decrypted plain.json\n"
        + "  %(prog)s -k wallet.json --benchmark\n"
    )
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Offline password recovery for Trust Wallet backup files "
                    "(.json). By %s (%s)." % (BRAND, BRAND_URL),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-k", "--keystore", metavar="FILE",
                   help="encrypted wallet .json file to recover (or the "
                        "single file to inspect/verify/decrypt; ignored in "
                        "--batch mode)")
    p.add_argument("--inspect", action="store_true",
                   help="validate the backup and print a full structural "
                        "report (KDF params, accounts, hashcat compatibility) "
                        "- no password guessing")
    p.add_argument("--verify-password", metavar="PASS", action="append",
                   default=[],
                   help="check specific password(s) against the backup's MAC "
                        "and report CORRECT/incorrect (repeatable; works "
                        "without pycryptodome)")
    p.add_argument("--decrypt-password", metavar="PASS", action="append",
                   default=[],
                   help="check password(s) and decrypt + report the payload "
                        "for the first correct one (combine with "
                        "--show-secrets / --export-decrypted)")
    p.add_argument("--batch", metavar="DIR",
                   help="recover passwords across every .json backup in a "
                        "directory (one run, shared password sources)")
    p.add_argument("-p", "--password", metavar="PASS", action="append", default=[],
                   help="try one explicit password (repeatable)")
    p.add_argument("-l", "--wordlist", metavar="FILE", action="append", default=[],
                   help="dictionary of passwords (one per line, repeatable, "
                        "'-' = stdin, .gz supported)")
    p.add_argument("-r", "--rules",
                   choices=("none", "typos", "basic", "medium", "full", "leet"),
                   default="medium",
                   help="wordlist mutation rules (default: medium). none = raw "
                        "words only; typos = bt-recovery-style single typo variants "
                        "(deletions, adjacent swaps, doublings, inserted 's'); "
                        "basic = digits/years/symbols; medium = basic + leet; "
                        "full = medium + 3-digit suffixes; leet = leet-heavy")
    p.add_argument("-a", "--alphabet", metavar="CHARS",
                   help="brute-force alphabet (e.g. abcd1234)")
    p.add_argument("--min-length", type=int, default=1, metavar="N",
                   help="brute-force minimum length (default: 1)")
    p.add_argument("--max-length", type=int, default=None, metavar="N",
                   help="brute-force maximum length (default: same as --min-length)")
    p.add_argument("-t", "--threads", type=int, default=0, metavar="N",
                   help="parallel worker processes (default: CPU count, 0 = auto)")
    p.add_argument("--limit", type=int, default=None, metavar="N",
                   help="stop after N candidates (across all sources)")
    p.add_argument("--check-empty", action="store_true",
                   help="also try the empty password")
    p.add_argument("--verify-address", metavar="ADDR",
                   help="cross-check the recovered key against a known address")
    p.add_argument("--show-secrets", action="store_true",
                   help="print the recovered private key / plaintext payload")
    p.add_argument("--export-decrypted", metavar="OUT",
                   help="write the decrypted payload to OUT (JSON or hex file)")
    p.add_argument("--export-hashcat", metavar="OUT",
                   help="export the keystore as a hashcat 'Ethereum Wallet' "
                        "line to OUT ('-' = stdout) for GPU cracking "
                        "(mode 15700 scrypt / 15600 pbkdf2)")
    p.add_argument("--benchmark", action="store_true",
                   help="measure and print the attack speed for this "
                       "keystore, then exit (no attempts)")
    p.add_argument("--json-output", action="store_true",
                   help="emit a single machine-readable JSON result on stdout")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress all non-essential output")
    p.add_argument("--progress", action="store_true",
                   help="show progress even when stderr is not a TTY")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="verbose diagnostics")
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation on long runs")
    p.add_argument("--version", action="version", version=VERSION_LINE)
    return p


def _time_one_attempt(ks):
    """Seconds per single password check (best of three, warmed)."""
    best = None
    for _ in range(3):
        t0 = time.perf_counter()
        _try_password(ks, "twrecover-probe-%d" % _)
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
    return best


def _maybe_confirm(ui, est_seconds, total, stdin_used, auto_yes):
    """Ask before launching very long runs. Returns True to proceed."""
    ui.info("estimated time: %s (%s candidates, %.0f/s at full parallelism)"
            % (_fmt_duration(est_seconds), _fmt_int(total),
               total / est_seconds if est_seconds else 0))
    if auto_yes or stdin_used or not ui.tty:
        return True
    if est_seconds <= 120:
        return True
    ui.warn("this could take %s - you can interrupt with Ctrl-C and retry "
            "with a narrower wordlist or rule set" % _fmt_duration(est_seconds))
    try:
        answer = input("Continue? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.startswith("y")


def _scan_keystore(ks, label, sources, total, args, ui, threads, auto_confirm):
    """Full single-file recovery run: diagnostics, timing, confirmation,
    attack, reporting. Returns (exit_code, found_bool)."""
    ui.info("keystore: %s" % keystore_summary(ks))
    if args.verbose:
        ui.info("keccak implementation: %s" % _KECCAK_IMPL)
        ui.info("threads: %d (one candidate per attempt; scrypt uses ~%s of "
                "memory per worker)"
                % (threads, _fmt_int(ks.get("n", 1) * ks.get("r", 1) * 128)))
    for src, name in sources:
        ui.info("source: %s" % name)

    try:
        per_attempt = _time_one_attempt(ks)
    except KeystoreError as exc:
        ui.err(str(exc))
        return EXIT_ERROR, False
    est = per_attempt * total / max(threads, 1)
    ui.info("one attempt: %.1f ms (%.0f/s per worker)"
            % (per_attempt * 1000, 1.0 / per_attempt if per_attempt else 0))
    if not auto_confirm and not _maybe_confirm(ui, est, total,
                                               args.wordlist and "-" in args.wordlist,
                                               args.yes):
        ui.warn("aborted by user")
        return EXIT_ERROR, False

    show_progress = (not args.quiet) and (ui.tty or args.progress)
    found = None
    found_source = None
    attempts = 0
    t_start = time.monotonic()
    try:
        for src, name in sources:
            ui.head("trying %s..." % name)
            limit = None if args.limit is None else max(0, args.limit - attempts)
            progress = Progress(src.total if limit is None else min(src.total, limit))
            pw, a, _ = run_attack(ks, src, threads, limit=limit,
                                  progress_cb=progress.update if show_progress else None)
            progress.finish()
            attempts += a
            if pw is not None:
                found, found_source = pw, name
                break
            if limit is not None and attempts >= args.limit:
                break
    except KeystoreError as exc:
        ui.err(str(exc))
        return EXIT_ERROR, False
    except KeyboardInterrupt:
        ui.warn("interrupted after %s attempts" % _fmt_int(attempts))
        return EXIT_INTERRUPTED, False

    elapsed = time.monotonic() - t_start
    rate = attempts / elapsed if elapsed > 0 else 0.0

    result = {
        "found": found is not None,
        "keystore": label,
        "attempts": attempts,
        "seconds": round(elapsed, 2),
        "candidates_per_second": round(rate, 1),
        "by": BRAND_LINE,
    }

    if found is not None:
        ui.ok("password found in %s (source: %s)" % (found_source, _fmt_duration(elapsed)))
        ui.info("recovered by %s \u2014 %s" % (BRAND, BRAND_URL))
        result["password"] = found
        result["source"] = found_source
        extra = _inspect_and_report(ks, found, args, ui)
        result.update(extra)
        if args.json_output:
            print(json.dumps(result, ensure_ascii=False))
        else:
            print("Password: %s" % found)
        return EXIT_FOUND, True

    ui.err("password not found after %s attempts (%.1f/s)"
           % (_fmt_int(attempts), rate))
    if args.json_output:
        print(json.dumps(result, ensure_ascii=False))
    return EXIT_NOT_FOUND, False


def _assemble_sources(args, ui):
    """Build the password candidate sources. Returns (sources, total) or
    (None, None) on error (error already reported)."""
    sources = []
    direct = []
    if args.check_empty:
        direct.append("")
    direct.extend(args.password)
    if direct:
        sources.append((DirectSource(direct), "direct"))
    if args.wordlist:
        words = []
        for wl in args.wordlist:
            words.extend(_read_wordlist(wl))
        words = list(dict.fromkeys(words))
        if not words:
            ui.warn("wordlist(s) contained no usable passwords")
        else:
            src = WordlistSource(words, args.rules)
            sources.append((src, src.describe()))
    if args.alphabet:
        try:
            src = BruteSource(args.alphabet, args.min_length,
                              args.max_length if args.max_length is not None
                              else args.min_length)
        except KeystoreError as exc:
            ui.err(str(exc))
            return None, None
        sources.append((src, src.describe()))
    if not sources:
        ui.err("nothing to try - use --password, --wordlist and/or --alphabet "
               "(see --help)")
        return None, None
    total = sum(s.total for s, _ in sources)
    if args.limit is not None:
        total = min(total, args.limit)
    if total <= 0:
        ui.err("nothing to try (0 candidates)")
        return None, None
    return sources, total


def main(argv=None):
    args = build_parser().parse_args(argv)
    ui = UI(quiet=args.quiet)
    threads = args.threads or os.cpu_count() or 1

    if not args.keystore and not args.batch:
        ui.err("missing -k/--keystore FILE (or use --batch DIR)")
        return EXIT_ERROR
    if args.batch and args.keystore:
        ui.err("--batch cannot be combined with -k/--keystore")
        return EXIT_ERROR

    # ---- inspect: validate + full structural report, no guessing -----------
    if args.inspect:
        if not args.keystore:
            ui.err("--inspect needs -k/--keystore FILE")
            return EXIT_ERROR
        try:
            ks = load_keystore(args.keystore)
        except KeystoreError as exc:
            ui.err(str(exc))
            return EXIT_ERROR
        report = inspect_keystore(ks, args.keystore)
        if args.json_output:
            print(json.dumps(report, ensure_ascii=False))
            return 0
        ui.head("inspect: %s" % args.keystore)
        ui.info("format: %s (version %s)" % (report["format"], report["version"]))
        if report.get("name"):
            ui.info("wallet name: %r" % report["name"])
        if report.get("type"):
            ui.info("type: %s" % report["type"])
        for acct in report["accounts"]:
            extra = "  (coin %s, %s)" % (acct["coin"], acct["derivation_path"]) \
                if acct.get("coin") is not None else ""
            ui.info("account: %s%s" % (acct["address"], extra))
        if report["kdf"] == "scrypt":
            ui.info("kdf: scrypt n=%d r=%d p=%d dklen=%d"
                    % (report["scrypt_n"], report["scrypt_r"],
                       report["scrypt_p"], report["dklen"]))
        else:
            ui.info("kdf: pbkdf2-hmac-sha256 c=%d dklen=%d"
                    % (report["pbkdf2_c"], report["dklen"]))
        ui.info("cipher: %s (iv %d B) | mac %d B | ciphertext %d B | salt %d B"
                % (report["cipher"], report["iv_bytes"], report["mac_bytes"],
                   report["ciphertext_bytes"], report["salt_bytes"]))
        if report["salt_bytes"] == 0:
            ui.warn("legacy backup: the salt is EMPTY (common in older Trust "
                    "Wallet cloud backups) - twrecover handles this natively")
        if report["hashcat_loadable"]:
            ui.ok("hashcat: loadable (mode %d) - export with --export-hashcat"
                  % report["hashcat_mode"])
        else:
            ui.warn("hashcat: NOT loadable - %s" % "; ".join(report["hashcat_reasons"]))
            ui.info("hashcat: recover this backup with twrecover instead "
                    "(CPU mode; see --benchmark)")
        ui.ok("verdict: fully recoverable by twrecover")
        ui.info("Made by %s \u2014 %s" % (BRAND, BRAND_URL))
        return 0

    # ---- verify / decrypt: check specific passwords, no attack loop --------
    if args.verify_password or args.decrypt_password:
        if not args.keystore:
            ui.err("--verify-password/--decrypt-password need -k/--keystore FILE")
            return EXIT_ERROR
        try:
            ks = load_keystore(args.keystore)
        except KeystoreError as exc:
            ui.err(str(exc))
            return EXIT_ERROR
        any_ok = False
        for pw in args.verify_password:
            ok = _try_password(ks, pw)
            any_ok = any_ok or ok
            if args.json_output:
                print(json.dumps({"password": pw, "correct": ok,
                                  "keystore": args.keystore, "by": BRAND_LINE},
                                 ensure_ascii=False))
            elif ok:
                ui.ok("password %r is CORRECT (MAC verified)" % pw)
            else:
                ui.err("password %r is incorrect" % pw)
        for pw in args.decrypt_password:
            if not _try_password(ks, pw):
                if args.json_output:
                    print(json.dumps({"password": pw, "correct": False,
                                      "keystore": args.keystore, "by": BRAND_LINE},
                                     ensure_ascii=False))
                else:
                    ui.err("password %r is incorrect" % pw)
                continue
            any_ok = True
            ui.ok("password %r is CORRECT (MAC verified) - decrypting..." % pw)
            extra = _inspect_and_report(ks, pw, args, ui)
            if args.json_output:
                result = {"password": pw, "correct": True,
                          "keystore": args.keystore, "by": BRAND_LINE}
                result.update(extra)
                print(json.dumps(result, ensure_ascii=False))
            else:
                print("Password: %s" % pw)
        return EXIT_FOUND if any_ok else EXIT_NOT_FOUND

    # ---- single-file export / benchmark modes -------------------------------
    if not args.batch:
        try:
            ks = load_keystore(args.keystore)
        except KeystoreError as exc:
            ui.err(str(exc))
            return EXIT_ERROR
        if args.export_hashcat:
            line = hashcat_line(ks)
            if args.export_hashcat == "-":
                print(line)
            else:
                with open(args.export_hashcat, "w") as fh:
                    fh.write(line + "\n")
            ui.ok("hashcat line written (mode %d - %s)" % (
                hashcat_mode(ks),
                "Ethereum Wallet, SCRYPT" if ks["kdf"] == "scrypt"
                else "Ethereum Wallet, PBKDF2-HMAC-SHA256"))
            hc_ok, hc_reasons = hashcat_compatible(ks)
            if not hc_ok:
                ui.warn("hashcat will NOT load this line: %s"
                        % "; ".join(hc_reasons))
            return 0
        if args.benchmark:
            per = _time_one_attempt(ks)
            single = 1.0 / per if per else 0.0
            ui.head("benchmark")
            ui.info("keystore: %s" % keystore_summary(ks))
            ui.info("one attempt: %.1f ms  ->  %.0f candidates/s on one core"
                    % (per * 1000, single))
            ui.info("all %d cores: ~%.0f candidates/s (theoretical)"
                        % (threads, single * threads))
            if ks["kdf"] == "scrypt":
                mem = ks["n"] * ks["r"] * 128
                ui.info("scrypt memory: ~%s per worker, ~%s total for %d workers"
                            % (_fmt_bytes(mem), _fmt_bytes(mem * threads), threads))
            ui.info("Made by %s \u2014 %s" % (BRAND, BRAND_URL))
            return 0

    # ---- assemble password sources (shared by single-file and batch) -------
    sources, total = _assemble_sources(args, ui)
    if sources is None:
        return EXIT_ERROR

    # ---- batch: recover every .json in a directory --------------------------
    if args.batch:
        if not os.path.isdir(args.batch):
            ui.err("--batch: not a directory: %s" % args.batch)
            return EXIT_ERROR
        files = sorted(f for f in os.listdir(args.batch) if f.lower().endswith(".json"))
        if not files:
            ui.err("--batch: no .json files in %s" % args.batch)
            return EXIT_ERROR
        ui.head("batch: %d backup file(s) in %s" % (len(files), args.batch))
        scanned = 0
        found_count = 0
        for fname in files:
            path = os.path.join(args.batch, fname)
            try:
                ks = load_keystore(path)
            except KeystoreError as exc:
                ui.warn("skipping %s: %s" % (fname, exc))
                continue
            scanned += 1
            code, found = _scan_keystore(ks, path, sources, total, args, ui,
                                         threads, auto_confirm=scanned > 1)
            if code == EXIT_INTERRUPTED:
                return code
            if found:
                found_count += 1
        ui.head("batch done: %d of %d file(s) recovered"
                % (found_count, scanned))
        ui.info("Made by %s \u2014 %s" % (BRAND, BRAND_URL))
        return EXIT_FOUND if found_count else (EXIT_NOT_FOUND if scanned else EXIT_ERROR)

    # ---- single-file recovery ------------------------------------------------
    return _scan_keystore(ks, args.keystore, sources, total, args, ui, threads,
                          auto_confirm=False)[0]


if __name__ == "__main__":
    sys.exit(main())
