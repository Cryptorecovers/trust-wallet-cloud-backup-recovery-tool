#!/usr/bin/env python3
"""
Generate the test fixture keystores (tests/fixtures/*.json).

The fixtures are built with raw PyCryptodome primitives - independent of
twrecover's own implementation - so the test suite validates the tool
against an external oracle. Re-run this script to regenerate them; the
expected values are recorded in fixtures/metadata.json.

Usage:  python tests/make_fixtures.py
"""

import hashlib
import hmac
import json
import os
import uuid

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, keccak
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Util import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


def keccak256(data):
    return keccak.new(digest_bits=256, data=data).digest()


def build_keystore(password, privkey_bytes, kdf, n_or_c, r=8, p=1):
    """Build a keystore v3 document (independent of twrecover)."""
    salt = os.urandom(32)
    iv = os.urandom(16)
    if kdf == "scrypt":
        derived = scrypt(password.encode("utf-8"), salt, 32, n_or_c, r, p)
        kdfparams = {"dklen": 32, "n": n_or_c, "r": r, "p": p, "salt": salt.hex()}
    else:
        # NB: pycryptodome's PBKDF2 defaults to HMAC-SHA1; keystore v3
        # requires hmac-sha256 (which is what twrecover implements).
        derived = PBKDF2(password.encode("utf-8"), salt, 32, count=n_or_c,
                         hmac_hash_module=SHA256)
        kdfparams = {"dklen": 32, "c": n_or_c, "prf": "hmac-sha256", "salt": salt.hex()}
    key = derived[:16]
    ciphertext = AES.new(key, AES.MODE_CTR,
                         counter=Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                         ).encrypt(privkey_bytes)
    mac = keccak256(derived[16:32] + ciphertext)
    x, y = _pubkey(privkey_bytes)
    address = "0x" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:].hex()
    doc = {
        "version": 3,
        "id": str(uuid.uuid4()),
        "address": address,
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": iv.hex()},
            "cipher": "aes-128-ctr",
            "kdf": kdf,
            "kdfparams": kdfparams,
            "mac": mac.hex(),
        },
    }
    return doc


_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    m = ((3 * x1 * x1) * pow(2 * y1, _P - 2, _P) if p1 == p2
         else (y2 - y1) * pow(x2 - x1, _P - 2, _P)) % _P
    x3 = (m * m - x1 - x2) % _P
    return (x3, (m * (x1 - x3) - y1) % _P)


def _pubkey(priv):
    k = int.from_bytes(priv, "big")
    res, add = None, _G
    while k:
        if k & 1:
            res = _add(res, add)
        add = _add(add, add)
        k >>= 1
    return res


# ---------------------------------------------------------------------------
# Trust Wallet cloud backup (StoredKey) fixtures
#
# Faithful to trustwallet/wallet-core src/Keystore: top level type/'mnemonic'
# + name + id + activeAccounts, crypto envelope with keystore-v3 fields, and
# the real scrypt presets (weak: n=2^14 r=8 p=4, standard: n=2^18 r=8 p=1).
# The Ethereum account is derived with BIP39 + BIP32 m/44'/60'/0'/0/0.
# ---------------------------------------------------------------------------


# The well-known BIP39 test-vector mnemonic; its Ethereum address at
# m/44'/60'/0'/0/0 (0x9858EfFD...) is published in many official test suites.
VECTOR_MNEMONIC = "abandon abandon abandon abandon abandon abandon " \
                  "abandon abandon abandon abandon abandon about"


def _mnemonic_seed(phrase, passphrase=""):
    """BIP39 seed derivation (PBKDF2-HMAC-SHA512, 2048 iterations)."""
    return hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"),
                               ("mnemonic" + passphrase).encode("utf-8"), 2048,
                               dklen=64)


def _bip32_privkey(seed, path=(
        44 + 0x80000000, 60 + 0x80000000, 0x80000000, 0, 0)):
    """BIP32: walk the hardened/normal path and return the private key."""
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(i[:32], "big")
    chain = i[32:]
    for index in path:
        if index >= 0x80000000:
            data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:
            x, y = _pubkey(key.to_bytes(32, "big"))
            pub = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
            data = pub + index.to_bytes(4, "big")
        i = hmac.new(chain, data, hashlib.sha512).digest()
        key = (int.from_bytes(i[:32], "big") + key) % _N
        chain = i[32:]
    return key.to_bytes(32, "big")


def _checksummed_address(lower_hex):
    """EIP-55 checksum (as the Trust Wallet app writes account addresses)."""
    lower = lower_hex[2:] if lower_hex.startswith("0x") else lower_hex
    h = keccak.new(digest_bits=256, data=lower.encode("ascii")).digest()
    out = []
    for i, ch in enumerate(lower):
        if ch in "0123456789abcdef" and (h[i // 2] >> (4 * (1 - i % 2))) & 0xF >= 8:
            out.append(ch.upper())
        else:
            out.append(ch)
    return "0x" + "".join(out)


def build_trust_backup(password, mnemonic, scrypt_n, scrypt_r=8, scrypt_p=4,
                       name="Trust Wallet", salt=None, omit_salt=False):
    """Build a Trust Wallet iCloud/Google Drive-style backup document.

    Like the app (via wallet-core), the AES-CTR plaintext is the UTF-8
    recovery phrase, the MAC is keccak(derived[16:32] || ciphertext), and
    the top level carries StoredKey metadata plus the wallet's accounts.

    salt:      override the salt (b"" reproduces the LEGACY empty-salt
               backups seen in the wild, e.g. the hashcat forum example)
    omit_salt: drop the "salt" key entirely (wallet-core accepts that and
               falls back to an empty salt)
    """
    if omit_salt:
        salt = b""  # encryption must use the same empty salt the file implies
    elif salt is None:
        salt = os.urandom(32)
    iv = os.urandom(16)
    phrase_bytes = mnemonic.encode("utf-8")
    derived = scrypt(password.encode("utf-8"), salt, 32, scrypt_n, scrypt_r, scrypt_p)
    key = derived[:16]
    ciphertext = AES.new(key, AES.MODE_CTR,
                         counter=Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                         ).encrypt(phrase_bytes)
    mac = keccak256(derived[16:32] + ciphertext)

    privkey = _bip32_privkey(_mnemonic_seed(mnemonic))
    x, y = _pubkey(privkey)
    pub_bytes = bytes([4]) + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    # NB: the Ethereum address hashes x||y WITHOUT the 0x04 SEC1 prefix.
    address = _checksummed_address("0x" + keccak256(pub_bytes[1:])[12:].hex())

    kdfparams = {"dklen": 32, "n": scrypt_n, "r": scrypt_r, "p": scrypt_p}
    if not omit_salt:
        kdfparams["salt"] = salt.hex()
    doc = {
        "version": 3,
        "type": "mnemonic",
        "id": str(uuid.uuid4()),
        "name": name,
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": iv.hex()},
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": kdfparams,
            "mac": mac.hex(),
        },
        "activeAccounts": [
            {
                "address": address,
                "derivationPath": "m/44'/60'/0'/0/0",
                "coin": 60,
                "publicKey": pub_bytes.hex(),
            }
        ],
    }
    return doc


def main():
    if not os.path.isdir(FIXTURES):
        os.makedirs(FIXTURES)

    fixtures = [
        # (filename, password, privkey, kdf, kdf-param)
        ("scrypt_keystore.json", "sunflower", (1).to_bytes(32, "big"),
         "scrypt", 1024),
        ("scrypt_digits_keystore.json", "sunflower42", (2).to_bytes(32, "big"),
         "scrypt", 1024),
        ("pbkdf2_keystore.json", "monkey!2025", (3).to_bytes(32, "big"),
         "pbkdf2", 100000),
        ("empty_pass_keystore.json", "", (4).to_bytes(32, "big"),
         "scrypt", 1024),
        # brute-force fixture: 'sun' sits at a low index in alphabet
        # "sunflower" (length 1..3), so brute-force tests complete fast
        ("brute_keystore.json", "sun", (5).to_bytes(32, "big"),
         "scrypt", 1024),
        # typo fixture: 'sunflwer' is 'sunflower' with the 'o' deleted
        # (bt-recovery-style typo, recovered via -r typos)
        ("typo_keystore.json", "sunflwer", (6).to_bytes(32, "big"),
         "scrypt", 1024),
    ]
    metadata = {}
    for name, pw, priv, kdf, param in fixtures:
        doc = build_keystore(pw, priv, kdf, param)
        path = os.path.join(FIXTURES, name)
        with open(path, "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        metadata[name] = {"password": pw, "kdf": kdf, "param": param,
                          "address": doc["address"],
                          "privkey": priv.hex()}
        print("wrote %s (kdf=%s, param=%s, address=%s)"
              % (name, kdf, param, doc["address"]))

    # Trust Wallet cloud-backup style fixtures (real StoredKey format).
    # The weak preset (2^14/8/4) is what the app uses by default; the
    # standard preset (2^18/8/1, ~256 MB) is the strong one used for
    # iCloud/Google Drive "encrypted backup". Both are wallet-core presets.
    backups = [
        ("trust_backup_weak.json", "sunflwer", 16384, 8, 4, {}),
        ("trust_backup_standard.json", "sunflowers", 262144, 8, 1, {}),
        # exact structure of the widely-shared legacy example (hashcat
        # forum thread 11545, 2023): empty salt, n=16384 r=8 p=4
        ("trust_backup_legacy_emptysalt.json", "sunflower42", 16384, 8, 4,
         {"salt": b""}),
        # same, but with the "salt" key missing entirely (also accepted
        # by wallet-core, which falls back to an empty salt)
        ("trust_backup_legacy_nosalt.json", "sunflower42", 16384, 8, 4,
         {"omit_salt": True}),
    ]
    for name, pw, n, r, p, kw in backups:
        doc = build_trust_backup(pw, VECTOR_MNEMONIC, n, r, p, **kw)
        path = os.path.join(FIXTURES, name)
        with open(path, "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        metadata[name] = {"password": pw, "kdf": "scrypt",
                          "param": n, "mnemonic": VECTOR_MNEMONIC,
                          "address": doc["activeAccounts"][0]["address"]}
        print("wrote %s (scrypt n=%d r=%d p=%d, address=%s)"
              % (name, n, r, p, doc["activeAccounts"][0]["address"]))

    meta_path = os.path.join(FIXTURES, "metadata.json")
    with open(meta_path, "w") as fh:
        json.dump(metadata, fh, indent=2)
        fh.write("\n")
    print("wrote metadata.json")


if __name__ == "__main__":
    main()