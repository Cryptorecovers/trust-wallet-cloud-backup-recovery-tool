#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test suite for twrecover.

Run with:  python -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import twrecover as t  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

try:
    from Crypto.Hash import keccak as _ck
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def fixture_path(name):
    return os.path.join(FIXTURES, name)


def load_metadata():
    with open(fixture_path("metadata.json")) as fh:
        return json.load(fh)


META = load_metadata()


def run_cli(args):
    """Run main() capturing stdout/stderr; returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = t.main(args)
        except SystemExit as exc:
            code = exc.code if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


class TestKeccak(unittest.TestCase):
    VECTORS = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"hello world": "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
        b"The quick brown fox jumps over the lazy dog":
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    }

    def test_pure_python_known_vectors(self):
        for data, expected in self.VECTORS.items():
            self.assertEqual(t._keccak256(data).hex(), expected)

    def test_module_keccak_matches_pure(self):
        import os as _os
        for _ in range(20):
            data = _os.urandom(_os.urandom(1)[0] * 100 + 1)
            self.assertEqual(t.keccak256(data), t._keccak256(data))

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_pure_matches_pycryptodome(self):
        import os as _os
        for _ in range(20):
            data = _os.urandom(_os.urandom(1)[0] * 100 + 1)
            expected = _ck.new(digest_bits=256, data=data).digest()
            self.assertEqual(t._keccak256(data), expected)


class TestSecp256k1(unittest.TestCase):
    def test_known_addresses(self):
        # Well-known Ethereum accounts #1 and #2
        self.assertEqual(
            t._ethereum_address((1).to_bytes(32, "big")),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
        self.assertEqual(
            t._ethereum_address((2).to_bytes(32, "big")),
            "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf")

    def test_fixture_addresses_match(self):
        for name, meta in META.items():
            if "privkey" not in meta:  # mnemonic backups have no raw key
                continue
            ks = t.load_keystore(fixture_path(name))
            self.assertEqual(
                t._ethereum_address(bytes.fromhex(meta["privkey"])),
                "0x" + t._normalize_address(ks["address"]))

    def test_invalid_key(self):
        self.assertIsNone(t._ethereum_address(b"\x00" * 32))


class TestKeystore(unittest.TestCase):
    def test_load_scrypt(self):
        ks = t.load_keystore(fixture_path("scrypt_keystore.json"))
        self.assertEqual(ks["kdf"], "scrypt")
        self.assertEqual(ks["n"], 1024)
        self.assertEqual(ks["cipher"], "aes-128-ctr")
        self.assertEqual(len(ks["salt"]), 32)
        self.assertEqual(len(ks["ciphertext"]), 32)

    def test_load_pbkdf2(self):
        ks = t.load_keystore(fixture_path("pbkdf2_keystore.json"))
        self.assertEqual(ks["kdf"], "pbkdf2")
        self.assertEqual(ks["c"], 100000)

    def test_mac_correct_password(self):
        for name, meta in META.items():
            ks = t.load_keystore(fixture_path(name))
            self.assertTrue(t._try_password(ks, meta["password"]), name)

    def test_mac_wrong_password(self):
        ks = t.load_keystore(fixture_path("scrypt_keystore.json"))
        for pw in ("wrong", "sunflower1", "Sunflower", "sunflower "):
            self.assertFalse(t._try_password(ks, pw), pw)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_decrypt_roundtrip(self):
        for name, meta in META.items():
            if "privkey" not in meta:  # mnemonic backups are covered by TestTrustBackup
                continue
            ks = t.load_keystore(fixture_path(name))
            pt = t.decrypt(ks, meta["password"])
            self.assertEqual(pt.hex(), meta["privkey"], name)
            self.assertEqual(t.describe_plaintext(pt), "private-key")

    def test_unencrypted_file_detected(self):
        doc = {"version": 3, "address": "0xabc",
               "privateKey": "0x" + "11" * 32}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(doc, fh)
            path = fh.name
        try:
            with self.assertRaises(t.KeystoreError) as ctx:
                t.load_keystore(path)
            self.assertIn("NOT encrypted", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            with self.assertRaises(t.KeystoreError):
                t.load_keystore(path)
        finally:
            os.unlink(path)

    def test_unsupported_kdf(self):
        ks = t.load_keystore(fixture_path("scrypt_keystore.json"))
        ks["kdf"] = "argon2"
        with self.assertRaises(t.KeystoreError):
            t.derive_key(ks, "x")


class TestSources(unittest.TestCase):
    def test_rule_counts_word_independent(self):
        words = ("sunflower", "", "ABC", "123")
        for rs in ("none", "basic", "medium", "full", "leet"):
            counts = {w: len(t._candidates_for(w, rs)) for w in words}
            self.assertEqual(len(set(counts.values())), 1, rs)

    def test_typos_counts_scale_with_length(self):
        for w in ("a", "sunflower", "", "x" * 20):
            n = len(w)
            expected = 1 + 3 * n + max(n - 1, 0)
            self.assertEqual(len(t._candidates_for(w, "typos")), expected, w)
        self.assertEqual(t._candidates_for("", "typos"), [""])

    def test_typos_cover_expected_variants(self):
        cands = t._candidates_for("sunflower", "typos")
        self.assertEqual(cands[0], "sunflower")
        for expected in ("sunflwer",     # deleted 'o'
                         "sunflowerr",   # doubled 'r'
                         "usnflower",    # swapped 'su'
                         "sunflowers"):  # inserted 's'
            self.assertIn(expected, cands, expected)

    def test_rules_cover_expected_candidates(self):
        cands = t._candidates_for("sunflower", "basic")
        for expected in ("sunflower", "Sunflower", "SUNFLOWER", "sunflower42",
                         "sunflower2024", "Sunflower2025", "sunflower!",
                         "sunflower1", "sunflowersunflower"):
            self.assertIn(expected, cands, expected)
        medium = t._candidates_for("password", "medium")
        for expected in ("p455w0rd", "P455w0rd", "p455w0rd7"):
            self.assertIn(expected, medium, expected)

    def test_wordlist_index_math(self):
        for ruleset in ("basic", "typos"):
            words = ["alpha", "b", "gamma"]
            src = t.WordlistSource(words, ruleset)
            expected = [c for w in words
                        for c in t._candidates_for(w, ruleset)]
            self.assertEqual(src.total, len(expected), ruleset)
            for i in range(src.total):
                self.assertEqual(src.at(i), expected[i], (ruleset, i))

    def test_wordlist_scan_matches_at(self):
        words = ["alpha", "b", "gamma", "delta"]
        for ruleset in ("basic", "typos"):
            src = t.WordlistSource(words, ruleset)
            expected = [src.at(i) for i in range(src.total)]
            ks = t.load_keystore(fixture_path("scrypt_keystore.json"))
            # scan a mid-range chunk and record candidates tried via a stub
            seen = []
            orig = t._try_password
            try:
                def spy(ks_, pw):
                    seen.append(pw)
                    return orig(ks_, pw)
                t._try_password = spy
                src.scan(ks, 5, 13)
            finally:
                t._try_password = orig
            self.assertEqual(seen, expected[5:13], ruleset)

    def test_brute_total_and_at(self):
        src = t.BruteSource("ab3", 1, 3)
        self.assertEqual(src.total, 3 + 9 + 27)
        self.assertEqual(src.at(0), "a")
        self.assertEqual(src.at(2), "3")
        self.assertEqual(src.at(3), "aa")
        self.assertEqual(src.at(8), "b3")
        self.assertEqual(src.at(9), "3a")
        self.assertEqual(src.at(38), "333")
        seen = {src.at(i) for i in range(src.total)}
        self.assertEqual(len(seen), src.total)

    def test_brute_single_length(self):
        src = t.BruteSource("ab", 4, 4)
        self.assertEqual(src.total, 16)
        self.assertEqual(len(src.at(0)), 4)


class TestEngine(unittest.TestCase):
    def _ks(self, name="scrypt_keystore.json"):
        return t.load_keystore(fixture_path(name))

    def test_serial_attack_finds(self):
        ks = self._ks()
        src = t.DirectSource(["nope", "maybe", "sunflower"])
        found, attempts, _ = t.run_attack(ks, src, threads=1)
        self.assertEqual(found, "sunflower")
        self.assertEqual(attempts, 3)

    def test_parallel_attack_finds(self):
        ks = self._ks()
        src = t.DirectSource(["nope", "maybe", "sunflower", "later"])
        found, attempts, _ = t.run_attack(ks, src, threads=2)
        self.assertEqual(found, "sunflower")
        self.assertLessEqual(attempts, 4)

    def test_wordlist_rule_attack_finds_digit_suffix(self):
        ks = t.load_keystore(fixture_path("scrypt_digits_keystore.json"))
        src = t.WordlistSource(["sunflower"], "basic")
        found, attempts, _ = t.run_attack(ks, src, threads=1)
        self.assertEqual(found, "sunflower42")

    def test_typos_attack_finds_deleted_char(self):
        ks = t.load_keystore(fixture_path("typo_keystore.json"))
        src = t.WordlistSource(["sunflower"], "typos")
        # threads=1: parallel workers may be mid-candidate when the winner
        # is reported, making the attempt count timing-dependent.
        found, attempts, _ = t.run_attack(ks, src, threads=1)
        self.assertEqual(found, "sunflwer")
        self.assertEqual(attempts, 17)  # identity + 3 variants per char, then delete 'o'

    def test_brute_attack_finds(self):
        ks = t.load_keystore(fixture_path("brute_keystore.json"))
        src = t.BruteSource("sunflower", 1, 3)
        found, attempts, _ = t.run_attack(ks, src, threads=1)
        self.assertEqual(found, "sun")
        self.assertLess(attempts, 200)  # 'sun' is index ~101 in this space

    def test_not_found(self):
        ks = self._ks()
        src = t.DirectSource(["wrong", "passwords"])
        found, attempts, _ = t.run_attack(ks, src, threads=2)
        self.assertIsNone(found)
        self.assertEqual(attempts, 2)

    def test_limit(self):
        ks = self._ks()
        src = t.DirectSource(["a", "b", "sunflower", "c"])
        found, attempts, _ = t.run_attack(ks, src, threads=1, limit=2)
        self.assertIsNone(found)
        self.assertEqual(attempts, 2)

    def test_empty_password(self):
        ks = t.load_keystore(fixture_path("empty_pass_keystore.json"))
        found, _, _ = t.run_attack(ks, t.DirectSource([""]), threads=1)
        self.assertEqual(found, "")


class TestTrustBackup(unittest.TestCase):
    """Trust Wallet cloud-backup (StoredKey) support: BIP39/BIP44
    derivation is pinned against published spec vectors, and the backup
    fixtures (generated in the exact wallet-core format) must recover."""

    VECTOR_MNEMONIC = ("abandon abandon abandon abandon abandon abandon "
                       "abandon abandon abandon abandon abandon about")
    # Published in official test suites: first Ethereum address of the
    # VECTOR_MNEMONIC at m/44'/60'/0'/0/0.
    VECTOR_ADDRESS = "9858effd232b4033e47d90003d41ec34ecaeda94"
    BIP32_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_bip39_seed_spec_vector(self):
        seed = t._mnemonic_to_seed(self.VECTOR_MNEMONIC)
        self.assertEqual(
            seed.hex(),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19"
            "a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

    def test_bip32_master_key_spec_vector(self):
        i = t.hmac.new(b"Bitcoin seed", self.BIP32_SEED, t.hashlib.sha512).digest()
        self.assertEqual(
            i[:32].hex(),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")

    def test_known_ethereum_address(self):
        addr = t.mnemonic_eth_address(self.VECTOR_MNEMONIC)
        self.assertEqual(addr, "0x" + self.VECTOR_ADDRESS)

    def test_fixture_account_is_known_vector(self):
        meta = META["trust_backup_weak.json"]
        self.assertEqual(meta["address"].lower(), "0x" + self.VECTOR_ADDRESS)

    def test_load_trust_backup_metadata(self):
        ks = t.load_keystore(fixture_path("trust_backup_weak.json"))
        self.assertEqual(ks["type"], "mnemonic")
        self.assertEqual(ks["name"], "Trust Wallet")
        self.assertEqual(ks["active_accounts"][0]["coin"], 60)
        self.assertEqual(ks["kdf"], "scrypt")
        self.assertEqual(ks["n"], 16384)
        summary = t.keystore_summary(ks)
        self.assertIn("type=mnemonic", summary)
        self.assertIn("name='Trust Wallet'", summary)
        self.assertIn("address=0x", summary)

    def test_recover_mnemonic_backup_via_typos(self):
        ks = t.load_keystore(fixture_path("trust_backup_weak.json"))
        src = t.WordlistSource(["sunflower"], "typos")
        # threads=1 keeps the attempt count deterministic (parallel workers may
        # be mid-candidate when the winner is reported).
        found, attempts, _ = t.run_attack(ks, src, threads=1)
        self.assertEqual(found, "sunflwer")
        self.assertEqual(attempts, 17)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_cli_recovery_reports_phrase_and_address_match(self):
        code, out, err = run_cli([
            "-k", fixture_path("trust_backup_weak.json"),
            "-p", "sunflwer"])
        self.assertEqual(code, 0)
        self.assertIn("decrypted payload: mnemonic", err)
        self.assertIn("derived address: 0x" + self.VECTOR_ADDRESS, err)
        self.assertIn("(match)", err)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_show_secrets_prints_recovery_phrase(self):
        code, out, _ = run_cli([
            "-k", fixture_path("trust_backup_weak.json"),
            "-p", "sunflwer", "--show-secrets"])
        self.assertEqual(code, 0)
        self.assertIn("recovery phrase: " + self.VECTOR_MNEMONIC, out)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_export_decrypted_writes_phrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "phrase.txt")
            code, _, _ = run_cli([
                "-k", fixture_path("trust_backup_weak.json"),
                "-p", "sunflwer", "--export-decrypted", out_path])
            self.assertEqual(code, 0)
            with open(out_path) as fh:
                self.assertEqual(fh.read().strip(), self.VECTOR_MNEMONIC)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_json_output_reports_mnemonic_kind(self):
        code, out, _ = run_cli([
            "-k", fixture_path("trust_backup_weak.json"),
            "-p", "sunflwer", "--json-output"])
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(result["plaintext_kind"], "mnemonic")
        self.assertTrue(result["address_match"])

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_standard_preset_backup_mac(self):
        """The real iCloud/Drive preset (n=262144 r=8 p=1) must validate."""
        ks = t.load_keystore(fixture_path("trust_backup_standard.json"))
        self.assertTrue(t._try_password(ks, "sunflowers"))
        self.assertFalse(t._try_password(ks, "wrong-password"))


class TestCLI(unittest.TestCase):
    def test_found_exit_zero(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "sunflower"])
        self.assertEqual(code, 0)
        self.assertIn("Password: sunflower", out)

    def test_wrong_password_exit_one(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "nope"])
        self.assertEqual(code, 1)
        self.assertNotIn("Password:", out)

    def test_wordlist_attack(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("wrong\nguess\nsunflower\n")
            wl = fh.name
        try:
            code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                    "-l", wl, "-r", "none"])
            self.assertEqual(code, 0)
            self.assertIn("Password: sunflower", out)
        finally:
            os.unlink(wl)

    def test_brute_cli(self):
        code, out, _ = run_cli(["-k", fixture_path("brute_keystore.json"),
                                "-a", "sunflower", "--min-length", "1",
                                "--max-length", "3", "--yes"])
        self.assertEqual(code, 0)
        self.assertIn("Password: sun", out)

    def test_quiet_still_prints_password(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "sunflower", "-q"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "Password: sunflower")

    def test_json_output(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "sunflower", "--json-output"])
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertTrue(result["found"])
        self.assertEqual(result["password"], "sunflower")
        self.assertGreater(result["attempts"], 0)

    def test_json_output_not_found(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "nope", "--json-output"])
        self.assertEqual(code, 1)
        result = json.loads(out)
        self.assertFalse(result["found"])

    def test_export_decrypted(self):
        meta = META["scrypt_keystore.json"]
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "decrypted.key")
            code, _, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                  "-p", "sunflower",
                                  "--export-decrypted", out_path])
            self.assertEqual(code, 0)
            with open(out_path) as fh:
                content = fh.read()
            self.assertIn(meta["privkey"], content)

    def test_show_secrets(self):
        meta = META["scrypt_keystore.json"]
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "sunflower", "--show-secrets"])
        self.assertEqual(code, 0)
        self.assertIn(meta["privkey"], out)

    def test_verify_address(self):
        meta = META["scrypt_keystore.json"]
        code, _, err = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "sunflower",
                                "--verify-address", meta["address"]])
        self.assertEqual(code, 0)
        self.assertIn("match", err)

    def test_missing_file_exit_two(self):
        code, _, err = run_cli(["-k", "/nonexistent/wallet.json", "-p", "x"])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_unencrypted_exit_two(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"privateKey": "0x" + "11" * 32}, fh)
            path = fh.name
        try:
            code, _, err = run_cli(["-k", path, "-p", "x"])
            self.assertEqual(code, 2)
            self.assertIn("NOT encrypted", err)
        finally:
            os.unlink(path)

    def test_no_source_exit_two(self):
        code, _, _ = run_cli(["-k", fixture_path("scrypt_keystore.json")])
        self.assertEqual(code, 2)

    def test_empty_password_flag(self):
        code, out, _ = run_cli(["-k", fixture_path("empty_pass_keystore.json"),
                                "--check-empty", "--yes"])
        self.assertEqual(code, 0)
        self.assertIn("Password: ", out)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_pbkdf2_cli(self):
        code, out, _ = run_cli(["-k", fixture_path("pbkdf2_keystore.json"),
                                "-p", "monkey!2025"])
        self.assertEqual(code, 0)
        self.assertIn("Password: monkey!2025", out)

    def test_version_shows_brand(self):
        code, out, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(t.BRAND, out)
        self.assertIn(t.BRAND_URL, out)

    def test_success_shows_brand(self):
        code, _, err = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "-p", "sunflower"])
        self.assertEqual(code, 0)
        self.assertIn("Crypto Recovers", err)

    def test_export_hashcat_scrypt(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "--export-hashcat", "-"])
        self.assertEqual(code, 0)
        line = out.strip()
        self.assertTrue(line.startswith("$ethereum$s*"), line)
        fields = line.split("*")
        # $ethereum$s, N, r, p, salt, ciphertext, mac
        self.assertEqual(len(fields), 7)
        self.assertEqual(fields[1], "1024")
        self.assertEqual(fields[2], "8")
        self.assertEqual(fields[3], "1")
        self.assertEqual(len(fields[4]), 64)
        self.assertEqual(len(fields[5]), 64)
        self.assertEqual(len(fields[6]), 64)

    def test_export_hashcat_pbkdf2(self):
        code, out, _ = run_cli(["-k", fixture_path("pbkdf2_keystore.json"),
                                "--export-hashcat", "-"])
        self.assertEqual(code, 0)
        fields = out.strip().split("*")
        self.assertEqual(fields[0], "$ethereum$p")
        self.assertEqual(fields[1], "100000")
        self.assertEqual(len(fields[2]), 64)
        self.assertEqual(len(fields), 5)

    def test_export_hashcat_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "wallet.15700")
            code, _, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                  "--export-hashcat", out_path])
            self.assertEqual(code, 0)
            with open(out_path) as fh:
                self.assertTrue(fh.read().strip().startswith("$ethereum$s*"))

    def test_benchmark(self):
        code, _, err = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "--benchmark"])
        self.assertEqual(code, 0)
        self.assertIn("one attempt", err)
        self.assertIn("candidates/s", err)

    def test_typos_cli(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("sunflower\n")
            wl = fh.name
        try:
            code, out, _ = run_cli(["-k", fixture_path("typo_keystore.json"),
                                    "-l", wl, "-r", "typos", "--yes"])
            self.assertEqual(code, 0)
            self.assertIn("Password: sunflwer", out)
        finally:
            os.unlink(wl)

    def test_hashcat_export_matches_keystore_fields(self):
        ks = t.load_keystore(fixture_path("scrypt_keystore.json"))
        line = t.hashcat_line(ks)
        fields = line.split("*")
        self.assertEqual(fields[4], ks["salt"].hex())
        self.assertEqual(fields[5], ks["ciphertext"].hex())
        self.assertEqual(fields[6], ks["mac"].hex())


class TestSuiteAdditions(unittest.TestCase):
    """v1.4 suite: --inspect / --verify-password / --decrypt-password /
    --batch modes and the legacy empty-salt backups from the wild."""

    def test_inspect_modern_backup_hashcat_loadable(self):
        code, out, err = run_cli(["-k", fixture_path("trust_backup_weak.json"),
                                  "--inspect", "--json-output"])
        self.assertEqual(code, 0)
        r = json.loads(out)
        self.assertEqual(r["format"], "Trust Wallet StoredKey (cloud backup)")
        self.assertEqual(r["type"], "mnemonic")
        self.assertEqual(r["salt_bytes"], 32)
        self.assertTrue(r["hashcat_loadable"])
        self.assertEqual(r["hashcat_mode"], 15700)

    def test_inspect_legacy_empty_salt_flagged(self):
        code, out, err = run_cli(["-k",
                                  fixture_path("trust_backup_legacy_emptysalt.json"),
                                  "--inspect", "--json-output"])
        self.assertEqual(code, 0)
        r = json.loads(out)
        self.assertEqual(r["salt_bytes"], 0)
        self.assertFalse(r["hashcat_loadable"])
        self.assertTrue(any("32-byte salt" in x for x in r["hashcat_reasons"]))
        self.assertTrue(r["recoverable"])

    def test_inspect_missing_salt_key_also_ok(self):
        code, out, _ = run_cli(["-k",
                                fixture_path("trust_backup_legacy_nosalt.json"),
                                "--inspect", "--json-output"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["salt_bytes"], 0)

    def test_verify_password_correct_and_wrong(self):
        code, out, err = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                  "--verify-password", "wrong",
                                  "--verify-password", "sunflower"])
        self.assertEqual(code, 0)
        self.assertIn("'sunflower' is CORRECT", err)
        self.assertIn("'wrong' is incorrect", err)

    def test_verify_password_all_wrong_exit_one(self):
        code, _, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                              "--verify-password", "nope"])
        self.assertEqual(code, 1)

    def test_verify_password_json(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "--verify-password", "sunflower",
                                "--json-output"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["correct"])

    def test_verify_works_without_pycryptodome(self):
        # MAC verification is pure KDF + pure-Python keccak; emulate the
        # zero-dependency path by loading the module-level keccak source.
        ks = t.load_keystore(fixture_path("scrypt_keystore.json"))
        self.assertTrue(t._try_password(ks, "sunflower"))
        self.assertFalse(t._try_password(ks, "nope"))

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_decrypt_password_reports_payload(self):
        code, out, _ = run_cli(["-k", fixture_path("scrypt_keystore.json"),
                                "--decrypt-password", "sunflower",
                                "--json-output"])
        self.assertEqual(code, 0)
        r = json.loads(out)
        self.assertTrue(r["correct"])
        self.assertEqual(r["plaintext_kind"], "private-key")
        self.assertTrue(r["address_match"])

    def test_legacy_empty_salt_recovery(self):
        ks = t.load_keystore(fixture_path("trust_backup_legacy_emptysalt.json"))
        self.assertEqual(len(ks["salt"]), 0)
        src = t.WordlistSource(["sunflower"], "basic")
        found, _, _ = t.run_attack(ks, src, threads=2)
        self.assertEqual(found, "sunflower42")

    def test_legacy_missing_salt_recovery(self):
        ks = t.load_keystore(fixture_path("trust_backup_legacy_nosalt.json"))
        self.assertEqual(len(ks["salt"]), 0)
        src = t.WordlistSource(["sunflower"], "basic")
        found, _, _ = t.run_attack(ks, src, threads=2)
        self.assertEqual(found, "sunflower42")

    def test_batch_mode_recovers_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("scrypt_keystore.json", "trust_backup_weak.json"):
                shutil.copy(fixture_path(name), os.path.join(tmp, name))
            code, out, err = run_cli(["--batch", tmp,
                                      "-p", "sunflower", "-p", "sunflwer",
                                      "--yes"])
            self.assertEqual(code, 0)
            self.assertIn("batch done: 2 of 2 file(s) recovered", err)

    def test_batch_none_found_exit_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(fixture_path("trust_backup_weak.json"),
                        os.path.join(tmp, "w.json"))
            code, _, err = run_cli(["--batch", tmp, "-p", "not-the-password",
                                    "--yes"])
            self.assertEqual(code, 1)
            self.assertIn("0 of 1 file(s) recovered", "\n".join(err.splitlines()[-3:]))

    def test_batch_empty_dir_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli(["--batch", tmp, "-p", "x"])
            self.assertEqual(code, 2)
            self.assertIn("no .json files", err)

    def test_hashcat_export_legacy_warns(self):
        code, out, err = run_cli(["-k",
                                  fixture_path("trust_backup_legacy_emptysalt.json"),
                                  "--export-hashcat", "-"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("$ethereum$s*16384*8*4**"), out)
        self.assertIn("will NOT load", err)

    def test_wrapper_inspect_script(self):
        code = subprocess.call(
            [sys.executable, os.path.join(HERE, "..", "trustwallet_backup_inspect.py"),
             fixture_path("scrypt_keystore.json")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(code, 0)

    def test_wrapper_hashcat_script(self):
        out = subprocess.check_output(
            [sys.executable, os.path.join(HERE, "..", "trustwallet2hashcat.py"),
             fixture_path("scrypt_keystore.json")], text=True)
        self.assertTrue(out.strip().startswith("$ethereum$s*"))

    def test_wrapper_verify_script(self):
        code = subprocess.call(
            [sys.executable, os.path.join(HERE, "..", "trustwallet_backup_verify.py"),
             fixture_path("scrypt_keystore.json"), "sunflower"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(code, 0)

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome not installed")
    def test_wrapper_decrypt_script_exports_phrase(self):
        root = os.path.join(HERE, "..")
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "phrase.txt")
            code = subprocess.call(
                [sys.executable, os.path.join(root, "trustwallet_backup_decrypt.py"),
                 fixture_path("trust_backup_weak.json"), "sunflwer",
                 "-o", out_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(code, 0)
            with open(out_path) as fh:
                self.assertIn("abandon abandon", fh.read())

    def test_wrapper_no_args_usage_exit_two(self):
        for name in ("trustwallet_backup_inspect.py", "trustwallet2hashcat.py",
                     "trustwallet_backup_decrypt.py", "trustwallet_backup_verify.py",
                     "trustwallet_backup_recover.py"):
            code = subprocess.call(
                [sys.executable, os.path.join(HERE, "..", name)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(code, 2, name)

    def test_wrapper_help_exit_zero(self):
        for name in ("trustwallet_backup_inspect.py", "trustwallet2hashcat.py",
                     "trustwallet_backup_decrypt.py", "trustwallet_backup_verify.py",
                     "trustwallet_backup_recover.py"):
            code = subprocess.call(
                [sys.executable, os.path.join(HERE, "..", name), "--help"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(code, 0, name)

    def test_inspect_pbkdf2_mode_15600(self):
        code, out, _ = run_cli(["-k", fixture_path("pbkdf2_keystore.json"),
                                "--inspect", "--json-output"])
        self.assertEqual(code, 0)
        r = json.loads(out)
        self.assertEqual(r["kdf"], "pbkdf2")
        self.assertEqual(r["hashcat_mode"], 15600)
        self.assertTrue(r["hashcat_loadable"])

    def test_batch_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("scrypt_keystore.json", "trust_backup_weak.json"):
                shutil.copy(fixture_path(name), os.path.join(tmp, name))
            code, out, _ = run_cli(["--batch", tmp,
                                    "-p", "sunflower", "-p", "sunflwer",
                                    "--json-output", "--yes"])
            self.assertEqual(code, 0)
            lines = [json.loads(x) for x in out.strip().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertTrue(all(l["found"] for l in lines))


if __name__ == "__main__":
    unittest.main()