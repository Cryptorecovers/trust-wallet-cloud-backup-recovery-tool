# 🔑 twrecover

**Offline password recovery for your Trust Wallet backup file (.json).**

By **Crypto Recovers** — [cryptorecovers.com](https://cryptorecovers.com)

Forgot the password of your Trust Wallet backup? `twrecover` tries candidate
passwords for you, fast and 100% offline, until it finds the one that
unlocks the file. It works on the password-protected backup file the Trust
Wallet app exports when you back up a wallet.

> ⚠️ **Please read this first:** only use this tool on wallet files you own,
> or that you are explicitly authorized to recover. Cracking someone else's
> wallet without permission is illegal in most countries. It is also only
> realistic for passwords that have at least some predictable structure: a
> random 25-character password cannot be recovered by anyone, ever (see
> [Why is it so slow?](#why-is-it-slow)).

---

## Table of contents

1. [Features](#features)
2. [Who this is for](#who-this-is-for)
3. [Requirements & installation](#requirements--installation)
4. [Step-by-step guide (start here)](#step-by-step-guide)
5. [Command reference](#command-reference)
6. [The complete suite](#the-complete-suite)
7. [How it works](#how-it-works)
8. [Attack strategy guide](#attack-strategy-guide)
9. [Performance & benchmarking](#performance--benchmarking)
10. [GPU cracking (hashcat bridge)](#gpu-cracking-with-hashcat)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)
13. [Security & privacy](#security--privacy)
14. [Development & testing](#development--testing)
15. [License](#license)

---

## Features

- 🔓 Recovers the password of Trust Wallet backup files — the exported
  `.json` backups (`crypto` section, `version: 3`, cipher `aes-128-ctr`)
- 🧂 Both key-derivation functions used in the wild: **scrypt** and
  **PBKDF2-HMAC-SHA256**
- 🧠 Three attack modes, freely combinable in a single run:
  - explicit passwords (`-p`)
  - dictionary wordlists with smart mutations (`-l` + `-r`), including
    bt-recovery-style hint lists with automatic typo generation (`-r typos`)
  - brute force over a custom alphabet (`-a`)
- 🗄️ Runs **parallel across all your CPU cores** with live progress, speed
  and ETA; safe to interrupt any time (Ctrl-C)
- ✅ **Effectively zero false positives** — every candidate is verified
  against the keystore's MAC (a 256-bit keccak check), and the recovered key
  is cross-checked against the wallet's Ethereum address
- 🧾 Native support for **mnemonic (“cloud backup”) files** — the encrypted
  backup you upload to iCloud/Google Drive. The payload is your recovery
  phrase: twrecover decrypts it, derives the Ethereum address via
  BIP39 + BIP32 `m/44'/60'/0'/0/0`, and matches it against the backup's
  account list (see [How it works §4–5](#4-decryption--the-address-cross-check))
- 🐍 **Runs with just the Python standard library** for PBKDF2 keystores;
  optional `pycryptodome` adds decryption/export and a scrypt fallback
- 📦 Machine-readable `--json-output`, decrypted-payload export, GPU bridge
  via `--export-hashcat`, `--benchmark` mode
- 🗃️ `--batch DIR` recovers across every backup in a folder, and the suite
  ships named entry points: `trustwallet_backup_inspect/verify/decrypt/
  recover.py` + `trustwallet2hashcat.py` (see [The complete suite](#the-complete-suite))

---

## Who this is for

| If you... | twrecover can help |
| --- | --- |
| Forgot the password of your Trust Wallet backup export | Yes — if you can partially remember it, or it contains a word/date/name |
| Remember the password but lost the file | No — you need the `.json` file itself |
| Have a random 25-character password | Probably no — see [Why is it slow?](#why-is-it-slow) |
| Want to crack someone else's wallet | **No** — illegal and we won't help with that; use only files you own |

---

## Requirements & installation

**Requirements:** Python 3.9 or newer. On macOS it is preinstalled; on
Windows get it from [python.org](https://python.org) (tick *"Add Python to
PATH"* during install); on Linux `sudo apt install python3` (Debian/Ubuntu).

You don't even need to install anything —

```bash
git clone https://github.com/Cryptorecovers/trust-wallet-cloud-backup-recovery-tool
cd trust-wallet-cloud-backup-recovery-tool
python twrecover.py --help
```

or install the whole suite as commands:

```bash
pip install .[crypto]
```

This gives you six commands usable from anywhere:
`twrecover`, `trustwallet_backup_inspect`, `trustwallet_backup_verify`,
`trustwallet_backup_decrypt`, `trustwallet_backup_recover` and
`trustwallet2hashcat` (the suite is described in
[The complete suite](#the-complete-suite)). The same six scripts also
run directly from the repo without installing anything:
`python trustwallet_backup_inspect.py wallet.json`.

`pycryptodome` (the `[crypto]` part) is **optional**: it enables decrypting
the recovered payload and works around systems without scrypt in OpenSSL.
Core password recovery (guessing + MAC verification) works without it.

> **Windows users:** `python` may be `py` (e.g. `py twrecover.py ...`).

---

## Step-by-step guide

### Step 1 — Get your wallet's encrypted JSON file

Every app that supports this format lets you export / back up the wallet to
a password-protected file:

- **Trust Wallet (mobile or extension):** open the app, go to your Wallets
  and choose *Backup* / *Export backup* on the wallet you want. The app
  asks you for (or lets you set) a password and produces a JSON file -
  that password is exactly what we're recovering.
- The result is a JSON file that contains a `"crypto"` (or `"Crypto"`)
  section. Copy it to your computer, ideally to an **offline** machine.

> If your file has no `crypto` section at all, it is probably **not
> encrypted** — `twrecover` will detect that immediately and tell you.

### Step 2 — see what you're dealing with

The fastest way to check the file is a real, recoverable Trust Wallet
backup:

```bash
python trustwallet_backup_inspect.py wallet.json
```

It prints the file's format, KDF settings, salt size and the wallet's
accounts, plus whether hashcat will be able to help later.
Then, to learn how fast your machine can try passwords:

```bash
python twrecover.py -k wallet.json --benchmark
```

Output example:

```
benchmark
keystore: kdf=scrypt, n=16384 r=8 p=4, dklen=32, cipher=aes-128-ctr, address=0x42d01cb7e4c27fe6f1b4d0eae12c3a953b0df20c
one attempt: 54.2 ms  ->  18 candidates/s on one core
all 8 cores: ~147 candidates/s (theoretical)
scrypt memory: ~16 MB per worker, ~128 MB total for 8 workers
```

This tells you the encryption settings, how fast one guess takes, and how
many passwords-per-second your machine can attempt. (Trust Wallet's real
presets, straight from its open-source core: `n=16384 r=8 p=4` for regular
backups and `n=262144 r=8 p=1` for the strong iCloud/Google Drive encrypted
backup — roughly 50–160 ms per guess.)

### Step 3 — Try passwords you remember

```bash
python twrecover.py -k wallet.json -p "mybirthday123"
python twrecover.py -k wallet.json -p "First guess" -p "Second guess"
```

If one matches, you'll see:

```
[+] password found in direct (source: 1s)
Password: mybirthday123
[+] decrypted payload: private-key (32 bytes)
derived address: 0x2b5ad5c4795c026514f8317c7a215e218dccd6cf
keystore address: 0x2b5ad5c4795c026514f8317c7a215e218dccd6cf
(match)
```

**Done. That's the password.** The address check proves the file really
contains the wallet it claims to.

### Step 4 — Dictionary attack

When the obvious guesses fail, put every word you can think of — names,
pets, dates, favorite phrases, old passwords — into a text file, one per
line:

```
sunflower
dragon
friends
...
```

Then run:

```bash
python twrecover.py -k wallet.json -l my-words.txt -r medium
```

The `-r medium` does the heavy lifting: for every word it also tries
capitizations, **+digits** (`sunflower42`), **+years** (`sunflower2024`),
symbols (`sunflower!`), leetspeak (`p455w0rd`) and more:

| Rule set | What it adds | Candidates/hint |
| --- | --- | --- |
| `none` | the hints as-is | 1 |
| `typos` | bt-recovery-style single typos of each hint (see Step 5) | ~4 × length |
| `basic` | case variants, digits 0–99, years 1990–2026, symbols, doubled, reversed, Unicode forms | ~300 |
| `medium` **default** | `basic` + leetspeak (`p455w0rd`) | ~325 |
| `full` | `medium` + 3-digit suffixes | ~2,300 |
| `leet` | leet-heavy expansion | ~560 |

This is where most passwords are found, because people rarely pick
truly random strings.

### Step 5 — Password hint lists (bt-recovery style) 🧠

This is the mode that matters most in practice: you write down **every
word, name or date you associate with the password** — the tool does the
rest. It works the same way as BTCrecover's famous hint-list + typos flow:

```bash
python twrecover.py -k wallet.json -l hints.txt -r typos
```

`hints.txt` is a plain text file, one hint per line:

```
sunflower
dragon
Karen
barcelona
1998
mycat
neighbor
```

With `-r typos`, every hint automatically spawns its single-typo
variants — exactly like a human fingerspelling a password:

| Typo class | Example for `sunflower` |
| --- | --- |
| exact hint | `sunflower` |
| one char deleted | `sunflwer`, `sunflower` minus any other letter |
| adjacent chars swapped | `usnflower`, `sunfolwer`… |
| one char doubled | `sunflowerr`, `ssunflower`… |
| an `s` inserted (plural/possessive) | `ssunflower`, `sunflowers`… |

**Why typo rules matter:** a wallet password you "remember" was almost
certainly typed once with a typo (dropped letter, swapped pair, fat-fingered
double) and then saved as-is. BTCrecover users know this is where most
"forgotten" passwords actually are, and now `twrecover` does it too.

Compared with BTCrecover:

| BTCrecover | twrecover |
| --- | --- |
| `--tokenlist` (hint words) | `-l hints.txt` |
| `--typos N` (auto-typo generation) | `-r typos` (built-in single-typo set) |
| workspaces / hierarchical tokens | not supported — write full phrases as hints |
| many wallet formats | Trust Wallet backups (`.json`) |

Still not found? Add multi-word phrases as hints too (`ilovekaren`,
`barcelona1999`) — the `basic`/`medium` rule sets then cover the
phrase+number/symbol combos on top.

### Step 6 — When you know the shape, brute force

If you know the password is, say, 4 characters of lowercase letters and
digits:

```bash
python twrecover.py -k wallet.json -a abcdefghijklmnopqrstuvwxyz0123456789 \
    --min-length 4 --max-length 4
```

Only do this when the space is small — see the timing math below.

### Step 7 — Use the result

When the password is found you can also:

```bash
# Save the decrypted wallet content to a file:
python twrecover.py -k wallet.json -l words.txt --export-decrypted recovered.json

# Print the private key directly (be careful!):
python twrecover.py -k wallet.json -l words.txt --show-secrets

# Machine-readable result (for scripts/Markov automation):
python twrecover.py -k wallet.json -l words.txt --json-output
```

Then import the wallet back into the app with the recovered password as soon
as possible, and **delete the decrypted artifacts** afterwards — a private
key in a plain file is a wallet lying in the open.

---

## Command reference

| Option | Description |
| --- | --- |
| `-k, --keystore FILE` | Encrypted wallet `.json` file (omit with `--batch`) |
| `-p, --password PASS` | Try one explicit password (repeatable) |
| `-l, --wordlist FILE` | Dictionary file, one password per line (repeatable; `-` = stdin, `.gz` OK) |
| `-r, --rules NAME` | Mutation rules: `none`, `typos`, `basic`, `medium` (default), `full`, `leet` |
| `-a, --alphabet CHARS` | Brute-force character set |
| `--min-length N` | Brute-force minimum length (default 1) |
| `--max-length N` | Brute-force maximum length (default: same as min) |
| `-t, --threads N` | Work processes (default: all cores; 1 = serial) |
| `--limit N` | Stop after N candidates |
| `--check-empty` | Also try the empty password |
| `--verify-address ADDR` | Cross-check the recovered key against a known address |
| `--show-secrets` | Print the recovered private key / plaintext |
| `--export-decrypted OUT` | Write the decrypted payload to a file |
| `--export-hashcat OUT` | Export the keystore as a hashcat line for GPU cracking (`-` = stdout) |
| `--benchmark` | Print speed/memory estimates and exit |
| `--inspect` | Validate the backup & print a structural report (KDF, accounts, salt size, hashcat verdict) — no guessing |
| `--verify-password PASS` | Check specific passwords against the MAC; print `CORRECT`/`incorrect` (repeatable; no pycryptodome needed) |
| `--decrypt-password PASS` | Decrypt with a known password & report the payload (repeatable) |
| `--batch DIR` | Recover across **every** `.json` backup in a directory, one run |
| `--json-output` | Emit one JSON result on stdout (one per file in `--batch` mode) |
| `-q, --quiet` | Only print the password (or JSON); the recovery credit line still shows |
| `--progress` | Show progress even when not on a TTY |
| `--yes` | Skip the confirmation prompt for very long runs |
| `-v, --verbose` | Extra diagnostics |
| `--version` | Print version & credits |

**Exit codes:** `0` found · `1` not found · `2` usage/keystore error ·
`130` interrupted.

---

## The complete suite

Every capability is available both as a `twrecover` flag and as a named,
standalone entry point (they are thin wrappers around the same engine -
no duplicated code):

| Tool | What it does | Equivalent twrecover command |
| --- | --- | --- |
| `trustwallet_backup_inspect.py` | Validate a backup & print a full structural report: format, KDF params, accounts, salt size, **hashcat compatibility verdict** | `twrecover -k file --inspect` |
| `trustwallet_backup_verify.py` | Test specific passwords against the MAC; answer `CORRECT`/`incorrect` per password. Zero dependencies (works without pycryptodome) | `twrecover -k file --verify-password PASS` |
| `trustwallet_backup_decrypt.py` | Decrypt with a *known* password: verify MAC → AES-128-CTR → classify payload (private key / mnemonic phrase) → cross-check the derived address | `twrecover -k file --decrypt-password PASS` |
| `trustwallet_backup_recover.py` | The full recovery engine: guessing, rules, brute force, parallel cores (identical to `twrecover` itself) | `twrecover -k file …` |
| `trustwallet2hashcat.py` | Convert a backup to hashcat mode 15700/15600 for GPU cracking | `twrecover -k file --export-hashcat OUT` |
| `twrecover --batch DIR` | Recover passwords across **every** `.json` in a folder with one run, shared password sources; summary: `batch done: 2 of 3 file(s) recovered` | `twrecover --batch DIR -l words.txt` |

Typical session restoring an old iCloud/Drive backup:

```bash
python trustwallet_backup_inspect.py backup.json      # what are we dealing with?
python trustwallet_backup_recover.py -k backup.json -l hints.txt -r typos
python trustwallet_backup_decrypt.py backup.json NEWPASS --export-decrypted phrase.txt
python trustwallet2hashcat.py backup.json -o wallet.15700   # if CPU isn't enough
python twrecover.py --batch ~/Downloads/backups -l words.txt -r basic  # many files
```

---

## How it works

### 1. What's actually inside a keystore file?

A Trust Wallet backup file is just JSON. Stripped down, it looks like
this (the format itself is the standardized Web3 Secret Storage / keystore
v3 structure):

```json
{
  "version": 3,
  "id": "01f9c9b7-…",
  "address": "2aed5ad5c4795c026514f8317c7a215e218dccd6cf",
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": { "iv": "0f33a5c2e00c607049700f29fb8614a0" },
    "ciphertext": "… (encrypted private key) …",
    "kdf": "scrypt",                          ← or "pbkdf2"
    "kdfparams": { "n": 16384, "r": 8, "p": 4, "dklen": 32, "salt": "…" },
    "mac": "… (checksum of the key) …"
  }
}
```

The private key is encrypted in `ciphertext` with **AES-128-CTR**. The
256-bit AES key is derived from your password through a deliberately slow
function — that's the "key derivation" (KDF).

A Trust Wallet **cloud backup** (the encrypted file you can upload to
iCloud / Google Drive) uses the *exact same* `crypto` envelope, but wears
Trust Wallet's own top-level layout (defined in their open-source
`wallet-core`):

```json
{
  "version": 3,
  "type": "mnemonic",
  "id": "1f7a0b13-…",
  "name": "Trust Wallet",
  "crypto": { /* identical scrypt/aes-128-ctr block as above */ },
  "activeAccounts": [
    { "address": "0x9858EfFD…", "derivationPath": "m/44'/60'/0'/0/0",
      "coin": 60, "publicKey": "…" }
  ]
}
```

The encrypted payload of a cloud backup is your **recovery phrase** (the
12–24 words), not a private key — that's why the file has a `type` of
`mnemonic` and lists your account addresses in `activeAccounts`.

### 2. How the password becomes the key

**scrypt** (Trust Wallet default) takes your password, a random `salt`,
and three cost parameters (`n`, `r`, `p`) and spends a controlled amount
of memory+CPU mixing it before producing the 32-byte key. Higher `n` =
safer wallet = slower guesses:

```
scrypt(n=16384, r=8, p=4, salt, password)  →  32 bytes derived key
```

(Trust's presets: `n=16384 r=8 p=4` by default; the strong iCloud/Drive
cloud backup uses `n=262144 r=8 p=1` — about 256 MB of memory per guess.)

**PBKDF2-HMAC-SHA256** repeats a keyed hash (a SHA-256 hash protected by an
MAC) `c` times, which is cheap on memory but deliberately slow on CPU:

```
PBKDF2-HMAC-SHA256(salt, password, iterations=c)  →  32 bytes derived key
```

This indirection layer is why guessing isn't free: each candidate costs a
full scrypt (hundreds of MB of work) or thousands of hash rounds, on
purpose. Wallets are designed so that brute-forcing them is costly.

### 3. The MAC — how the tool knows a guess is right

The derived key is split in two halves (16 bytes each): the first half
becomes the AES key; the second half is used for verification:

```
MAC = Keccak-256( derived_key[16:32]  ||  ciphertext )
```

The file stores the correctly computed MAC. For every candidate password
we re-derive the key and recompute this MAC; if it matches, the password is
correct — **cryptographically confirmed**. False positives are effectively
impossible: matching the 256-bit keccak MAC means the derived key is
byte-identical, unless a keccak-256 collision (~2⁻²⁵⁶) is involved. (This
is the same check every wallet app performs when you unlock it.)

### 4. Decryption & the address cross-check

Once a candidate passes the MAC, we decrypt `ciphertext` with
`AES-128-CTR(key = derived[0:16], iv)` — and we don't stop there:

- If the payload is a **private key** (exported keystore): we derive the
  **Ethereum address** (secp256k1 public key, hashed with Keccak-256) and
  compare it with the `address` in the file.
- If the payload is a **recovery phrase** (cloud backup): we derive the
  Ethereum address with BIP39 (seed = PBKDF2-HMAC-SHA512 of the phrase) and
  BIP32 along Trust Wallet's path `m/44'/60'/0'/0/0`, then compare it with
  the first account in the file's `activeAccounts`.

Either way we have checked *everything the wallet itself checks*. The
full pipeline:

```
password ──► scrypt/PBKDF2 ──► 32 B derived key
                │                    │
                │        ┌───────────┴───────────┐
                │     [0:16] AES key        [16:32] MAC key
                │        │                         │
                │        ▼                         ▼
                │   AES-CTR decrypt          Keccak-256(MAC key || ciphertext)
                │        │                         │
                ▼        ▼                         ▼
          ciphertext   private key            compare to stored MAC
                │        │                         │
                │        └──► derive address ──► compare to stored address
                │                                  │
                └─────── "password found" ◄─────────┘
```

### 5. Proven against the real Trust Wallet format

“Does this actually work on a *real* backup?” — yes, and it is tested
against files in the exact format the app writes. Trust Wallet's backup
code is open source (`trustwallet/wallet-core`), so the test fixtures are
generated to match it byte-for-byte:

- at the top level: `type: "mnemonic"`, `name`, `id`, and
  `activeAccounts` with the EIP-55 checksummed address, `derivationPath`,
  `coin: 60` and `publicKey` — exactly what `StoredKey::json()` writes;
- the `crypto` envelope with the real scrypt presets: `n=16384 r=8 p=4`
  (the wallet's default) *and* `n=262144 r=8 p=1` (the strong preset used
  for iCloud / Google Drive encrypted backup, ~256 MB per attempt — the
  same numbers hashcat lists under mode 15700);
- the plaintext is the UTF-8 recovery phrase, MAC = Keccak-256 of
  `derived[16:32] || ciphertext`, AES-128-CTR, 32-byte salt.

Every derivation is additionally pinned against published spec vectors:
BIP39 and BIP32 test vectors, plus the well-known mnemonic
`abandon abandon … about`, whose Ethereum address at `m/44'/60'/0'/0/0`
is `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` in countless official
test suites. The test suite then *really recovers* these backups —
dictionary, typo, and brute-force attacks all run end-to-end against the
fixtures, and the derived address comes back matching `activeAccounts`.
You can regenerate them any time with `python tests/make_fixtures.py`.

### Why is it slow?

Because wallets are built that way on *purpose*. The KDF settings are
tuned to make each password guess expensive (about 0.05-0.2 s per guess on
a modern CPU for Trust-Wallet-style scrypt settings). Nobody can "get
around" the KDF: any false candidate you check must pay the full price.
That is exactly why this tool is CPU-parallel, and why the biggest lever is
*choosing the right candidates*, not faster hardware.

---

## Attack strategy guide

Before you throw hardware at the problem, throw **thought**:

1. **Brain-dump everything you remember.** Old passwords, the password you
   use for other accounts, birthdays, a kid's name, the dog, your street,
   the number 7, the year you opened it. Put them all in a wordlist file —
   one per line. Most "forgotten" passwords are *variations* of something
   you still know.
2. **Let the rules do the variation work.** The same wordlist covers
   `Dragon`, `dragon2021`, `Dragon!`, `dr4gon` etc. via `-r medium`.
3. **Order attacks by likelihood, not coverage.** Explicit `-p` → small
   wordlist → big wordlist → brute. The tool tells you the estimated time
   before it starts — and you can interrupt any time.
4. **Estimate how far you can get.** If rate is 150 candidates/s = 540k/h:
   - a 100-word personal list → seconds
   - 10k-word dictionary x 324 rules = 3.24M → ~6 h
   - 26^5 (all-lowercase 5 chars) = 11.9M → ~22 h
   - 36^8 = 2.8 * 10^12 → **give up, it's not that password**
5. **Remember which source the found password came from** — the output
   says e.g. `source: wordlist (120 words x 302 rules)`: that tells you
   exactly which shape of your memory the password had was recovered.

---

## Performance & benchmarking

`--benchmark` measures your exact machine right away. Typical single-core
costs:

| Keystore KDF | ms/guess | guesses/s (1 core) |
| --- | --- | --- |
| scrypt n=4096, r=8 | ~2 ms | ~500 |
| scrypt n=16384, r=8, p=4 (Trust default) | ~50-90 ms | ~11-20 |
| scrypt n=262144, r=8, p=1 (Trust strong/cloud) | ~120-160 ms | ~6-8 |
| pbkdf2 c=100000 | ~40 ms | ~25 |

Multiply by cores for total throughput (use `-t` to cap it). **Memory:**
every parallel worker needs `128 × n × r` bytes (`16384×8 → 16 MB`, and
`262144×8 → 256 MB` for the strong preset) — so on a 16 GB machine don't
run 64 workers against scrypt n=262144; leave headroom for the OS.

The engine is CPU-only by design (see next section) — each worker is a
separate process, so it scales with your physical cores and never with
market volatility.

---

## GPU cracking with hashcat

`twrecover` is a CPU engine. When CPU parallelism isn't enough, the right
tool is **hashcat**, which runs scrypt/PBKDF2 on GPUs. We make the handoff
trivial with a verified export:

```bash
python twrecover.py -k wallet.json --export-hashcat wallet.15700

hashcat -m 15700 wallet.15700 wordlist.txt        # scrypt keystores
hashcat -m 15700 wallet.15700 -a 3 ?l?l?l?l?l?l  # mask attack
```

For PBKDF2 keystores the format is mode **15600** instead:

```bash
python twrecover.py -k wallet.json --export-hashcat wallet.15600
hashcat -m 15600 wallet.15600 wordlist.txt
```

The export format (`$ethereum$s*N*r*p*salt*ciphertext*mac` and
`$ethereum$p*iters*salt*ciphertext*mac`) was verified against hashcat's
module source, so it parses without repackaging. Two caveats:

- hashcat requires the scrypt `n` to be divisible by 1024 (Trust Wallet
  defaults qualify); `twrecover` warns when a file doesn't.
- hashcat reports a *cracked password* when the MAC matches — it does not
  verify the Ethereum address. A MAC match already confirms the password,
  but double-check by running the recovered password through `twrecover
  -p` on the original JSON.

**One more, important: legacy empty-salt backups.** Older Trust Wallet
cloud backups (the shape shared in the hashcat forum, 2023) carry an
**empty salt** (`"salt": ""`) or no salt key at all. hashcat's Ethereum
modes cannot load them — their parser locks the salt field to exactly
64 hex characters and rejects anything else, which is why the only
hashcat issue about Trust Wallet backups ([#4338, July 2025](https://github.com/hashcat/hashcat/issues/4338))
still sits open with "no such mode". `twrecover` handles these files
natively (empty salt = valid input to the same scrypt), `--inspect`
detects them and tells you upfront, and `--export-hashcat` warns you
that the line won't load. When hashcat merges support, the exported line
will drop in unchanged.

**Why not GPU in twrecover itself?** A correct, portable GPU kernel for
scrypt with the same verification we do is a whole project (hashcat is
that project). This tool's job is, first, to make the human-shaped part
of recovery *good* (guessing, rules, verification, documentation), and
second, to hand off cleanly when you need horsepower.

---

## Troubleshooting

| Symptom | What's up & what to do |
| --- | --- |
| `this file is NOT encrypted` | Your export already contains the key in plain. Move it to a safe place; no password is needed. |
| `unsupported keystore version 1` | A very old pre-standard backup (keystore v1): different scheme, not supported |
| `scrypt is not available` | Your Python/OpenSSL lacks scrypt. `pip install pycryptodome` and re-run. |
| `hashcat: no hashes loaded` | Wrong mode: scrypt → `-m 15700`, PBKDF2 → `-m 15600`. Use `--benchmark` to see the kdf. |
| `hashcat: no hashes loaded` (legacy backup) | Legacy empty-salt backups can't be parsed by hashcat at all ([#4338](https://github.com/hashcat/hashcat/issues/4338)). Recover with `trustwallet_backup_recover.py` instead — `--inspect` tells you upfront. |
| Progress shows 0% for a while | Normal for huge scrypt n: each probe is a full scrypt. Wait for first 10 candidates. |
| `[x] password not found` | Wrong attack shape. Add every word/pattern you remember to `-p`; try `-l` of *your own words* before generic. |
| Very slow on Windows | Older OpenSSL lacks scrypt — install `pycryptodome` (`pip install pycryptodome`) for a big speedup. |
| The password printed but address mismatch shows | Extremely rare; the MAC already proved the password. The address field in the file was likely stale — still verify ownership before importing funds. |

---

## FAQ

**Which files work?** Trust Wallet backup files — the password-protected
`.json` exports with a `crypto` section, `aes-128-ctr` cipher, and
scrypt or pbkdf2 key derivation. (For transparency: this file structure is
the standardized Web3 Secret Storage format, so the same decoder also opens
an equivalent backup from other wallets — but twrecover is built and
positioned for Trust Wallet backups.)

**I have the file but the password is 20 random characters.** Unless you
remember it, there's ~nothing to do. The KDF prevents that. Be honest about
the shape of the password before spending compute.

**Does it send my data somewhere?** No — it never opens a network
connection. Run it on an offline machine for extra certainty.

**Can I combine attacks?** Yes: `-p oldpass -l words.txt -a abc123`
runs direct, then wordlist, then brute, stopping at the first hit.

**What about the empty password?** `--check-empty`.

**GPU support?** Via the `--export-hashcat` bridge (section above).
Twrecover proper is CPU-parallel.

**Can I test a single remembered password quickly?** Yes:
`trustwallet_backup_verify.py backup.json "guess"` (or
`twrecover -k backup.json --verify-password "guess"`). Instant MAC check,
works with the plain standard library.

**I have several backup files.** Point `--batch` at the folder:
`twrecover --batch ~/backups -l words.txt -r basic` — one run, one
summary line (`batch done: 2 of 3 file(s) recovered`).

**Is this tested against real Trust Wallet format?** Yes — the test suite
recovers backup files generated in the exact layout Trust Wallet's own
wallet-core writes (ScryptKey metadata, mnemonic payloads, both real
scrypt presets), and every derived address matches published spec vectors.
See [How it works §5](#5-proven-against-the-real-trust-wallet-format).

**Is it safe on a realistic machine to run?** Yes — each guess is a
well-bounded computation; the tool shows expected time and can be stopped
anytime. Memory: see per-worker RAM in `--benchmark`.

---

## Security & privacy

- Everything runs locally, offline-capable; nothing is transmitted.
- When found, the password to be printed with the payload can be exported
  (`--show-secrets`/`--export-decrypted`). **Treat the result like the
  wallet itself:** import ASAP, then delete exported copies.
- Use trustworthy hardware/software: this tool is as secure as the machine
  it runs on. Keep your keystore file itself protected (it is the wallet!).
- Personal wordlists are never transmitted, either — they live and die on
  your machine. If you download a public wordlist, prefer one with a known
  provenance (e.g. the rockyou collection); junk lines are simply tried
  and discarded.

---

## Development & testing

```bash
pip install pycryptodome                 # recommended for full suite
python tests/make_fixtures.py            # regenerate the test keystores
python -m unittest discover -s tests -v  # 81 tests
```

The test suite validates:
- Keccak-256 against known vectors and against PyCryptodome (the pure-Python
  fallback is also cross-checked — the reference at the heart if it breaks)
- secp256k1/address derivation against well-known accounts
- scrypt & PBKDF2 round-trips against fixtures built from raw crypto libs
- the candidate-math (rules index, brute-force enumerations, bt-recovery-
  style typo variants across variable-length hints)
- end-to-end hint-list recovery: a one-word hint list recovering a
  typo'd password (`-r typos`)
- the parallel engine (find / not-found / limits)
- CLI end-to-end: found, not found, JSON, export, hashcat export,
  branding, benchmark, error handling
- Trust Wallet StoredKey backups: mnemonic payloads, both real scrypt
  presets, legacy empty-salt / missing-salt files, BIP39+BIP44 address
  derivation pinned to published spec vectors
- the suite modes: `--inspect`, `--verify-password`, `--decrypt-password`,
  `--batch`, and the five standalone suite scripts

CI (GitHub Actions) runs the suite on Python 3.9–3.13.

---

## License

MIT — see [LICENSE](LICENSE). Provided as-is, without warranty. Use only
lawfully, on files you own or are authorized to recover.

Made by **Crypto Recovers** (https://cryptorecovers.com), because nobody
should lose their own wallet.