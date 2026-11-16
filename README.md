# BAT: a small, reusable encryption toolkit

BAT turns data into unreadable bytes that only the right password (or key) can turn back.
It works fully offline, supports any data (text, files, photos, video, database fields...), and
is built **only from standard, widely reviewed algorithms**. It does *not* invent a new cipher.

> Status: **unaudited prototype.** The algorithms are trusted, but this particular code has not been
> reviewed by an independent security expert. Get a review (or switch to libsodium/Tink) before real
> users depend on it.

---------------------------------------------------------------------------------------------

## 1. Quick start

Requirements: Python 3.10+ and `pip install -r requirements.txt` (the `cryptography` package, 44 or newer).

```python
import bat

# A) Small data, with a password
blob = bat.encrypt(b"my secret", "a long passphrase here", context=b"myapp/notes")
data = bat.decrypt(blob, "a long passphrase here", context=b"myapp/notes")

# B) Small data, with a random 32-byte key (store the key safely!)
key  = bat.generate_key()
blob = bat.encrypt(b"my secret", key)
data = bat.decrypt(blob, key)

# C) Big files (chunked, safe for multi-GB; output appears only if everything verified)
bat.encrypt_file("video.mp4", "video.mp4.bat", "passphrase")
bat.decrypt_file("video.mp4.bat", "video.mp4", "passphrase")

# D) Streams (sockets, pipes, open files)
bat.encrypt_stream(src_fileobj, dst_fileobj, key)
bat.decrypt_stream(src_fileobj, dst_fileobj, key)

# E) Separate keys for separate purposes from one master key
k_db   = bat.derive_subkey(key, b"database")
k_logs = bat.derive_subkey(key, b"logs")
```

Wrong password, wrong context, or modified data raises `bat.DecryptionError`.
Not-BAT data or a bad header raises `bat.FormatError`.

Command line:
```
python -m bat encrypt  file.pdf file.pdf.bat      # asks for a password
python -m bat decrypt  file.pdf.bat file.pdf
python -m bat keygen   my.key                     # then add:  --keyfile my.key
```
Tests: `python -m unittest discover -s tests`

---------------------------------------------------------------------------------------------

## 2. What BAT is made of (the algorithms)

| Job | Algorithm | In plain words |
|---|---|---|
| Password -> key | **Argon2id** (default 256 MiB, 3 passes, 4 lanes) | Deliberately slow and memory-hungry, so guessing passwords is very expensive |
| Encrypt + detect tampering | **ChaCha20-Poly1305** (AEAD) | Scrambles data and attaches a tag; any change to data or context makes decryption fail |
| Extended nonce | **HKDF-SHA256** over a random 24-byte nonce | Gives every message its own one-time key, so random nonces never collide dangerously |
| Derive separate keys | **HKDF-SHA256** | One master key -> many independent keys |
| Fingerprints | **BLAKE2b-256** | Detects changes |
| Randomness | **OS secure random** (`os.urandom`) | Never a custom generator |

These are the same families used in TLS 1.3, WireGuard, password managers and disk encryption.
The code lives in `bat/core.py` (primitives, ~90 lines) and `bat/api.py` (the easy functions).

---------------------------------------------------------------------------------------------

## 3. How it works

### Small data (`encrypt` / `decrypt`)
```
password --Argon2id(salt)--> key          (or you supply a 32-byte key)
output = header | nonce(24) | ciphertext | tag(16)
header = "BAT1" | mode | KDF settings | salt        (stored in clear; needed to decrypt)
```
The header **and your `context`** are fed in as "associated data". They are not encrypted, but they are
authenticated: change one bit of the header, or decrypt with a different context, and it fails.

### Big data (`encrypt_stream` / `encrypt_file`)
```
header = "BATF" | mode | KDF settings | salt | file_id(16) | chunk_size
body   = chunk 0 | chunk 1 | ... | final chunk        (default 1 MiB each)
```
- Each chunk is encrypted separately with its own random nonce.
- Each chunk's authenticated data = header + context + **chunk number** + **"is this the last chunk"**.
  So an attacker cannot reorder, duplicate, swap in chunks from another file, or silently cut the file short.
- `decrypt_file` writes to a temporary file and renames it only after every chunk verified.

### Why a "context" string?
Set it to say what the data is, e.g. `b"myapp/user/42/profile"`. Then an encrypted blob cannot be
copied from one place in your app to another and still decrypt. Use it every time.

---------------------------------------------------------------------------------------------

## 4. Rules for integrating BAT into another project

1. **Key safety is everything.** Encryption is only as strong as the password or where you keep the key.
   Use a long random passphrase (6+ random words). Never hard-code keys or commit them to git.
2. **Always use a `context`**, different for each kind of data.
3. **Never reuse one raw key for unrelated jobs**; use `derive_subkey`.
4. **Lost key/password = lost data.** Add a recovery plan (e.g. wrap your key with a second recovery key).
5. **Large data**: use the stream/file functions, not `encrypt`, which holds everything in memory.
6. **Store the encrypted output as-is.** Do not edit headers; do not strip them.
7. **Don't parse or trust data before decrypting it**; decryption success means "authentic and unmodified".
8. If you need random access (seeking inside a huge file) or a multi-file container, see the companion
   "vaultcore" prototype, or design chunk indexes yourself with per-chunk keys and authenticated indexes.

---------------------------------------------------------------------------------------------

## 5. What BAT does NOT do (honest limits)

- **No protection from malware or a compromised device** while data is decrypted in memory.
- **Not rollback-proof**: someone can restore an older valid encrypted copy; encryption can't tell it's old.
  If that matters, add your own version numbers inside your data format.
- **Python cannot reliably wipe keys from memory**; no memory locking. For high-security use, rewrite
  the same design in Rust/C with libsodium.
- **Lengths leak**: ciphertext size reveals approximate plaintext size. No padding is applied.
- **No password recovery** and no key rotation tooling is included.
- **ChaCha20-Poly1305 with an HKDF-extended nonce** is used because the `cryptography` package has no
  XChaCha20. It is a standard construction, but production systems should prefer libsodium's
  XChaCha20-Poly1305 or Google Tink. The BAT file format would need a new version number for that.
- **Not interoperable** with other tools: BAT's header/chunk format is its own.
- **Unaudited.** Do not use it for irreplaceable or life-critical data before an independent review.

---------------------------------------------------------------------------------------------

## 6. Format reference (for re-implementing or porting)

All integers little-endian. Overhead per sealed piece = 24 (nonce) + 16 (tag) = 40 bytes.

```
sealed(key, plaintext, aad):
    nonce24 = random(24)
    subkey  = HKDF-SHA256(key, salt=nonce24[0:16], info="vault3/ext-nonce")
    ct|tag  = ChaCha20-Poly1305(subkey).encrypt(nonce = nonce24[16:24] + 00 00 00 00, plaintext, aad)
    return nonce24 | ct | tag

blob   : "BAT1" | mode u8 (1=password, 2=key) | m u32 (KiB) | t u32 | p u8 | salt16 | sealed(key, data, aad = header | context)
file   : "BATF" | mode | m | t | p | salt16 | file_id16 | chunk_size u32 | frames...
         key       = HKDF-SHA256(base_key, salt=file_id, info="bat/stream-key")
         frame i   = sealed(key, chunk_i, aad = header | context | i u64 | final u8)   (final=1 only on the last frame)
base_key = Argon2id(NFKC(password).utf8, salt, m, t, p) -> 32 bytes   (or the raw 32-byte key)
Argon2id limits enforced BEFORE running the KDF: m 8 MiB..4 GiB, t 1..16, p 1..16. Chunk size <= 16 MiB.
```

## 7. Files
```
bat/core.py   primitives (seal/open, HKDF, Argon2id, hashing, random)
bat/api.py    encrypt/decrypt, streams, files, subkeys, errors
bat/__main__.py   command-line tool
tests/        7 tests (tampering, truncation, reordering, wrong context, bad headers, atomic files)
```
