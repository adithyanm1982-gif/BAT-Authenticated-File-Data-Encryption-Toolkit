"""BAT core: thin wrappers over vetted primitives from the `cryptography` package.

No custom ciphers. Extended-nonce AEAD: the sandbox/library has no XChaCha20, so
we use the standard HKDF-based extended-nonce construction on top of
ChaCha20-Poly1305: a fresh 24-byte random nonce -> HKDF(key, nonce[:16]) gives a
one-time subkey, nonce[16:] + 4 zero bytes is the 96-bit nonce. Production code
should use libsodium's XChaCha20-Poly1305 instead (same interface).
"""
import hashlib
import os
import struct
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 24
TAG_LEN = 16
OVERHEAD = NONCE_LEN + TAG_LEN

M_MIN, M_MAX = 8192, 4 * 1024 * 1024      # KiB (8 MiB .. 4 GiB)
T_MIN, T_MAX = 1, 16
P_MIN, P_MAX = 1, 16


class AuthError(Exception):
    pass


def rand(n: int) -> bytes:
    return os.urandom(n)          # OS CSPRNG only


def b2(data: bytes, domain: bytes = b"") -> bytes:
    """BLAKE2b with a native 32-byte digest, domain-separated."""
    h = hashlib.blake2b(digest_size=32)
    h.update(struct.pack("<H", len(domain)) + domain)
    h.update(data)
    return h.digest()


def hkdf(key: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = rand(NONCE_LEN)
    subkey = hkdf(key, nonce[:16], b"vault3/ext-nonce")
    ct = ChaCha20Poly1305(subkey).encrypt(nonce[16:] + b"\0\0\0\0", plaintext, aad)
    return nonce + ct


def open_(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < OVERHEAD:
        raise AuthError("short blob")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    subkey = hkdf(key, nonce[:16], b"vault3/ext-nonce")
    try:
        return ChaCha20Poly1305(subkey).decrypt(nonce[16:] + b"\0\0\0\0", ct, aad)
    except InvalidTag:
        raise AuthError("authentication failed")


def check_kdf_params(m: int, t: int, p: int) -> None:
    """Hard format bounds, enforced BEFORE running the KDF on untrusted headers."""
    if not (M_MIN <= m <= M_MAX and T_MIN <= t <= T_MAX and P_MIN <= p <= P_MAX):
        raise ValueError("Argon2id parameters out of bounds")


def normalize_password(pw: str) -> bytes:
    b = unicodedata.normalize("NFKC", pw).encode("utf-8")
    if not b or len(b) > 1024:
        raise ValueError("password must be 1..1024 bytes")
    return b


def kdf_argon2(password: bytes, salt: bytes, m: int, t: int, p: int) -> bytes:
    check_kdf_params(m, t, p)
    return Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m).derive(password)
