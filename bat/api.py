"""BAT high-level API: encrypt/decrypt bytes, streams and files with a password or a 32-byte key."""
import os
import struct

from .core import (AuthError, OVERHEAD, check_kdf_params, hkdf, kdf_argon2,
                   normalize_password, open_, rand, seal)

DEFAULT_KDF = (262144, 3, 4)          # 256 MiB, 3 passes, 4 lanes
FAST_KDF = (8192, 1, 1)               # testing only
MODE_PW, MODE_KEY = 1, 2
MAX_CHUNK = 16 << 20
_BLOB_MAGIC, _FILE_MAGIC = b"BAT1", b"BATF"
_BLOB_HDR = 4 + 1 + 9 + 16            # magic|mode|m,t,p|salt
_FILE_HDR = _BLOB_HDR + 16 + 4        # ...|file_id|chunk_size


class DecryptionError(Exception):
    """Wrong password/key, wrong context, or the data was modified."""


class FormatError(Exception):
    """Input is not valid BAT data (bad header, bad parameters, truncated)."""


def generate_key() -> bytes:
    return rand(32)


def derive_subkey(key: bytes, purpose: bytes) -> bytes:
    """Make a separate key for each purpose from one master key."""
    return hkdf(key, b"bat/subkey", purpose)


def _mode(secret, kdf):
    if isinstance(secret, str):
        check_kdf_params(*kdf)
        return MODE_PW, kdf, rand(16)
    if isinstance(secret, (bytes, bytearray)) and len(secret) == 32:
        return MODE_KEY, (0, 0, 0), b"\0" * 16
    raise TypeError("secret must be a password (str) or a 32-byte key (bytes)")


def _base_key(mode, secret, params, salt):
    if mode == MODE_PW:
        if not isinstance(secret, str):
            raise DecryptionError("this data was encrypted with a password")
        try:
            check_kdf_params(*params)               # bounds BEFORE the slow KDF
        except ValueError:
            raise FormatError("KDF parameters out of bounds")
        return kdf_argon2(normalize_password(secret), salt, *params)
    if mode == MODE_KEY:
        if not (isinstance(secret, (bytes, bytearray)) and len(secret) == 32):
            raise DecryptionError("this data was encrypted with a 32-byte key")
        return bytes(secret)
    raise FormatError("unknown mode")


def _header(magic, mode, params, salt):
    return magic + bytes([mode]) + struct.pack("<IIB", *params) + salt


def _parse(hdr, magic):
    if len(hdr) < _BLOB_HDR or hdr[:4] != magic:
        raise FormatError("not BAT data")
    mode = hdr[4]
    params = struct.unpack("<IIB", hdr[5:14])
    return mode, params, hdr[14:30]


# ------------------------------------------------------------ small data
def encrypt(data: bytes, secret, *, context: bytes = b"", kdf=DEFAULT_KDF) -> bytes:
    """Encrypt bytes. `secret` = password (str) or 32-byte key. `context` must match on decrypt."""
    mode, params, salt = _mode(secret, kdf)
    hdr = _header(_BLOB_MAGIC, mode, params, salt)
    key = _base_key(mode, secret, params, salt)
    return hdr + seal(key, data, hdr + context)


def decrypt(blob: bytes, secret, *, context: bytes = b"") -> bytes:
    mode, params, salt = _parse(blob[:_BLOB_HDR], _BLOB_MAGIC)
    key = _base_key(mode, secret, params, salt)
    try:
        return open_(key, blob[_BLOB_HDR:], blob[:_BLOB_HDR] + context)
    except AuthError:
        raise DecryptionError("wrong password/key, wrong context, or data was modified")


# ------------------------------------------------------------ big data (streams)
def _read_full(f, n):
    buf = b""
    while len(buf) < n:
        part = f.read(n - len(buf))
        if not part:
            break
        buf += part
    return buf


def encrypt_stream(src, dst, secret, *, context=b"", chunk_size=1 << 20, kdf=DEFAULT_KDF):
    """Chunked encryption. Each chunk is bound to its position and to 'final', so
    reordering, dropping or truncating chunks is detected."""
    if not 0 < chunk_size <= MAX_CHUNK:
        raise ValueError("chunk_size out of range")
    mode, params, salt = _mode(secret, kdf)
    file_id = rand(16)
    hdr = _header(_FILE_MAGIC, mode, params, salt) + file_id + struct.pack("<I", chunk_size)
    key = hkdf(_base_key(mode, secret, params, salt), file_id, b"bat/stream-key")
    dst.write(hdr)
    idx, cur = 0, _read_full(src, chunk_size)
    while True:
        nxt = _read_full(src, chunk_size) if cur else b""
        final = not nxt
        dst.write(seal(key, cur, hdr + context + struct.pack("<QB", idx, 1 if final else 0)))
        if final:
            return
        cur, idx = nxt, idx + 1


def decrypt_stream(src, dst, secret, *, context=b""):
    """NOTE: chunks are written as each one verifies; truncation is only known at the end.
    Use decrypt_file() (writes a temp file, renames on success) when that matters."""
    hdr = _read_full(src, _FILE_HDR)
    if len(hdr) < _FILE_HDR:
        raise FormatError("truncated header")
    mode, params, salt = _parse(hdr, _FILE_MAGIC)
    file_id = hdr[30:46]
    (chunk_size,) = struct.unpack("<I", hdr[46:50])
    if not 0 < chunk_size <= MAX_CHUNK:
        raise FormatError("bad chunk size")
    key = hkdf(_base_key(mode, secret, params, salt), file_id, b"bat/stream-key")
    fsz = chunk_size + OVERHEAD
    cur = _read_full(src, fsz)
    idx = 0
    while True:
        nxt = _read_full(src, fsz)
        final = not nxt
        if not final and len(cur) != fsz:
            raise FormatError("malformed chunk")
        try:
            pt = open_(key, cur, hdr + context + struct.pack("<QB", idx, 1 if final else 0))
        except AuthError:
            raise DecryptionError("wrong password/key, wrong context, or data was modified/truncated")
        dst.write(pt)
        if final:
            return
        cur, idx = nxt, idx + 1


def encrypt_file(path_in, path_out, secret, **kw):
    tmp = path_out + ".tmp"
    try:
        with open(path_in, "rb") as s, open(tmp, "xb") as d:
            encrypt_stream(s, d, secret, **kw)
            d.flush(); os.fsync(d.fileno())
        os.replace(tmp, path_out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def decrypt_file(path_in, path_out, secret, **kw):
    tmp = path_out + ".tmp"
    try:
        with open(path_in, "rb") as s, open(tmp, "xb") as d:
            decrypt_stream(s, d, secret, **kw)
            d.flush(); os.fsync(d.fileno())
        os.replace(tmp, path_out)         # only appears if EVERYTHING verified
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
