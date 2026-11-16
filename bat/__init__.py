"""BAT - a small, reusable encryption toolkit built only from standard, vetted primitives."""
from .api import (encrypt, decrypt, encrypt_stream, decrypt_stream, encrypt_file, decrypt_file,
                  generate_key, derive_subkey, DecryptionError, FormatError,
                  DEFAULT_KDF, FAST_KDF)
from .core import seal, open_, hkdf, rand, b2, kdf_argon2, AuthError
__version__ = "1.0.0"
__all__ = ["encrypt", "decrypt", "encrypt_stream", "decrypt_stream", "encrypt_file", "decrypt_file",
           "generate_key", "derive_subkey", "DecryptionError", "FormatError", "DEFAULT_KDF",
           "FAST_KDF", "seal", "open_", "hkdf", "rand", "b2", "kdf_argon2", "AuthError"]
