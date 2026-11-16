"""python -m bat encrypt|decrypt|keygen ...   (password: prompt or env BAT_PASSWORD)"""
import argparse, getpass, os, sys
from . import (encrypt_file, decrypt_file, generate_key, DecryptionError, FormatError,
               DEFAULT_KDF, FAST_KDF)
from .api import _secure_create


def _secret(a, confirm=False):
    if a.keyfile:
        k = open(a.keyfile, "rb").read()
        if len(k) != 32:
            sys.exit("keyfile must be exactly 32 bytes (use: python -m bat keygen FILE)")
        return k
    pw = os.environ.get("BAT_PASSWORD")
    if pw is None:
        pw = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Repeat: ") != pw:
            sys.exit("passwords differ")
    return pw


def main(argv=None):
    p = argparse.ArgumentParser(prog="bat")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("encrypt", "decrypt"):
        s = sub.add_parser(name)
        s.add_argument("input"); s.add_argument("output")
        s.add_argument("--keyfile")
        if name == "encrypt":
            s.add_argument("--fast", action="store_true", help="weak KDF, testing only")
    k = sub.add_parser("keygen"); k.add_argument("file")
    a = p.parse_args(argv)
    try:
        if a.cmd == "keygen":
            with _secure_create(a.file) as f:
                f.write(generate_key())
            print("wrote 32-byte key:", a.file, "(back it up; losing it loses your data)")
        elif a.cmd == "encrypt":
            encrypt_file(a.input, a.output, _secret(a, True), kdf=FAST_KDF if a.fast else DEFAULT_KDF)
            print("encrypted ->", a.output)
        else:
            decrypt_file(a.input, a.output, _secret(a))
            print("decrypted ->", a.output)
        return 0
    except (DecryptionError, FormatError, OSError, TypeError, ValueError) as e:
        print("error:", e, file=sys.stderr)
        return 2


sys.exit(main())
