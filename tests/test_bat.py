import io, os, sys, tempfile, unittest, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bat
from bat import *
from bat.core import check_kdf_params

F = FAST_KDF


class T(unittest.TestCase):
    def test_blob_password_and_key(self):
        b = encrypt(b"secret", "pass phrase", kdf=F)
        self.assertEqual(decrypt(b, "pass phrase"), b"secret")
        k = generate_key()
        self.assertEqual(decrypt(encrypt(b"x" * 1000, k), k), b"x" * 1000)

    def test_wrong_secret_context_tamper(self):
        b = encrypt(b"secret", "pw", context=b"app/a", kdf=F)
        with self.assertRaises(DecryptionError): decrypt(b, "other", context=b"app/a")
        with self.assertRaises(DecryptionError): decrypt(b, "pw", context=b"app/b")
        t = bytearray(b); t[-1] ^= 1
        with self.assertRaises(DecryptionError): decrypt(bytes(t), "pw", context=b"app/a")
        with self.assertRaises(DecryptionError): decrypt(encrypt(b"x", generate_key()), "pw")

    def test_not_bat_and_bad_params(self):
        with self.assertRaises(FormatError): decrypt(b"garbage" * 20, "pw")
        b = bytearray(encrypt(b"x", "pw", kdf=F)); b[5:9] = (2**31 - 1).to_bytes(4, "little")
        with self.assertRaises(FormatError): decrypt(bytes(b), "pw")      # header edit refused before KDF
        for bad in ((2**31, 3, 4), (8192, 10**6, 1), (1, 1, 1)):
            with self.assertRaises(ValueError): check_kdf_params(*bad)

    def test_stream_sizes(self):
        k = generate_key()
        for n in (0, 1, 999, 1000, 1001, 3000, 3500):
            data = os.urandom(n)
            e, o = io.BytesIO(), io.BytesIO()
            encrypt_stream(io.BytesIO(data), e, k, chunk_size=1000)
            decrypt_stream(io.BytesIO(e.getvalue()), o, k)
            self.assertEqual(o.getvalue(), data, n)

    def test_stream_truncate_reorder_context(self):
        k = generate_key()
        e = io.BytesIO(); encrypt_stream(io.BytesIO(os.urandom(3500)), e, k, chunk_size=1000, context=b"c")
        blob, fsz, hs = e.getvalue(), 1000 + 40, 50
        def dec(b, ctx=b"c"):
            output = io.BytesIO()
            with self.assertRaises(DecryptionError):
                decrypt_stream(io.BytesIO(b), output, k, context=ctx)
            self.assertEqual(output.getvalue(), b"")
        decrypt_stream(io.BytesIO(blob), io.BytesIO(), k, context=b"c")
        dec(blob[:hs + 2 * fsz])            # cut at chunk boundary
        dec(blob[:-5])                      # cut mid-chunk
        c = [blob[hs + i * fsz: hs + (i + 1) * fsz] for i in range(3)]
        swapped = blob[:hs] + c[1] + c[0] + c[2] + blob[hs + 3 * fsz:]
        dec(swapped)                        # reorder
        dec(blob, b"x")                     # wrong context

    def test_files_atomic(self):
        d = tempfile.mkdtemp()
        try:
            src, enc, out = (os.path.join(d, n) for n in ("a", "a.bat", "a.out"))
            data = os.urandom(2_500_000); open(src, "wb").write(data)
            encrypt_file(src, enc, "pw", kdf=F)
            self.assertNotIn(data[:64], open(enc, "rb").read())
            decrypt_file(enc, out, "pw"); self.assertEqual(open(out, "rb").read(), data)
            raw = bytearray(open(enc, "rb").read()); raw[-3] ^= 1; open(enc, "wb").write(raw)
            os.remove(out)
            with self.assertRaises(DecryptionError): decrypt_file(enc, out, "pw")
            self.assertFalse(os.path.exists(out)); self.assertFalse(os.path.exists(out + ".tmp"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_subkeys_and_type_errors(self):
        k = generate_key()
        self.assertNotEqual(derive_subkey(k, b"a"), derive_subkey(k, b"b"))
        with self.assertRaises(TypeError): encrypt(b"x", b"short")
        with self.assertRaises(TypeError): encrypt(b"x", 123)


if __name__ == "__main__":
    unittest.main(verbosity=2)
