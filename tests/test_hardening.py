"""Adversarial / known-answer tests. Run: python -m unittest tests.test_hardening -v"""
import io, os, random, resource, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bat
from bat import *
from bat.core import hkdf
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

EXPECTED = (DecryptionError, FormatError)


class KnownAnswers(unittest.TestCase):
    def test_chacha20poly1305_rfc8439(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
              b"tip for the future, sunscreen would be it.")
        ct = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        self.assertEqual(ct[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")

    def test_hkdf_rfc5869_case1(self):
        okm = hkdf(bytes.fromhex("0b" * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                    "34007208d5b887185865")

    def test_argon2id_rfc9106(self):
        tag = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32,
                       secret=b"\x03" * 8, ad=b"\x04" * 12).derive(b"\x01" * 32)
        self.assertEqual(tag.hex(), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")


class Adversarial(unittest.TestCase):
    def test_every_byte_bitflip_and_truncation_blob(self):
        k = generate_key()
        blob = encrypt(b"top secret payload " * 3, k, context=b"c")
        for i in range(len(blob)):
            for bit in range(8):
                t = bytearray(blob); t[i] ^= 1 << bit
                with self.assertRaises(EXPECTED, msg=f"byte {i} bit {bit}"):
                    decrypt(bytes(t), k, context=b"c")
        for n in range(len(blob)):
            with self.assertRaises(EXPECTED, msg=f"trunc {n}"):
                decrypt(blob[:n], k, context=b"c")
        with self.assertRaises(EXPECTED):
            decrypt(blob + b"\0", k, context=b"c")           # appended junk

    def test_every_byte_flip_and_truncation_stream(self):
        k = generate_key()
        e = io.BytesIO(); encrypt_stream(io.BytesIO(os.urandom(250)), e, k, chunk_size=100, context=b"c")
        blob = e.getvalue()
        dec = lambda b: decrypt_stream(io.BytesIO(b), io.BytesIO(), k, context=b"c")
        dec(blob)
        for i in range(len(blob)):
            t = bytearray(blob); t[i] ^= 0x01
            with self.assertRaises(EXPECTED, msg=f"flip {i}"): dec(bytes(t))
        for n in range(len(blob)):
            with self.assertRaises(EXPECTED, msg=f"trunc {n}"): dec(blob[:n])
        with self.assertRaises(EXPECTED): dec(blob + b"x")

    def test_password_mode_header_flips(self):
        blob = encrypt(b"data", "pw", kdf=FAST_KDF)
        for i in list(range(0, 9)) + list(range(13, len(blob))):   # skip m,t bytes (would just run big KDF)
            t = bytearray(blob); t[i] ^= 1
            with self.assertRaises(EXPECTED, msg=f"byte {i}"): decrypt(bytes(t), "pw")

    def test_fuzz_garbage_never_crashes(self):
        rnd = random.Random(1234)
        k = generate_key()
        for _ in range(3000):
            n = rnd.choice([0, 1, 5, 29, 30, 49, 50, 51, 100, 500])
            junk = bytes(rnd.getrandbits(8) for _ in range(n))
            if rnd.random() < .5 and n >= 4:
                junk = (b"BAT1" if rnd.random() < .5 else b"BATF") + junk[4:]
                if len(junk) > 5: junk = junk[:4] + b"\x02" + junk[5:]   # key mode: avoid KDF
            for fn in (lambda: decrypt(junk, k), lambda: decrypt_stream(io.BytesIO(junk), io.BytesIO(), k)):
                try: fn()
                except EXPECTED: pass

    def test_property_roundtrip(self):
        rnd = random.Random(7); k = generate_key()
        for _ in range(300):
            data = os.urandom(rnd.choice([0, 1, 15, 16, 17, 255, 4096, 70000]))
            ctx = os.urandom(rnd.randrange(0, 40))
            self.assertEqual(decrypt(encrypt(data, k, context=ctx), k, context=ctx), data)
            cs = rnd.choice([1, 7, 100, 4096])
            if len(data) // cs > 500: cs = 4096
            e, o = io.BytesIO(), io.BytesIO()
            encrypt_stream(io.BytesIO(data), e, k, context=ctx, chunk_size=cs)
            decrypt_stream(io.BytesIO(e.getvalue()), o, k, context=ctx)
            self.assertEqual(o.getvalue(), data)

    def test_nonce_uniqueness_and_randomised_output(self):
        k = generate_key(); seen = set()
        for _ in range(100_000):
            seen.add(encrypt(b"same", k)[30:54])
        self.assertEqual(len(seen), 100_000)
        self.assertNotEqual(encrypt(b"same", k), encrypt(b"same", k))

    def test_wrong_keys_and_cross_format(self):
        k = generate_key(); b = encrypt(b"x", k)
        for _ in range(500):
            with self.assertRaises(DecryptionError): decrypt(b, generate_key())
        e = io.BytesIO(); encrypt_stream(io.BytesIO(b"hello"), e, k)
        with self.assertRaises(EXPECTED): decrypt(e.getvalue(), k)                       # stream as blob
        with self.assertRaises(EXPECTED): decrypt_stream(io.BytesIO(b), io.BytesIO(), k)  # blob as stream

    def test_unicode_normalisation(self):
        b = encrypt(b"x", "caf\u00e9 pass", kdf=FAST_KDF)
        self.assertEqual(decrypt(b, "cafe\u0301 pass"), b"x")

    def test_large_stream_bounded_memory(self):
        class Gen:                                   # 96 MiB of data, never held in memory
            def __init__(s): s.left = 96 << 20
            def read(s, n):
                n = min(n, s.left); s.left -= n; return b"\xAB" * n
        class Sink:
            def __init__(s): s.n = 0
            def write(s, b): s.n += len(b)
        k = generate_key(); tmp = io.BytesIO()
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        class Spool:
            def __init__(s): s.f = open("/tmp/bat_big.bin", "wb")
            def write(s, b): s.f.write(b)
        sp = Spool(); encrypt_stream(Gen(), sp, k); sp.f.close()
        sink = Sink(); decrypt_stream(open("/tmp/bat_big.bin", "rb"), sink, k)
        os.remove("/tmp/bat_big.bin")
        self.assertEqual(sink.n, 96 << 20)
        grew_mb = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) / 1024
        self.assertLess(grew_mb, 60, f"memory grew {grew_mb:.0f} MB")


if __name__ == "__main__":
    unittest.main(verbosity=2)
