import os
import stat
import tempfile
import unittest

from src import vault


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keyfile = os.path.join(self.tmp.name, "k", "vault.key")
        os.environ["PII_VAULT_KEY_FILE"] = self.keyfile
        vault.keygen()
        self.doc = "CURP: GODE561231HDFXXX09\nCorreo: ana@example.com\n".encode("utf-8")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("PII_VAULT_KEY_FILE", None)

    def backends(self):
        out = [vault._LibcryptoBackend()]
        try:
            out.append(vault._CryptographyBackend())
        except ImportError:
            pass
        return out

    def test_key_file_is_private(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.keyfile).st_mode), 0o600)

    def test_round_trip_every_backend(self):
        for b in self.backends():
            blob = vault.encrypt_bytes(self.doc, backend=b)
            self.assertNotIn(b"GODE561231", blob)
            self.assertEqual(vault.decrypt_bytes(blob, backend=b), self.doc)

    def test_backends_are_interoperable(self):
        bs = self.backends()
        if len(bs) < 2:
            self.skipTest("only one backend installed")
        blob = vault.encrypt_bytes(self.doc, backend=bs[0])
        self.assertEqual(vault.decrypt_bytes(blob, backend=bs[1]), self.doc)

    def test_tampered_ciphertext_is_rejected(self):
        for b in self.backends():
            blob = bytearray(vault.encrypt_bytes(self.doc, backend=b))
            blob[-20] ^= 1
            with self.assertRaises(vault.VaultError):
                vault.decrypt_bytes(bytes(blob), backend=b)

    def test_wrong_key_is_rejected(self):
        blob = vault.encrypt_bytes(self.doc)
        with self.assertRaises(vault.VaultError):
            vault.decrypt_bytes(blob, key=b"\x01" * 32)

    def test_file_round_trip_and_shred(self):
        src = os.path.join(self.tmp.name, "cv.txt")
        with open(src, "wb") as fh:
            fh.write(self.doc)
        enc = vault.encrypt_file(src, shred=True)
        self.assertFalse(os.path.exists(src))
        self.assertEqual(vault.open_document(enc), self.doc.decode("utf-8"))

    def test_world_readable_key_is_refused(self):
        os.chmod(self.keyfile, 0o644)
        with self.assertRaises(vault.VaultError):
            vault.load_key()

    def test_encrypted_hmac_key_is_used_by_crypto_config(self):
        from src import crypto_config
        plain = os.path.join(self.tmp.name, "hmac.key")
        with open(plain, "w") as fh:
            fh.write("cd" * 64)
        enc = vault.encrypt_file(plain, shred=True)
        os.environ.pop("PII_HMAC_KEY", None)
        os.environ["PII_HMAC_KEY_FILE"] = enc
        try:
            self.assertEqual(crypto_config.hmac_key(required=True), bytes.fromhex("cd" * 64))
        finally:
            os.environ.pop("PII_HMAC_KEY_FILE", None)


if __name__ == "__main__":
    unittest.main()


class VaultFailurePaths(unittest.TestCase):
    """B3: corrupted inputs, wrong keys, tampering, bad key files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["PII_VAULT_KEY_FILE"] = os.path.join(self.tmp.name, "k", "vault.key")
        vault.keygen()
        self.blob = vault.encrypt_bytes(b"CURP: GODE561231HDFXXX09")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("PII_VAULT_KEY_FILE", None)

    def backends(self):
        out = [vault._LibcryptoBackend()]
        try:
            out.append(vault._CryptographyBackend())
        except ImportError:
            pass
        return out

    def test_empty_and_short_inputs(self):
        for bad in (b"", b"PIIV1", self.blob[:20], self.blob[:-17]):
            with self.subTest(n=len(bad)), self.assertRaises(vault.VaultError):
                vault.decrypt_bytes(bad)

    def test_wrong_magic(self):
        with self.assertRaises(vault.VaultError):
            vault.decrypt_bytes(b"XXXXX" + self.blob[5:])

    def test_tampered_header_key_id(self):
        b = bytearray(self.blob); b[6] ^= 1
        with self.assertRaises(vault.VaultError):
            vault.decrypt_bytes(bytes(b))

    def test_every_region_tampered_is_rejected(self):
        hlen = len(vault.MAGIC) + 8
        regions = {"nonce": hlen + 1, "ciphertext": hlen + vault.NONCE_LEN + 1, "tag": len(self.blob) - 1}
        for b in self.backends():
            for name, i in regions.items():
                with self.subTest(backend=b.name, region=name):
                    t = bytearray(self.blob); t[i] ^= 0x80
                    with self.assertRaises(vault.VaultError):
                        vault.decrypt_bytes(bytes(t), backend=b)

    def test_truncated_tag(self):
        for b in self.backends():
            with self.subTest(backend=b.name), self.assertRaises(vault.VaultError):
                vault.decrypt_bytes(self.blob[:-1], backend=b)

    def test_wrong_key_same_length(self):
        with self.assertRaises(vault.VaultError):
            vault.decrypt_bytes(self.blob, key=os.urandom(32))

    def test_errors_do_not_leak_plaintext(self):
        t = bytearray(self.blob); t[-1] ^= 1
        try:
            vault.decrypt_bytes(bytes(t))
        except vault.VaultError as exc:
            self.assertNotIn("GODE561231", str(exc))

    def test_bad_key_files(self):
        path = os.environ["PII_VAULT_KEY_FILE"]
        cases = {"not hex": "zz" * 32, "too short": "ab" * 16, "empty": ""}
        for name, content in cases.items():
            with self.subTest(case=name):
                with open(path, "w") as fh:
                    fh.write(content)
                os.chmod(path, 0o600)
                with self.assertRaises((vault.VaultError, ValueError)):
                    vault.load_key()

    def test_missing_key_file(self):
        os.remove(os.environ["PII_VAULT_KEY_FILE"])
        with self.assertRaises(vault.VaultError):
            vault.load_key()

    def test_keygen_refuses_overwrite(self):
        with self.assertRaises(vault.VaultError):
            vault.keygen()

    def test_open_document_on_plaintext_file(self):
        p = os.path.join(self.tmp.name, "plain.txt")
        with open(p, "w") as fh:
            fh.write("CURP: GODE561231HDFXXX09")
        with self.assertRaises(vault.VaultError):
            vault.open_document(p)
