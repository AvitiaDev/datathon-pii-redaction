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
