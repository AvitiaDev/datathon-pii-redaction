"""B2: key creation permissions, overwrite refusal, invalid config, sign/verify failure paths.

ML-DSA is exercised with a tiny fake `oqs` module so these tests run in CI
without liboqs; the real library is covered by tests that skip when absent.
"""
import hashlib
import hmac as _hmac
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fake_oqs():
    m = types.ModuleType("oqs")

    class Signature:
        def __init__(self, alg, secret_key=None):
            self.alg, self.sk = alg, secret_key

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def generate_keypair(self):
            self.sk = os.urandom(32)
            return hashlib.sha256(self.sk).digest()

        def export_secret_key(self):
            return self.sk

        def sign(self, msg):
            return _hmac.new(hashlib.sha256(self.sk).digest(), msg, "sha256").digest()

        def verify(self, msg, sig, pk):
            if len(sig) != 32:
                raise RuntimeError("malformed signature")
            return _hmac.compare_digest(_hmac.new(pk, msg, "sha256").digest(), sig)

    m.Signature = Signature
    return m


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class MlDsaKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.kd = os.path.join(self.tmp.name, "keys")
        self.patch = mock.patch.dict(sys.modules, {"oqs": _fake_oqs()})
        self.patch.start()
        from src.signers import MlDsaSigner
        self.S = MlDsaSigner

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_private_key_created_0600_dir_0700(self):
        self.S.keygen("ml-dsa-65", self.kd)
        self.assertEqual(mode(os.path.join(self.kd, "mldsa_private.key")), 0o600)
        self.assertEqual(mode(self.kd) & 0o077, 0)

    def test_keygen_refuses_overwrite(self):
        self.S.keygen("ml-dsa-65", self.kd)
        before = open(os.path.join(self.kd, "mldsa_private.key"), "rb").read()
        with self.assertRaises(FileExistsError):
            self.S.keygen("ml-dsa-65", self.kd)
        self.assertEqual(open(os.path.join(self.kd, "mldsa_private.key"), "rb").read(), before)

    def test_keygen_refuses_if_only_public_exists(self):
        os.makedirs(self.kd)
        open(os.path.join(self.kd, "mldsa_public.key"), "wb").write(b"x")
        with self.assertRaises(FileExistsError):
            self.S.keygen("ml-dsa-65", self.kd)
        self.assertFalse(os.path.exists(os.path.join(self.kd, "mldsa_private.key")))

    def test_world_readable_private_key_refused(self):
        self.S.keygen("ml-dsa-65", self.kd)
        os.chmod(os.path.join(self.kd, "mldsa_private.key"), 0o644)
        with self.assertRaises(PermissionError):
            self.S("ml-dsa-65", key_dir=self.kd)
        self.S("ml-dsa-65", key_dir=self.kd, verify_only=True)  # verifying needs only the public key

    def test_missing_keys_give_clear_error(self):
        with self.assertRaises(RuntimeError) as cm:
            self.S("ml-dsa-65", key_dir=self.kd)
        self.assertIn("keygen", str(cm.exception))

    def test_unknown_variant(self):
        with self.assertRaises(ValueError):
            self.S("ml-dsa-99", key_dir=self.kd)

    def test_sign_verify_and_failures(self):
        self.S.keygen("ml-dsa-65", self.kd)
        s = self.S("ml-dsa-65", key_dir=self.kd)
        sig = s.sign(b"entry")
        self.assertTrue(s.verify(b"entry", sig))
        self.assertFalse(s.verify(b"entrY", sig))
        for bad in ("zz-not-hex", "", "00", None, 123):
            with self.subTest(bad=bad):
                self.assertFalse(s.verify(b"entry", bad))

    def test_verify_only_cannot_sign(self):
        self.S.keygen("ml-dsa-65", self.kd)
        v = self.S("ml-dsa-65", key_dir=self.kd, verify_only=True)
        with self.assertRaises(RuntimeError):
            v.sign(b"x")

    def test_for_entry_matches_only_own_alg(self):
        self.S.keygen("ml-dsa-65", self.kd)
        s = self.S("ml-dsa-65", key_dir=self.kd)
        self.assertIs(s.for_entry("ML-DSA-65"), s)
        self.assertIsNone(s.for_entry("ML-DSA-44"))
        self.assertIsNone(s.for_entry("HMAC-SHA512"))

    def test_mldsa_audit_log_roundtrip(self):
        from src.audit import AuditLog, verify_log
        self.S.keygen("ml-dsa-65", self.kd)
        with mock.patch.dict(os.environ, {"PII_HMAC_KEY": "ab" * 64}):
            os.environ.pop("PII_HMAC_KEY_FILE", None)
            path = os.path.join(self.tmp.name, "a.jsonl")
            log = AuditLog(path, signer=self.S("ml-dsa-65", key_dir=self.kd))
            log.record("x", "x", [])
            log.record("y", "y", [])
            self.assertTrue(verify_log(path, self.S("ml-dsa-65", key_dir=self.kd, verify_only=True))["ok"])


class HmacAndConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = mock.patch.dict(os.environ, {}, clear=False)
        self.p.start()
        for k in ("PII_HMAC_KEY", "PII_HMAC_KEY_FILE", "PII_HASH_ALG", "PII_SIGNER"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def _keyfile(self, content, perm=0o600):
        path = os.path.join(self.tmp.name, "hmac.key")
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, perm)
        os.environ["PII_HMAC_KEY_FILE"] = path
        return path

    def test_world_readable_plain_key_refused(self):
        from src import crypto_config
        self._keyfile("ab" * 64, 0o644)
        with self.assertRaises(PermissionError):
            crypto_config.hmac_key(required=True)

    def test_non_hex_key_error_does_not_echo_key(self):
        from src import crypto_config
        secret = "not-hex-SECRETVALUE-" * 4
        self._keyfile(secret)
        with self.assertRaises(ValueError) as cm:
            crypto_config.hmac_key(required=True)
        self.assertNotIn("SECRETVALUE", str(cm.exception))

    def test_short_key_rejected(self):
        from src import crypto_config
        self._keyfile("ab" * 8)
        with self.assertRaises(ValueError):
            crypto_config.hmac_key(required=True)

    def test_missing_key_when_required(self):
        from src import crypto_config
        with self.assertRaises(RuntimeError):
            crypto_config.hmac_key(required=True)

    def test_invalid_hash_alg(self):
        from src import crypto_config
        for bad in ("md5", "sha1", "blake2b", "nope"):
            with self.subTest(bad=bad), mock.patch.dict(os.environ, {"PII_HASH_ALG": bad}):
                with self.assertRaises(ValueError):
                    crypto_config.hash_alg()

    def test_unknown_signer_name(self):
        from src.signers import get_signer
        os.environ["PII_HMAC_KEY"] = "ab" * 64
        with self.assertRaises(ValueError):
            get_signer("rsa")

    def test_hmac_verify_bad_inputs(self):
        from src.signers import HmacSigner
        s = HmacSigner(key=b"k" * 32, alg="sha512")
        sig = s.sign(b"m")
        self.assertTrue(s.verify(b"m", sig))
        for bad in (None, 123, "", sig[:-1], sig.upper()):
            with self.subTest(bad=bad):
                self.assertFalse(s.verify(b"m", bad))
        self.assertFalse(s.verify("m", sig))

    def test_hmac_for_entry_rejects_weak_alg(self):
        from src.signers import HmacSigner
        s = HmacSigner(key=b"k" * 32, alg="sha512")
        self.assertIsNone(s.for_entry("HMAC-MD5"))
        self.assertIsNone(s.for_entry("ML-DSA-65"))
        self.assertEqual(s.for_entry("HMAC-SHA3-512").alg, "sha3_512")

    def test_cli_hmac_keygen_0600_and_no_overwrite(self):
        out = os.path.join(self.tmp.name, "k")
        cmd = [sys.executable, "-m", "src.audit", "keygen", "--out", out]
        r1 = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        path = os.path.join(out, "hmac.key")
        self.assertEqual(mode(path), 0o600)
        before = open(path).read()
        r2 = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
        self.assertNotEqual(r2.returncode, 0)
        self.assertEqual(open(path).read(), before)


if __name__ == "__main__":
    unittest.main()
