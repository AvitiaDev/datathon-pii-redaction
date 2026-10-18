"""Dual signing (Ed25519 + ML-DSA): both must verify. ML-DSA via a fake oqs module."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_signers_keys import _fake_oqs

try:
    # Import before mock.patch.dict(sys.modules) so the patch never unloads them.
    import cryptography  # noqa: F401
    from cryptography.hazmat.primitives import serialization  # noqa: F401
    from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed")
class DualSignature(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.kd = os.path.join(self.tmp.name, "keys")
        self.p1 = mock.patch.dict(sys.modules, {"oqs": _fake_oqs()})
        self.p2 = mock.patch.dict(os.environ, {"PII_MLDSA_KEY_DIR": self.kd, "PII_HMAC_KEY": "ab" * 64})
        self.p1.start(); self.p2.start()
        os.environ.pop("PII_HMAC_KEY_FILE", None)
        from src import signers
        self.s = signers
        signers.Ed25519Signer.keygen(self.kd)
        signers.MlDsaSigner.keygen("ml-dsa-65", self.kd)

    def tearDown(self):
        self.p2.stop(); self.p1.stop()
        self.tmp.cleanup()

    def dual(self, verify_only=False):
        return self.s.get_signer("dual", verify_only=verify_only)

    def test_name_and_roundtrip(self):
        d = self.dual()
        self.assertEqual(d.name, "Ed25519+ML-DSA-65")
        sig = d.sign(b"entry")
        self.assertTrue(d.verify(b"entry", sig))
        self.assertTrue(self.dual(verify_only=True).verify(b"entry", sig))
        self.assertFalse(d.verify(b"entrY", sig))

    def test_both_halves_required(self):
        d = self.dual()
        c, q = d.sign(b"entry").split(".")
        other = self.dual().sign(b"other").split(".")
        cases = {
            "classical only": c,
            "pqc only": q,
            "classical tampered": other[0] + "." + q,
            "pqc tampered": c + "." + other[1],
            "swapped halves": q + "." + c,
            "empty classical": "." + q,
            "empty pqc": c + ".",
            "three parts": c + "." + q + "." + q,
            "not hex": "zz." + q,
            "none": None,
        }
        for name, sig in cases.items():
            with self.subTest(case=name):
                self.assertFalse(d.verify(b"entry", sig))

    def test_ed25519_private_key_0600_and_no_overwrite(self):
        path = os.path.join(self.kd, "ed25519_private.key")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            self.s.Ed25519Signer.keygen(self.kd)

    def test_readable_ed25519_key_refused(self):
        os.chmod(os.path.join(self.kd, "ed25519_private.key"), 0o644)
        with self.assertRaises(PermissionError):
            self.dual()
        self.dual(verify_only=True)

    def test_dual_audit_log_and_tamper(self):
        from src.audit import AuditLog, verify_log
        path = os.path.join(self.tmp.name, "a.jsonl")
        log = AuditLog(path, signer=self.dual())
        for i in range(3):
            log.record(f"doc {i}", f"doc {i}", [{"entity_type": "CURP"}])
        self.assertTrue(verify_log(path, self.dual(verify_only=True))["ok"])
        with open(path) as fh:
            lines = fh.readlines()
        e = json.loads(lines[1])
        self.assertEqual(e["sig_alg"], "Ed25519+ML-DSA-65")
        # attacker strips the PQC half and relabels the entry as plain Ed25519
        e["signature"] = e["signature"].split(".")[0]
        e["sig_alg"] = "Ed25519"
        lines[1] = json.dumps(e) + "\n"
        with open(path, "w") as fh:
            fh.writelines(lines)
        self.assertFalse(verify_log(path, self.dual(verify_only=True))["ok"])

    def test_single_signer_cannot_verify_dual_log(self):
        from src.audit import AuditLog, verify_log
        path = os.path.join(self.tmp.name, "b.jsonl")
        AuditLog(path, signer=self.dual()).record("x", "x", [])
        mldsa_only = self.s.MlDsaSigner("ml-dsa-65", key_dir=self.kd, verify_only=True)
        self.assertFalse(verify_log(path, mldsa_only)["ok"])

    def test_cli_keygen_dual_reuses_mldsa(self):
        kd = os.path.join(self.tmp.name, "k2")
        os.makedirs(kd)
        for f in ("mldsa_public.key", "mldsa_private.key"):
            fd = os.open(os.path.join(kd, f), os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, b"existing"); os.close(fd)
        code = ("import sys, runpy; sys.modules['oqs'] = __import__('test_signers_keys')._fake_oqs(); sys.argv = ['x', 'keygen', '--signer', 'dual', "
                f"'--out', {kd!r}]; runpy.run_module('src.audit', run_name='__main__')")
        env = dict(os.environ, PYTHONPATH=os.path.join(REPO, "tests"))
        r = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reused", r.stdout)
        with open(os.path.join(kd, "mldsa_public.key"), "rb") as fh:
            self.assertEqual(fh.read(), b"existing")
        self.assertTrue(os.path.exists(os.path.join(kd, "ed25519_private.key")))


if __name__ == "__main__":
    unittest.main()
