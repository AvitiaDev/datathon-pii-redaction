import json, os, tempfile, unittest
from unittest import mock
from src import audit, crypto_config
from src.signers import HmacSigner, get_signer

KEY = "ab" * 64


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"PII_HMAC_KEY": KEY}, clear=False)
        self.env.start()
        os.environ.pop("PII_SECURITY_PROFILE", None)
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "a.jsonl")
        self.s = HmacSigner()
        lg = audit.AuditLog(self.log, signer=self.s)
        for i in range(5):
            lg.record(f"t{i}", f"r{i}", [])
        self.anchor = audit.make_anchor(self.log, self.s)

    def tearDown(self):
        self.env.stop()

    def _lines(self):
        with open(self.log) as fh:
            return fh.readlines()

    def test_intact_and_appended_ok(self):
        self.assertTrue(audit.verify_anchor(self.log, self.s, self.anchor)["ok"])
        audit.AuditLog(self.log, signer=self.s).record("x", "y", [])
        self.assertTrue(audit.verify_anchor(self.log, self.s, self.anchor)["ok"])

    def test_tail_deletion_detected(self):
        keep = self._lines()[:3]
        with open(self.log, "w") as fh:
            fh.writelines(keep)
        self.assertTrue(audit.verify_log(self.log, self.s)["ok"])  # file alone can't tell
        rep = audit.verify_anchor(self.log, self.s, self.anchor)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("TRUNCATED" in e for e in rep["errors"]))

    def test_rollback_rewrite_detected(self):
        keep = self._lines()[:3]
        with open(self.log, "w") as fh:
            fh.writelines(keep)
        lg = audit.AuditLog(self.log, signer=self.s)  # key holder rewrites history
        lg.record("other", "other", [])
        lg.record("other2", "other2", [])
        self.assertTrue(audit.verify_log(self.log, self.s)["ok"])
        rep = audit.verify_anchor(self.log, self.s, self.anchor)
        self.assertTrue(any("ROLLBACK" in e for e in rep["errors"]))

    def test_forged_anchor_rejected(self):
        a = dict(self.anchor, entries=2)
        rep = audit.verify_anchor(self.log, self.s, a)
        self.assertTrue(any("anchor signature" in e for e in rep["errors"]))

    def test_cli_roundtrip(self):
        out = os.path.join(self.d, "anc.json")
        audit.main(["anchor", "--log", self.log, "--out", out, "--signer", "hmac"])
        with self.assertRaises(SystemExit) as cm:
            audit.main(["verify", "--log", self.log, "--signer", "hmac", "--anchor", out])
        self.assertEqual(cm.exception.code, 0)


class ProfileTests(unittest.TestCase):
    def test_pq_profile_refuses_hmac(self):
        with mock.patch.dict(os.environ, {"PII_SECURITY_PROFILE": "pq", "PII_SIGNER": "hmac",
                                          "PII_HMAC_KEY": KEY}):
            with self.assertRaises(crypto_config.InsecureProfile):
                get_signer()

    def test_dev_profile_allows_hmac(self):
        with mock.patch.dict(os.environ, {"PII_SECURITY_PROFILE": "dev", "PII_HMAC_KEY": KEY}):
            self.assertEqual(get_signer("hmac").name, "HMAC-SHA512")

    def test_bad_profile(self):
        with mock.patch.dict(os.environ, {"PII_SECURITY_PROFILE": "yolo"}):
            with self.assertRaises(ValueError):
                crypto_config.security_profile()


if __name__ == "__main__":
    unittest.main()
