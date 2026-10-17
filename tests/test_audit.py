import json
import os
import tempfile
import unittest

TEST_KEY = "ab" * 64  # synthetic 512-bit test key


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        os.environ["PII_HMAC_KEY"] = TEST_KEY
        os.environ.pop("PII_HMAC_KEY_FILE", None)
        os.environ.pop("PII_HASH_ALG", None)
        from src.audit import AuditLog, verify_log
        from src.pii_redactor import PIIRedactor
        self.verify_log = verify_log
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")
        self.log = AuditLog(self.path)
        self.redactor = PIIRedactor(audit_log=self.log)
        self.texts = [
            "Contact ana@example.com for help.",
            "CURP GODE561231HDFXXX09",
            "Sin datos.",
        ]
        for t in self.texts:
            self.redactor.process_text(t)

    def tearDown(self):
        self.tmp.cleanup()

    def _lines(self):
        with open(self.path, encoding="utf-8") as fh:
            return fh.readlines()

    def _write(self, lines):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)

    def test_untouched_log_verifies(self):
        rep = self.verify_log(self.path, self.log.signer)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["entries"], 3)

    def test_no_raw_pii_in_log(self):
        content = open(self.path, encoding="utf-8").read()
        for pii in ("ana@example.com", "GODE561231HDFXXX09"):
            self.assertNotIn(pii, content)

    def test_edited_entry_is_detected(self):
        lines = self._lines()
        e = json.loads(lines[0])
        e["counts"] = {}
        lines[0] = json.dumps(e) + "\n"
        self._write(lines)
        self.assertFalse(self.verify_log(self.path, self.log.signer)["ok"])

    def test_deleted_middle_entry_is_detected(self):
        lines = self._lines()
        del lines[1]
        self._write(lines)
        self.assertFalse(self.verify_log(self.path, self.log.signer)["ok"])

    def test_reordered_entries_are_detected(self):
        lines = self._lines()
        lines[0], lines[1] = lines[1], lines[0]
        self._write(lines)
        self.assertFalse(self.verify_log(self.path, self.log.signer)["ok"])

    def test_wrong_key_fails(self):
        from src.signers import HmacSigner
        other = HmacSigner(key=bytes.fromhex("cd" * 64))
        self.assertFalse(self.verify_log(self.path, other)["ok"])

    def test_log_resumes_chain_after_reopen(self):
        from src.audit import AuditLog
        log2 = AuditLog(self.path)
        log2.record("otro texto", "otro texto", [])
        self.assertTrue(self.verify_log(self.path, log2.signer)["ok"])


class TestHashPolicy(unittest.TestCase):
    def test_hash_is_keyed_and_stable(self):
        os.environ["PII_HMAC_KEY"] = TEST_KEY
        from src.policies import RedactionPolicy
        p = RedactionPolicy(default_strategy="HASH")
        p.rules = {}
        a = p.apply_policy("CURP", "GODE561231HDFXXX09")
        self.assertEqual(a, p.apply_policy("CURP", "GODE561231HDFXXX09"))
        self.assertTrue(a.startswith("[CURP_"))
        self.assertNotIn("GODE", a)


if __name__ == "__main__":
    unittest.main()
