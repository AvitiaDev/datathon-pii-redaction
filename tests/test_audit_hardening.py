"""B1 hash agility + B3 audit failure paths (synthetic data only)."""
import json
import os
import tempfile
import unittest

KEY = "ab" * 64


class _Env:
    def __init__(self, **kw):
        self.kw, self.old = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class Base(unittest.TestCase):
    def setUp(self):
        self.env = _Env(PII_HMAC_KEY=KEY, PII_HMAC_KEY_FILE=None, PII_HASH_ALG=None, PII_SIGNER=None)
        self.env.__enter__()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()
        self.env.__exit__()

    def write(self, alg, n=2, path=None):
        from src.audit import AuditLog
        with _Env(PII_HASH_ALG=alg):
            log = AuditLog(path or self.path)
            for i in range(n):
                log.record(f"documento {i} CURP GODE561231HDFXXX09", f"documento {i}",
                           [{"entity_type": "CURP"}])
        return log

    def lines(self):
        with open(self.path, encoding="utf-8") as fh:
            return fh.readlines()

    def rewrite(self, lines):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)

    def verify(self, signer=None):
        from src.audit import verify_log
        from src.signers import HmacSigner
        return verify_log(self.path, signer or HmacSigner(key=bytes.fromhex(KEY), alg="sha512"))


class HashAgility(Base):
    def test_each_supported_alg_verifies(self):
        from src import crypto_config
        for alg in crypto_config.ALLOWED_HASHES:
            with self.subTest(alg=alg):
                if os.path.exists(self.path):
                    os.remove(self.path)
                self.write(alg)
                self.assertTrue(self.verify()["ok"], self.verify()["errors"])
                self.assertTrue(all(json.loads(l)["hash_alg"] == alg for l in self.lines()))

    def test_verification_independent_of_current_setting(self):
        self.write("sha512")
        for current in ("sha3_512", "sha384", "sha256"):
            with self.subTest(current=current), _Env(PII_HASH_ALG=current):
                self.assertTrue(self.verify()["ok"])

    def test_algorithm_rotation_inside_one_log(self):
        self.write("sha512", n=2)
        self.write("sha3_512", n=2)  # reopen with a new algorithm and append
        algs = [json.loads(l)["hash_alg"] for l in self.lines()]
        self.assertEqual(algs, ["sha512", "sha512", "sha3_512", "sha3_512"])
        self.assertTrue(self.verify()["ok"], self.verify()["errors"])

    def test_tamper_still_detected_for_every_alg(self):
        from src import crypto_config
        for alg in crypto_config.ALLOWED_HASHES:
            with self.subTest(alg=alg):
                if os.path.exists(self.path):
                    os.remove(self.path)
                self.write(alg, n=3)
                ls = self.lines()
                e = json.loads(ls[1]); e["counts"] = {}
                ls[1] = json.dumps(e) + "\n"
                self.rewrite(ls)
                self.assertFalse(self.verify()["ok"])

    def test_downgrade_to_weak_hash_rejected(self):
        self.write("sha512")
        ls = self.lines()
        e = json.loads(ls[0]); e["hash_alg"] = "md5"
        ls[0] = json.dumps(e) + "\n"
        self.rewrite(ls)
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertTrue(any("unreadable" in x or "unsupported" in x for x in rep["errors"]))

    def test_relabelled_alg_breaks_signature(self):
        self.write("sha512")
        ls = self.lines()
        e = json.loads(ls[0]); e["hash_alg"] = "sha3_512"  # allowed, but not what was signed
        ls[0] = json.dumps(e) + "\n"
        self.rewrite(ls)
        self.assertFalse(self.verify()["ok"])

    def test_wrong_digest_length_rejected(self):
        self.write("sha512")
        ls = self.lines()
        e = json.loads(ls[0]); e["output_hash"] = e["output_hash"][:64]
        ls[0] = json.dumps(e) + "\n"
        self.rewrite(ls)
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertTrue(any("digest" in x for x in rep["errors"]))


class FailurePaths(Base):
    def test_missing_file(self):
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertIn("not found", rep["errors"][0])

    def test_empty_file(self):
        open(self.path, "w").close()
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertIn("log is empty", rep["errors"])

    def test_blank_lines_only(self):
        with open(self.path, "w") as fh:
            fh.write("\n\n  \n")
        self.assertFalse(self.verify()["ok"])

    def test_garbage_line(self):
        self.write("sha512")
        ls = self.lines(); ls.insert(1, "{not json\n")
        self.rewrite(ls)
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertTrue(any("unreadable" in x for x in rep["errors"]))

    def test_non_object_line(self):
        self.rewrite(['[1, 2, 3]\n'])
        self.assertFalse(self.verify()["ok"])

    def test_truncated_last_line(self):
        self.write("sha512", n=3)
        ls = self.lines(); ls[-1] = ls[-1][: len(ls[-1]) // 2]
        self.rewrite(ls)
        self.assertFalse(self.verify()["ok"])

    def test_missing_signature_field(self):
        self.write("sha512")
        ls = self.lines()
        e = json.loads(ls[0]); del e["signature"]
        ls[0] = json.dumps(e) + "\n"
        self.rewrite(ls)
        self.assertFalse(self.verify()["ok"])

    def test_duplicated_entry(self):
        self.write("sha512", n=2)
        ls = self.lines(); ls.insert(1, ls[0])
        self.rewrite(ls)
        self.assertFalse(self.verify()["ok"])

    def test_append_after_corruption_refused(self):
        from src.audit import AuditLog, AuditLogCorrupt
        self.write("sha512", n=2)
        ls = self.lines()
        e = json.loads(ls[0]); e["detector"] = "edited"
        ls[0] = json.dumps(e) + "\n"
        self.rewrite(ls)
        before = self.lines()
        with self.assertRaises(AuditLogCorrupt):
            AuditLog(self.path)
        self.assertEqual(self.lines(), before)  # nothing appended

    def test_append_after_garbage_refused(self):
        from src.audit import AuditLog, AuditLogCorrupt
        self.write("sha512")
        with open(self.path, "a") as fh:
            fh.write("garbage\n")
        with self.assertRaises(AuditLogCorrupt):
            AuditLog(self.path)

    def test_append_with_wrong_key_refused(self):
        from src.audit import AuditLog, AuditLogCorrupt
        self.write("sha512")
        with _Env(PII_HMAC_KEY="cd" * 64):
            with self.assertRaises(AuditLogCorrupt):
                AuditLog(self.path)

    def test_empty_file_can_start_a_log(self):
        from src.audit import AuditLog
        open(self.path, "w").close()
        AuditLog(self.path).record("x", "x", [])
        self.assertTrue(self.verify()["ok"])

    def test_verify_with_wrong_key(self):
        from src.signers import HmacSigner
        self.write("sha512")
        rep = self.verify(HmacSigner(key=bytes.fromhex("cd" * 64), alg="sha512"))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("key_id" in x for x in rep["errors"]))

    def test_errors_never_contain_pii(self):
        self.write("sha512")
        ls = self.lines(); ls.append('{"note": "GODE561231HDFXXX09"\n')
        self.rewrite(ls)
        rep = self.verify()
        self.assertNotIn("GODE561231HDFXXX09", " ".join(rep["errors"]))


if __name__ == "__main__":
    unittest.main()
