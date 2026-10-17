import os
import tempfile
import unittest


class DemoTest(unittest.TestCase):
    def test_end_to_end_mock_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"HOME": tmp}
            old = {k: os.environ.get(k) for k in
                   ("HOME", "PII_VAULT_KEY_FILE", "PII_HMAC_KEY_FILE", "PII_HMAC_KEY", "PII_SIGNER")}
            for k in old:
                os.environ.pop(k, None)
            os.environ.update(env)
            try:
                import importlib
                from src import demo
                importlib.reload(demo)  # pick up the temporary HOME
                demo.CONFIG_DIR = os.path.join(tmp, ".config", "pii-vault")
                os.environ["PII_VAULT_KEY_FILE"] = os.path.join(demo.CONFIG_DIR, "vault.key")
                out = demo.run(workdir=os.path.join(tmp, "demo"), backend="mock",
                               detector="regex", quiet_llm=True)
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            self.assertTrue(out["valid"])
            self.assertTrue(out["tamper_detected"])
            self.assertEqual(out["leaked"], [])
            self.assertGreaterEqual(out["entries"], 2)
            self.assertLess(out["seconds"], 60)


if __name__ == "__main__":
    unittest.main()
