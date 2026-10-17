import unittest

from src import llm_gateway
from src.detection import detect_pii_regex
from src.llm_gateway import LLMGateway, PIILeakError, assert_no_pii

DOC = ("Solicitud. Correo: laura.gomez@example.com. Tel: 656 123 4567. "
       "CURP: GORL900101MCHMZR09. Busca puesto de analista.")


class TestLLMGateway(unittest.TestCase):
    def setUp(self):
        self.sent = []

        def capture(prompt):
            self.sent.append(prompt)
            return "ok summary", "capture"

        llm_gateway.BACKENDS["capture"] = capture
        # Regex detector keeps the test independent of the trained ML model file.
        self.gw = LLMGateway(detector=detect_pii_regex, backend="capture")

    def tearDown(self):
        llm_gateway.BACKENDS.pop("capture", None)

    def test_prompt_contains_no_detected_span(self):
        r = self.gw.summarize(DOC)
        self.assertEqual(len(self.sent), 1)
        prompt = self.sent[0]
        spans = [DOC[d["start"]:d["end"]] for d in detect_pii_regex(DOC)]
        self.assertTrue(spans)
        for s in spans:
            self.assertNotIn(s, prompt)
        self.assertNotIn("laura.gomez@example.com", prompt)
        self.assertNotIn("GORL900101MCHMZR09", prompt)
        self.assertEqual(r["summary"], "ok summary")
        self.assertEqual(len(r["output_sha256"]), 64)

    def test_guard_blocks_leak(self):
        with self.assertRaises(PIILeakError):
            assert_no_pii("hello laura.gomez@example.com", ["laura.gomez@example.com"])

    def test_leaky_redactor_never_reaches_backend(self):
        class Leaky:
            def process_text(self, text):
                return {"redacted_text": text}

        gw = LLMGateway(detector=detect_pii_regex, backend="capture", redactor=Leaky())
        with self.assertRaises(PIILeakError):
            gw.summarize(DOC)
        self.assertEqual(self.sent, [])

    def test_log_has_hash_only(self):
        with self.assertLogs("llm_gateway", level="INFO") as cm:
            self.gw.summarize(DOC)
        line = "\n".join(cm.output)
        self.assertIn("output_sha256=", line)
        self.assertNotIn("ok summary", line)
        self.assertNotIn("example.com", line)

    def test_mock_demo_returns_summary(self):
        r = LLMGateway(detector=detect_pii_regex, backend="mock").summarize(DOC)
        self.assertIn("personal data removed", r["summary"])


if __name__ == "__main__":
    unittest.main()
