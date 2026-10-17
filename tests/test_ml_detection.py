import unittest

from src.token_classifier import MODEL_PATH

SAMPLE = (
    "Nombre: Laura Martínez Soto\n"
    "Correo: laura.mtz@example.com\n"
    "CURP: AAAA010101HDFRRT01\n"
    "RFC: ABCD010101AA1\n"
    "IP de acceso: 192.168.10.25\n"
)


@unittest.skipUnless(MODEL_PATH.exists(),
                     "model not trained: run python3 -m src.token_classifier")
class TestMLAndHybridDetection(unittest.TestCase):
    def setUp(self):
        from src.hybrid_detection import detect_pii_hybrid
        from src.token_classifier import detect_pii_ml
        self.ml = detect_pii_ml
        self.hybrid = detect_pii_hybrid

    def check_offsets(self, text, detections):
        for d in detections:
            self.assertGreaterEqual(d["start"], 0)
            self.assertLess(d["start"], d["end"])
            self.assertLessEqual(d["end"], len(text))
            self.assertEqual(text[d["start"]:d["end"]], d["text"])

    def test_ml_returns_valid_spans(self):
        detections = self.ml(SAMPLE)
        self.assertGreater(len(detections), 0)
        self.check_offsets(SAMPLE, detections)

    def test_ml_handles_empty_text(self):
        self.assertEqual(self.ml(""), [])

    def test_hybrid_keeps_mexican_identifiers(self):
        types = {d["entity_type"] for d in self.hybrid(SAMPLE)}
        self.assertTrue({"CURP", "RFC", "EMAIL"} <= types)

    def test_hybrid_spans_are_valid(self):
        self.check_offsets(SAMPLE, self.hybrid(SAMPLE))

    def test_pipeline_with_hybrid_hides_identifiers(self):
        from src.pii_redactor import PIIRedactor
        result = PIIRedactor(detector=self.hybrid).process_text(SAMPLE)
        for value in ("laura.mtz@example.com", "AAAA010101HDFRRT01",
                      "ABCD010101AA1", "192.168.10.25"):
            self.assertNotIn(value, result["redacted_text"])


if __name__ == "__main__":
    unittest.main()
