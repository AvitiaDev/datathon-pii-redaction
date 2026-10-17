import unittest

from src.pii_redactor import PIIRedactor


class TestPIIRedactor(unittest.TestCase):
    def setUp(self):
        self.redactor = PIIRedactor()

    def test_email_is_detected_and_redacted(self):
        result = self.redactor.process_text(
            "Contact ana@example.com for help."
        )

        self.assertEqual(
            result["redacted_text"],
            "Contact [EMAIL_REDACTED] for help.",
        )
        self.assertEqual(result["detection_count"], 1)
        self.assertEqual(result["detections"][0]["entity_type"], "EMAIL")

    def test_original_email_is_not_in_metadata(self):
        result = self.redactor.process_text(
            "Contact ana@example.com for help."
        )

        self.assertNotIn(
            "ana@example.com",
            str(result["detections"]),
        )

    def test_text_without_pii_is_preserved(self):
        text = "La reunión comienza mañana a las diez."
        result = self.redactor.process_text(text)

        self.assertEqual(result["redacted_text"], text)
        self.assertEqual(result["detection_count"], 0)

    def test_non_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            self.redactor.process_text(None)


if __name__ == "__main__":
    unittest.main()
