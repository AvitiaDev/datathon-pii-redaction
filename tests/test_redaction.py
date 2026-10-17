import unittest

from src.policies import RedactionPolicy
from src.redaction import redact_text


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.policy = RedactionPolicy()

    def test_redacts_email_and_preserves_surrounding_text(self):
        text = "Contact ana@example.com for assistance."
        start = text.index("ana@example.com")
        end = start + len("ana@example.com")

        result = redact_text(
            text,
            [{
                "entity_type": "EMAIL",
                "start": start,
                "end": end,
            }],
            self.policy,
        )

        self.assertEqual(
            result,
            "Contact [EMAIL_REDACTED] for assistance.",
        )

    def test_returns_original_when_no_detections(self):
        text = "This text contains no detected PII."
        self.assertEqual(redact_text(text, [], self.policy), text)

    def test_ignores_invalid_offsets(self):
        text = "Contact ana@example.com."
        result = redact_text(
            text,
            [{
                "entity_type": "EMAIL",
                "start": 100,
                "end": 110,
            }],
            self.policy,
        )

        self.assertEqual(result, text)

    def test_prefers_longest_overlapping_span(self):
        text = "ana@example.com"
        result = redact_text(
            text,
            [
                {
                    "entity_type": "EMAIL",
                    "start": 0,
                    "end": len(text),
                },
                {
                    "entity_type": "NAME",
                    "start": 0,
                    "end": 3,
                },
            ],
            self.policy,
        )

        self.assertEqual(result, "[EMAIL_REDACTED]")

    def test_redacts_multiple_spans_without_shifting_offsets(self):
        text = "ana@example.com y luis@example.com"
        first = text.index("ana@example.com")
        second = text.index("luis@example.com")

        detections = [
            {
                "entity_type": "EMAIL",
                "start": first,
                "end": first + len("ana@example.com"),
            },
            {
                "entity_type": "EMAIL",
                "start": second,
                "end": second + len("luis@example.com"),
            },
        ]

        result = redact_text(text, detections, self.policy)

        self.assertEqual(
            result,
            "[EMAIL_REDACTED] y [EMAIL_REDACTED]",
        )


if __name__ == "__main__":
    unittest.main()
