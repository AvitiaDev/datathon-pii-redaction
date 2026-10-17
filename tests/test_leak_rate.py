import json
import tempfile
import unittest

from src.evaluation import evaluate, leaked_groups


class TestLeakRate(unittest.TestCase):
    def test_full_cover_no_leak(self):
        self.assertEqual(leaked_groups(20, [(0, 5, "EMAIL")], [(0, 5, "EMAIL")]), set())

    def test_one_char_survives_is_leak(self):
        self.assertEqual(leaked_groups(20, [(0, 5, "EMAIL")], [(0, 4, "EMAIL")]), {"EMAIL"})

    def test_union_of_predictions_covers(self):
        self.assertEqual(
            leaked_groups(20, [(0, 10, "TEL")], [(0, 5, "PHONE"), (5, 10, "PHONE")]), set())

    def test_rate_one_of_four(self):
        docs = [
            {"source_text": "a" * 10, "privacy_mask": [{"start": 0, "end": 5, "label": "EMAIL"}]},
            {"source_text": "b" * 10, "privacy_mask": [{"start": 0, "end": 5, "label": "EMAIL"}]},
            {"source_text": "c" * 10, "privacy_mask": [{"start": 0, "end": 5, "label": "EMAIL"}]},
            {"source_text": "d" * 10, "privacy_mask": [{"start": 2, "end": 8, "label": "EMAIL"}]},
            {"source_text": "no pii", "privacy_mask": []},
        ]

        def det(_text):  # covers 0..5 only, so doc 4 leaks
            return [{"start": 0, "end": 5, "entity_type": "EMAIL"}]

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write("\n".join(json.dumps(d) for d in docs))
        r = evaluate(f.name, detector=det)
        self.assertEqual(r["documents_with_pii"], 4)
        self.assertEqual(r["leaked_documents"], 1)
        self.assertEqual(r["leak_rate"], 0.25)


if __name__ == "__main__":
    unittest.main()
