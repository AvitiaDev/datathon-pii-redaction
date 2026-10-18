import unittest

from src.detection import detect_all_pii


class TestPIIDetection(unittest.TestCase):
    def check_valid_offsets(self, text, detections):
        for item in detections:
            self.assertGreaterEqual(item["start"], 0)
            self.assertLess(item["start"], item["end"])
            self.assertLessEqual(item["end"], len(text))
            self.assertEqual(
                text[item["start"]:item["end"]],
                item["text"],
            )

    def test_email_detection(self):
        text = "Contacto: prueba.usuario@example.com"
        detections = detect_all_pii(text)
        self.assertIn("EMAIL", {d["entity_type"] for d in detections})
        self.check_valid_offsets(text, detections)

    def test_phone_detection(self):
        text = "Teléfono: 656-123-4567"
        detections = detect_all_pii(text)
        self.assertIn("PHONE", {d["entity_type"] for d in detections})
        self.check_valid_offsets(text, detections)

    def test_curp_detection(self):
        text = "CURP: AAAA010101HDFRRT01"
        detections = detect_all_pii(text)
        self.assertIn("CURP", {d["entity_type"] for d in detections})
        self.check_valid_offsets(text, detections)

    def test_rfc_detection(self):
        text = "RFC: ABCD010101AA1"
        detections = detect_all_pii(text)
        self.assertIn("RFC", {d["entity_type"] for d in detections})
        self.check_valid_offsets(text, detections)

    def test_rfc_detection_accepts_wxyz_homoclave_characters(self):
        for suffix in ("WA1", "XA1", "YA1", "ZA1"):
            with self.subTest(suffix=suffix):
                text = f"RFC: ABCD010101{suffix}"
                detections = detect_all_pii(text)
                rfcs = [
                    d for d in detections
                    if d["entity_type"] == "RFC"
                ]
                self.assertEqual(len(rfcs), 1)
                self.assertEqual(rfcs[0]["text"], f"ABCD010101{suffix}")
                self.check_valid_offsets(text, rfcs)

    def test_person_name_detection(self):
        text = "Candidato: Daniel Fernández"
        detections = detect_all_pii(text)
        self.assertIn("NAME", {d["entity_type"] for d in detections})
        self.check_valid_offsets(text, detections)

    def test_ordinary_date_has_no_detection(self):
        text = "La reunión será el 21 de octubre de 2026."
        self.assertEqual(detect_all_pii(text), [])

    def test_ordinary_numbers_have_no_detection(self):
        text = "El documento tiene 123 páginas y cuesta 450 pesos."
        self.assertEqual(detect_all_pii(text), [])

    def test_department_names_are_not_person_names(self):
        text = "El Departamento de Recursos Humanos revisó el informe."
        names = [
            d for d in detect_all_pii(text)
            if d["entity_type"] == "NAME"
        ]
        self.assertEqual(names, [])


if __name__ == "__main__":
    unittest.main()
