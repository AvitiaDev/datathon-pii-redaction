import os
import unittest
from unittest import mock

from src import hybrid_detection as hd


def fake_ml(text):
    """Simulates the observed ML behaviour: first name only, phone split into pieces."""
    out = []
    for word, etype in (("Laura", "NAME"), ("123", "IP")):
        i = text.find(word)
        if i >= 0:
            out.append({"entity_type": etype, "start": i, "end": i + len(word), "text": word})
    return out


DOC = "Nombre: Laura Gómez Ruiz\nTeléfono: 656 123 4567\nNSS: 12345678901\nClave de elector (INE): GMRZLR90010108M123"


class TestHybridMX(unittest.TestCase):
    def run_hybrid(self, enabled):
        with mock.patch.object(hd, "detect_pii_ml", fake_ml), \
             mock.patch.dict(os.environ, {"HYBRID_MX_RULES": "1" if enabled else "0"}):
            return {(d["entity_type"], DOC[d["start"]:d["end"]]) for d in hd.detect_pii_hybrid(DOC)}

    def test_full_name_after_cue(self):
        self.assertIn(("NAME", "Laura Gómez Ruiz"), self.run_hybrid(True))

    def test_mx_phone_whole(self):
        found = self.run_hybrid(True)
        self.assertIn(("PHONE", "656 123 4567"), found)
        self.assertNotIn(("IP", "123"), found)

    def test_nss_and_ine(self):
        found = self.run_hybrid(True)
        self.assertIn(("ID_NUMBER", "12345678901"), found)
        self.assertIn(("ID_NUMBER", "GMRZLR90010108M123"), found)

    def test_disabled_reproduces_before(self):
        found = self.run_hybrid(False)
        self.assertIn(("NAME", "Laura"), found)
        self.assertIn(("IP", "123"), found)

    def test_surname_extension_stops_at_street(self):
        text = "Contacto: Laura Gómez Calle Oro 12"
        with mock.patch.object(hd, "detect_pii_ml", fake_ml):
            names = [text[d["start"]:d["end"]] for d in hd.detect_pii_hybrid(text) if d["entity_type"] == "NAME"]
        self.assertIn("Laura Gómez", names)


if __name__ == "__main__":
    unittest.main()
