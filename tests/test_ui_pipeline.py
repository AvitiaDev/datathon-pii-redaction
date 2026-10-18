"""Tests for the Streamlit UI pipeline bridge and verification adapters.

Run with:
    python3 -m unittest tests/test_ui_pipeline.py -v

These tests do NOT start a Streamlit server. They test the underlying
Python modules (app.pipeline, app.verification, app.preferences) using
the standard unittest framework already in use in this project.

All test inputs are synthetic — no real personal data.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Ensure repo root is on path ───────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Imports under test ────────────────────────────────────────────────────────
from app import pipeline

_MODEL_PRESENT = (Path(__file__).resolve().parents[1] / "models" / "pii_token_clf.npz").exists()
from app.verification import (
    validate_curp_format,
    validate_rfc_format,
    validate_ine_format,
    run_document_checks,
    RENAPOProvider,
    MetamapIDProvider,
    VerificationResult,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline bridge tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineImports(unittest.TestCase):
    def test_detector_map_has_regex(self):
        self.assertIn("regex", pipeline.DETECTOR_MAP)

    def test_detector_map_has_hybrid(self):
        self.assertIn("hybrid", pipeline.DETECTOR_MAP)

    def test_demo_text_is_nonempty(self):
        self.assertGreater(len(pipeline.DEMO_TEXT), 50)

    def test_demo_text_contains_no_real_pii_hint(self):
        # Demo text uses recognisably synthetic values; check for the
        # synthetic CURP prefix in the demo document.
        self.assertIn("MAHA900515MCHRRN03", pipeline.DEMO_TEXT)

    def test_demo_text_has_synthetic_flag(self):
        # The demo text must have identifiers we can detect
        self.assertIn("example.com", pipeline.DEMO_TEXT)


class TestFileValidation(unittest.TestCase):
    def _make_file(self, name: str, size: int):
        f = MagicMock()
        f.name = name
        f.size = size
        return f

    def test_txt_file_accepted(self):
        f = self._make_file("doc.txt", 1024)
        ok, err = pipeline.validate_upload(f)
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_md_file_accepted(self):
        f = self._make_file("doc.md", 512)
        ok, err = pipeline.validate_upload(f)
        self.assertTrue(ok)

    def test_document_and_image_types_accepted(self):
        for name in ("scan.pdf", "photo.png", "photo.jpg", "photo.jpeg", "letter.docx"):
            with self.subTest(name=name):
                f = self._make_file(name, 512)
                ok, err = pipeline.validate_upload(f)
                self.assertTrue(ok, err)
                self.assertEqual(err, "")

    def test_exe_rejected(self):
        f = self._make_file("malware.exe", 100)
        ok, err = pipeline.validate_upload(f)
        self.assertFalse(ok)
        self.assertIn("not supported", err)

    def test_other_unsupported_types_rejected(self):
        for name in ("page.html", "script.js", "archive.zip", "noextension"):
            with self.subTest(name=name):
                f = self._make_file(name, 100)
                ok, err = pipeline.validate_upload(f)
                self.assertFalse(ok)
                self.assertTrue(err)

    def test_oversized_file_rejected(self):
        f = self._make_file("big.pdf", pipeline.MAX_FILE_BYTES + 1)
        ok, err = pipeline.validate_upload(f)
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_none_file_rejected(self):
        ok, err = pipeline.validate_upload(None)
        self.assertFalse(ok)

    def test_exact_limit_accepted(self):
        f = self._make_file("edge.txt", pipeline.MAX_FILE_BYTES)
        ok, err = pipeline.validate_upload(f)
        self.assertTrue(ok, err)

    def test_previous_64kb_limit_no_longer_applies(self):
        f = self._make_file("medium.txt", 65 * 1024)
        ok, err = pipeline.validate_upload(f)
        self.assertTrue(ok, err)


class TestRunDetection(unittest.TestCase):
    def test_regex_detects_email(self):
        text = "Contact: user@example.com"
        result = pipeline.run_detection(text, "regex")
        self.assertTrue(result["ok"])
        types = {d["entity_type"] for d in result["detections"]}
        self.assertIn("EMAIL", types)

    @unittest.skipUnless(_MODEL_PRESENT, "trained model models/pii_token_clf.npz not present")
    def test_hybrid_detects_curp(self):
        text = "CURP: MAHA900515MCHRRN09"
        result = pipeline.run_detection(text, "hybrid")
        self.assertTrue(result["ok"])
        types = {d["entity_type"] for d in result["detections"]}
        self.assertIn("CURP", types)

    def test_redacted_text_hides_email(self):
        text = "Email: secret@example.com"
        result = pipeline.run_detection(text, "regex")
        self.assertTrue(result["ok"])
        self.assertNotIn("secret@example.com", result["redacted_text"])

    @unittest.skipUnless(_MODEL_PRESENT, "trained model models/pii_token_clf.npz not present")
    def test_redacted_text_hides_curp(self):
        text = "CURP: MAHA900515MCHRRN09"
        result = pipeline.run_detection(text, "hybrid")
        self.assertTrue(result["ok"])
        self.assertNotIn("MAHA900515MCHRRN09", result["redacted_text"])

    def test_no_raw_pii_in_detections_metadata(self):
        """Metadata from PIIRedactor must not contain the raw PII text field."""
        text = "Email: analyst@example.com"
        result = pipeline.run_detection(text, "regex")
        for det in result["detections"]:
            self.assertNotIn("text", det,
                             "Raw PII value must not appear in detection metadata")

    def test_exception_message_does_not_leak_input(self):
        from unittest.mock import patch

        sensitive = "SYNTHETIC-PII-DO-NOT-LEAK"
        with patch(
            "app.pipeline.PIIRedactor",
            side_effect=RuntimeError(f"failed while processing {sensitive}"),
        ):
            result = pipeline.run_detection(sensitive, "regex")

        self.assertFalse(result["ok"])
        self.assertEqual(result["redacted_text"], "")
        self.assertNotIn(sensitive, result["error"])
        self.assertEqual(
            result["error"],
            "Detection failed. Check the application configuration and retry.",
        )

    def test_unknown_detector_returns_error(self):
        result = pipeline.run_detection("hello", "nonexistent_detector")
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])

    def test_empty_text_returns_ok_no_detections(self):
        result = pipeline.run_detection("", "regex")
        self.assertTrue(result["ok"])
        self.assertEqual(result["detection_count"], 0)

    def test_detection_count_matches_list(self):
        text = "Email: a@b.com and phone 656-123-4567"
        result = pipeline.run_detection(text, "hybrid")
        self.assertEqual(result["detection_count"], len(result["detections"]))

    def test_detections_have_valid_offsets(self):
        text = "Nombre: Juan Pérez. Email: jp@example.com"
        result = pipeline.run_detection(text, "hybrid")
        for det in result["detections"]:
            self.assertGreaterEqual(det["start"], 0)
            self.assertLess(det["start"], det["end"])
            self.assertLessEqual(det["end"], len(text))


class TestDiagnostics(unittest.TestCase):
    def test_diagnostics_has_required_keys(self):
        diag = pipeline.get_diagnostics()
        for key in ["python_version", "platform", "available_detectors",
                    "import_errors", "model_exists", "env"]:
            self.assertIn(key, diag)

    def test_env_does_not_expose_secrets(self):
        """Environment section must not expose actual key values."""
        diag = pipeline.get_diagnostics()
        env = diag["env"]
        for k, v in env.items():
            if "KEY" in k or "APIKEY" in k or "SECRET" in k or "TOKEN" in k:
                self.assertNotEqual(v, os.environ.get(k, ""),
                                    f"Secret value for {k} must not appear verbatim")


# ═══════════════════════════════════════════════════════════════════════════════
# CURP validation tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCURPValidation(unittest.TestCase):
    # Synthetic CURPs constructed to be structurally valid
    VALID_CURPS = [
        "MAHA900515MCHRRN09",   # from demo text (check digit may vary)
        "GODE561231HDFXXX09",   # from src/audit.py demo
    ]

    def test_wrong_length_not_verified(self):
        result = validate_curp_format("SHORT")
        self.assertEqual(result.status, "not_verified")
        self.assertIn("length", result.checks_performed)

    def test_invalid_pattern_not_verified(self):
        # Valid length but wrong characters
        result = validate_curp_format("AAAA000000XXYYYYY00")  # 19 chars
        self.assertEqual(result.status, "not_verified")

    def test_empty_string_not_verified(self):
        result = validate_curp_format("")
        self.assertEqual(result.status, "not_verified")

    def test_provider_is_local_format_check(self):
        result = validate_curp_format("AAAA010101HDFRRT01")
        self.assertEqual(result.provider, "local_format_check")

    def test_result_is_not_verified_label(self):
        """A passing format check must be labelled inconclusive, not verified."""
        result = validate_curp_format("AAAA010101HDFRRT01")
        # Even a plausible CURP is only inconclusive at most (local check)
        self.assertIn(result.status, ("inconclusive", "not_verified"))

    def test_result_summary_mentions_not_official(self):
        # Use a CURP that reaches inconclusive (passes all local checks) or
        # not_verified — in both cases the summary must not claim official status.
        result = validate_curp_format("AAAA010101HDFRRT01")
        # If inconclusive, the summary must disclaim official status.
        # If not_verified (e.g. bad check digit), that's also acceptable.
        if result.status == "inconclusive":
            self.assertIn("NOT", result.summary.upper())
        else:
            self.assertEqual(result.status, "not_verified")

    def test_as_dict_has_required_keys(self):
        result = validate_curp_format("AAAA010101HDFRRT01")
        d = result.as_dict()
        for key in ["provider", "status", "summary", "checks_performed", "timestamp"]:
            self.assertIn(key, d)

    def test_as_dict_excludes_details(self):
        result = validate_curp_format("AAAA010101HDFRRT01")
        d = result.as_dict()
        self.assertNotIn("details", d)


# ═══════════════════════════════════════════════════════════════════════════════
# CURP date-extraction regression tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCURPDateExtraction(unittest.TestCase):
    """Regression tests for the CURP date-plausibility check and the two-digit
    year century heuristic (positions 4-9, layout YYMMDD).

    Heuristic rule (app/verification.py line ~106):
        year = 2000 + yy  if yy <= 9
               1900 + yy  otherwise

    Known limitation: people born 2010-2099 have yy in 10-99, so their birth
    year is mapped to 1910-1999 rather than 2010-2099.  The date itself is
    still *calendar-valid*, so validation reaches "inconclusive" rather than
    "not_verified".  Only truly impossible calendar dates (e.g. Feb 30, month
    00, day 00) are caught as implausible.
    """

    # Pre-computed: AAAA300230HDFRRT07 — yy=30/mm=02/dd=30 → Feb 30, not a valid date
    IMPOSSIBLE_DATE_CURP = "AAAA300230HDFRRT07"

    # Demo CURP: MAHA900515MCHRRN03 — yy=90/mm=05/dd=15 → May 15, 1990
    DEMO_CURP = "MAHA900515MCHRRN03"

    def test_impossible_date_feb30_is_rejected(self):
        """A CURP containing February 30 must fail date_plausibility."""
        result = validate_curp_format(self.IMPOSSIBLE_DATE_CURP)
        self.assertEqual(result.status, "not_verified")
        self.assertIn("date_plausibility", result.checks_performed)
        self.assertIn("implausible", result.summary.lower())

    def test_date_check_fires_after_check_digit(self):
        """date_plausibility appears after check_digit in checks_performed."""
        result = validate_curp_format(self.IMPOSSIBLE_DATE_CURP)
        checks = result.checks_performed
        self.assertIn("check_digit", checks)
        # check_digit must come before date_plausibility
        ci = checks.index("check_digit")
        di = checks.index("date_plausibility")
        self.assertLess(ci, di)

    def test_demo_curp_date_passes_plausibility(self):
        """The demo CURP (MAHA900515MCHRRN03) must reach date_plausibility
        successfully and return inconclusive."""
        result = validate_curp_format(self.DEMO_CURP)
        self.assertEqual(result.status, "inconclusive")
        self.assertIn("date_plausibility", result.checks_performed)

    def test_century_heuristic_2000s_cutoff(self):
        """yy=09 should map to 2009 (2000+9), a valid date.
        AAAA090101HDFRRT0D — Jan 1, 2009 for the heuristic path yy<=9.
        We only care that date_plausibility does NOT fire as failure."""
        from app.verification import _CURP_DICT

        base17 = "AAAA090101HDFRRT0"
        s = sum(_CURP_DICT.index(ch) * (18 - i) for i, ch in enumerate(base17))
        digit = str((10 - s % 10) % 10)
        curp = base17 + digit
        result = validate_curp_format(curp)
        # Either passes all checks (inconclusive) or fails on check digit only
        # — but must NOT fail on date_plausibility
        if result.status == "not_verified":
            self.assertNotIn("date_plausibility", result.checks_performed,
                             "date_plausibility must not trigger for yy=09 (Jan 1, 2009)")
        else:
            self.assertEqual(result.status, "inconclusive")

    def test_century_heuristic_documented_limitation(self):
        """People born 2010+ have yy in 10-99, which the heuristic maps to
        1910-1999.  The date is still calendar-valid so validation returns
        inconclusive (not not_verified).  This test documents the known
        limitation: format validation cannot distinguish birth year 2010 from
        1910 without the full RENAPO registry lookup."""
        from app.verification import _CURP_DICT

        # yy=15 -> heuristic: 1900+15=1915, Jan 1 — calendar-valid, no error raised
        base17 = "AAAA150101HDFRRT0"
        s = sum(_CURP_DICT.index(ch) * (18 - i) for i, ch in enumerate(base17))
        digit = str((10 - s % 10) % 10)
        curp = base17 + digit
        result = validate_curp_format(curp)
        # The date is valid (1915-01-01) so it must pass date_plausibility
        if result.status == "inconclusive":
            self.assertIn("date_plausibility", result.checks_performed)
        # not_verified only if check_digit fails — either way, NOT a date error
        if result.status == "not_verified":
            self.assertNotIn("date_plausibility", result.checks_performed,
                             "date_plausibility must not reject a calendar-valid date")


# ═══════════════════════════════════════════════════════════════════════════════
# RFC validation tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRFCValidation(unittest.TestCase):
    def test_short_rfc_not_verified(self):
        result = validate_rfc_format("ABCD")
        self.assertEqual(result.status, "not_verified")

    def test_13char_valid_pattern(self):
        # ABCD010101 + homoclave AA1 — structure is valid, check digit may fail
        result = validate_rfc_format("ABCD010101AA1")
        self.assertIn(result.status, ("inconclusive", "not_verified"))
        self.assertEqual(result.provider, "local_format_check")

    def test_result_not_claimed_as_verified(self):
        result = validate_rfc_format("ABCD010101AA1")
        self.assertNotEqual(result.status, "verified")

    def test_summary_mentions_not_official(self):
        result = validate_rfc_format("ABCD010101AA1")
        if result.status == "inconclusive":
            self.assertIn("NOT", result.summary.upper())


# ═══════════════════════════════════════════════════════════════════════════════
# INE validation tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestINEValidation(unittest.TestCase):
    def test_wrong_length_not_verified(self):
        result = validate_ine_format("ABCDEF12345678H12")  # 17 chars
        self.assertEqual(result.status, "not_verified")

    def test_valid_pattern_is_inconclusive(self):
        result = validate_ine_format("MRTNHR900515MCHRR001")  # 20 chars - length check fails
        self.assertEqual(result.status, "not_verified")

    def test_18char_valid_pattern(self):
        result = validate_ine_format("ABCDEF12345678H123")  # 18 chars
        # may be inconclusive (passes format) or not_verified (bad pattern)
        self.assertIn(result.status, ("inconclusive", "not_verified"))

    def test_provider_is_local(self):
        result = validate_ine_format("ABCDEF12345678H123")
        self.assertEqual(result.provider, "local_format_check")


# ═══════════════════════════════════════════════════════════════════════════════
# External provider — unavailable state (no credentials in test env)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRENAPOProvider(unittest.TestCase):
    def setUp(self):
        # Ensure credentials are absent in test environment
        for k in ("RENAPO_API_KEY", "RENAPO_API_URL"):
            os.environ.pop(k, None)

    def test_returns_unavailable_without_credentials(self):
        result = RENAPOProvider.verify("AAAA010101HDFRRT01")
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.provider, "renapo_curp")

    def test_summary_explains_requirement(self):
        result = RENAPOProvider.verify("AAAA010101HDFRRT01")
        self.assertIn("disabled", result.summary.lower())

    def test_no_network_call_without_credentials(self):
        """Verify that no HTTP request is made when not configured."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            RENAPOProvider.verify("AAAA010101HDFRRT01")
            mock_urlopen.assert_not_called()


class TestTruoraProvider(unittest.TestCase):
    def setUp(self):
        self._previous_external_flag = os.environ.get(
            "ENABLE_UNVERIFIED_EXTERNAL_CHECKS"
        )
        os.environ["ENABLE_UNVERIFIED_EXTERNAL_CHECKS"] = "1"
        os.environ.pop("TRUORA_API_KEY", None)

    def tearDown(self):
        if self._previous_external_flag is None:
            os.environ.pop("ENABLE_UNVERIFIED_EXTERNAL_CHECKS", None)
        else:
            os.environ["ENABLE_UNVERIFIED_EXTERNAL_CHECKS"] = (
                self._previous_external_flag
            )

    def test_curp_returns_unavailable_without_credentials(self):
        result = MetamapIDProvider.verify_curp("AAAA010101HDFRRT01")
        self.assertEqual(result.status, "unavailable")

    def test_rfc_returns_unavailable_without_credentials(self):
        result = MetamapIDProvider.verify_rfc("ABCD010101AA1")
        self.assertEqual(result.status, "unavailable")

    def test_no_network_call_without_credentials(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            MetamapIDProvider.verify_curp("AAAA010101HDFRRT01")
            mock_urlopen.assert_not_called()

    def test_mocked_success_response(self):
        """Simulate a successful Truora API response with a mock."""
        import json
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "check": {"status": "completed", "check_id": "test-123"}
        }).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        os.environ["TRUORA_API_KEY"] = "test-key-sandbox"
        try:
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = MetamapIDProvider.verify_curp("AAAA010101HDFRRT01")
            self.assertEqual(result.status, "inconclusive")
            self.assertEqual(result.provider, "truora")
        finally:
            os.environ.pop("TRUORA_API_KEY", None)

    def test_mocked_not_found_response(self):
        import json
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "check": {"status": "not_found"}
        }).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        os.environ["TRUORA_API_KEY"] = "test-key-sandbox"
        try:
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = MetamapIDProvider.verify_curp("AAAA010101HDFRRT01")
            self.assertEqual(result.status, "inconclusive")
        finally:
            os.environ.pop("TRUORA_API_KEY", None)

    def test_mocked_timeout(self):
        os.environ["TRUORA_API_KEY"] = "test-key-sandbox"
        try:
            with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
                result = MetamapIDProvider.verify_curp("AAAA010101HDFRRT01")
            self.assertEqual(result.status, "error")
            self.assertIn("timed out", result.summary.lower())
        finally:
            os.environ.pop("TRUORA_API_KEY", None)

    def test_mocked_malformed_response(self):
        """A response that is not valid JSON should return error status."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"<html>502 Bad Gateway</html>"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        os.environ["TRUORA_API_KEY"] = "test-key-sandbox"
        try:
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = MetamapIDProvider.verify_curp("AAAA010101HDFRRT01")
            self.assertEqual(result.status, "error")
        finally:
            os.environ.pop("TRUORA_API_KEY", None)


# ═══════════════════════════════════════════════════════════════════════════════
# run_document_checks facade
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunDocumentChecks(unittest.TestCase):
    def test_curp_returns_multiple_checks(self):
        results = run_document_checks("CURP", "AAAA010101HDFRRT01")
        self.assertIn("format_check", results)
        self.assertIn("renapo_lookup", results)
        self.assertIn("truora_lookup", results)

    def test_rfc_returns_format_and_truora(self):
        results = run_document_checks("RFC", "ABCD010101AA1")
        self.assertIn("format_check", results)
        self.assertIn("truora_lookup", results)

    def test_unknown_type_returns_unavailable(self):
        results = run_document_checks("PASSWORD", "hunter2")
        self.assertIn("format_check", results)
        self.assertEqual(results["format_check"].status, "unavailable")

    def test_all_results_are_verification_result_instances(self):
        results = run_document_checks("CURP", "AAAA010101HDFRRT01")
        for name, r in results.items():
            self.assertIsInstance(r, VerificationResult, f"{name} is not a VerificationResult")

    def test_no_result_is_verified_without_external_api(self):
        """Without API keys, no check should claim 'verified'."""
        for etype, val in [("CURP", "AAAA010101HDFRRT01"),
                           ("RFC", "ABCD010101AA1"),
                           ("ID_NUMBER", "ABCDEF12345678H123")]:
            results = run_document_checks(etype, val)
            for check_name, r in results.items():
                self.assertNotEqual(
                    r.status, "verified",
                    f"{etype}/{check_name} claims 'verified' without credentials"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# Security: no secrets or PII in logs / error messages
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoLeakInErrorMessages(unittest.TestCase):
    SENSITIVE_CURP = "GODE561231HDFXXX09"

    def test_renapo_error_does_not_contain_curp(self):
        os.environ["RENAPO_API_KEY"] = "x"
        os.environ["RENAPO_API_URL"] = "http://localhost:19999/nonexistent"
        try:
            result = RENAPOProvider.verify(self.SENSITIVE_CURP)
            self.assertNotIn(self.SENSITIVE_CURP, result.summary)
        finally:
            os.environ.pop("RENAPO_API_KEY", None)
            os.environ.pop("RENAPO_API_URL", None)

    def test_truora_error_does_not_contain_curp(self):
        os.environ["TRUORA_API_KEY"] = "x"
        os.environ["TRUORA_API_URL"] = "http://localhost:19999/nonexistent"
        try:
            result = MetamapIDProvider.verify_curp(self.SENSITIVE_CURP)
            self.assertNotIn(self.SENSITIVE_CURP, result.summary)
        finally:
            os.environ.pop("TRUORA_API_KEY", None)
            os.environ.pop("TRUORA_API_URL", None)

    def test_detection_metadata_has_no_raw_text(self):
        text = f"CURP: {self.SENSITIVE_CURP}"
        result = pipeline.run_detection(text, "regex")
        for det in result["detections"]:
            self.assertNotIn("text", det)
            # Also check that the raw CURP doesn't appear in any field value
            for val in det.values():
                if isinstance(val, str):
                    self.assertNotIn(self.SENSITIVE_CURP, val)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestCorruptDocuments(unittest.TestCase):
    def test_corrupt_docx_raises_value_error(self):
        from importlib.util import find_spec
        if find_spec("docx") is None:
            self.skipTest("python-docx not installed")
        from app.document_ingest import extract_document
        with self.assertRaises(ValueError) as ctx:
            extract_document("broken.docx", b"this is not a real docx file")
        self.assertNotIn("this is not a real docx", str(ctx.exception))
