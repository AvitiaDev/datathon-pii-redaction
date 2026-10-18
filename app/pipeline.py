"""Pipeline bridge: connect the Streamlit UI to the existing detection/redaction
modules without modifying them. All heavy logic lives in src/; this module only
translates between the UI's needs and the existing API.
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any

# ── Ensure the repo root is on sys.path so `src` is importable ───────────────
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ── Lazy imports (model loads on first call) ──────────────────────────────────
_IMPORT_ERRORS: dict[str, str] = {}

def _safe_import(name: str, from_module: str):
    try:
        mod = __import__(from_module, fromlist=[name])
        return getattr(mod, name)
    except Exception as exc:
        _IMPORT_ERRORS[from_module] = str(exc)
        return None

detect_pii_regex  = _safe_import("detect_pii_regex",  "src.detection")
detect_pii_hybrid = _safe_import("detect_pii_hybrid", "src.hybrid_detection")
detect_pii_ml     = _safe_import("detect_pii_ml",     "src.token_classifier")
PIIRedactor       = _safe_import("PIIRedactor",        "src.pii_redactor")
RedactionPolicy   = _safe_import("RedactionPolicy",    "src.policies")

DETECTOR_MAP = {}
if detect_pii_regex:
    DETECTOR_MAP["regex"] = detect_pii_regex
if detect_pii_hybrid:
    DETECTOR_MAP["hybrid"] = detect_pii_hybrid
if detect_pii_ml:
    DETECTOR_MAP["ml"] = detect_pii_ml

# ── Synthetic demo text (no real personal data) ───────────────────────────────
# All identifiers are structurally synthetic and do not correspond to any
# real person. CURPs use valid check digits so the local format validator
# can reach the "inconclusive" state and exercise the date-plausibility check.
DEMO_TEXT = (
    "Curriculum Vitae\n\n"
    "Nombre completo: Ana Lucía Martínez Herrera\n"
    "Correo: ana.martinez@example.com\n"
    "Teléfono: 656 123 4567\n"
    "CURP: MAHA900515MCHRRN03\n"
    "RFC: MAHA900515AB1\n"
    "NSS: 34567890123\n"
    "INE: MRTNHR900515MCHRR001\n"
    "Dirección: Calle Juárez #42, Col. Centro, C.P. 32000, Ciudad Juárez, Chihuahua\n\n"
    "Experiencia: Cinco años como analista de datos en la industria maquiladora.\n"
    "Busca puesto de científica de datos senior.\n"
    "Fecha de nacimiento: 15 de mayo de 1990."
)

# ── File type and size limits ─────────────────────────────────────────────────
from app.document_ingest import MAX_FILE_BYTES, extract_document

ALLOWED_EXTENSIONS = {
    ".txt", ".md", ".png", ".jpg", ".jpeg", ".pdf", ".docx"
}


def validate_upload(file) -> tuple[bool, str]:
    """Validate an uploaded file before reading its contents."""
    if file is None:
        return False, "No file provided."

    suffix = Path(file.name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return False, (
            f"File type '{suffix}' is not supported. "
            f"Accepted types: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    if file.size == 0:
        return False, "The uploaded file is empty."

    if file.size > MAX_FILE_BYTES:
        return False, "File exceeds the 10 MiB upload limit."

    return True, ""


def read_upload(file) -> str:
    """Extract text from a supported uploaded document."""
    try:
        text = extract_document(file.name, file.getvalue())
    except ValueError:
        raise
    except Exception:
        raise ValueError(
            "Could not extract text from this document. "
            "Check the file format and try another file."
        ) from None

    if not text.strip():
        raise ValueError(
            "No readable text was extracted. Try a clearer image "
            "or a document with selectable text."
        )

    return text


def get_detector(name: str):
    """Return the detector callable by name; None if unavailable."""
    return DETECTOR_MAP.get(name)


def run_detection(text: str, detector_name: str) -> dict[str, Any]:
    """Run detection and return a structured result dict.

    Never includes raw detected values in the returned metadata.
    """
    detector_fn = get_detector(detector_name)
    if detector_fn is None:
        err = _IMPORT_ERRORS.get(f"src.{'hybrid_detection' if detector_name == 'hybrid' else 'detection'}", "unknown")
        return {
            "ok": False,
            "error": f"Detector '{detector_name}' is not available: {err}",
            "detections": [],
            "redacted_text": text,
            "detection_count": 0,
        }

    if PIIRedactor is None or RedactionPolicy is None:
        return {
            "ok": False,
            "error": "PIIRedactor or RedactionPolicy could not be imported.",
            "detections": [],
            "redacted_text": text,
            "detection_count": 0,
        }

    try:
        policy = RedactionPolicy()
        redactor = PIIRedactor(policy=policy, detector=detector_fn)
        result = redactor.process_text(text)
        # detections from PIIRedactor already omit the raw text value
        return {
            "ok": True,
            "error": None,
            "detections": result["detections"],
            "redacted_text": result["redacted_text"],
            "detection_count": result["detection_count"],
        }
    except Exception:
        # Exception messages can contain submitted text or detected PII.
        # Never expose raw exception details in the UI response.
        return {
            "ok": False,
            "error": "Detection failed. Check the application configuration and retry.",
            "detections": [],
            "redacted_text": "",
            "detection_count": 0,
        }


def get_diagnostics() -> dict[str, Any]:
    """Return a safe diagnostics dict (no secrets or PII)."""
    import platform
    diag: dict[str, Any] = {
        "python_version": platform.python_version(),
        "platform": platform.machine(),
        "available_detectors": list(DETECTOR_MAP.keys()),
        "import_errors": dict(_IMPORT_ERRORS),
        "model_file": str(_REPO_ROOT / "models" / "pii_token_clf.npz"),
        "model_exists": (_REPO_ROOT / "models" / "pii_token_clf.npz").exists(),
        "env": {
            "LLM_BACKEND": os.environ.get("LLM_BACKEND", "(not set)"),
            "PII_O_THRESHOLD": os.environ.get("PII_O_THRESHOLD", "(default 0.85)"),
            "HYBRID_MX_RULES": os.environ.get("HYBRID_MX_RULES", "(default 1)"),
            "RENAPO_API_KEY": "configured" if os.environ.get("RENAPO_API_KEY") else "not set",
            "TRUORA_API_KEY": "configured" if os.environ.get("TRUORA_API_KEY") else "not set",
            "WATSONX_APIKEY": "configured" if os.environ.get("WATSONX_APIKEY") else "not set",
        },
    }
    return diag
