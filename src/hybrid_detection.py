"""Hybrid PII detection: strict regex for structured IDs + ML token classifier.

Priority:
  1. Regex EMAIL, CURP, RFC (strict formats; CURP/RFC are Mexican and absent
     from the Spanish training data).
  2. ML token classifier for everything else.
  3. Regex PHONE only where nothing else matched (fallback for Mexican formats).
"""

from .detection import detect_pii_regex
from .token_classifier import detect_pii_ml

STRONG_REGEX_TYPES = {"EMAIL", "CURP", "RFC"}
FALLBACK_REGEX_TYPES = {"PHONE"}


def _overlaps(a, b):
    return a["start"] < b["end"] and b["start"] < a["end"]


def detect_pii_hybrid(text):
    regex = detect_pii_regex(text)
    strong = [d for d in regex if d["entity_type"] in STRONG_REGEX_TYPES]
    ml = [d for d in detect_pii_ml(text)
          if d["entity_type"] not in STRONG_REGEX_TYPES
          and not any(_overlaps(d, s) for s in strong)]
    fallback = [d for d in regex
                if d["entity_type"] in FALLBACK_REGEX_TYPES
                and not any(_overlaps(d, o) for o in strong + ml)]
    return sorted(strong + ml + fallback,
                  key=lambda d: (d["start"], -(d["end"] - d["start"])))
