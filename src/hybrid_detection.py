"""Hybrid PII detection: strict regex for structured IDs + ML token classifier.

Priority:
  1. Regex EMAIL, CURP, RFC (strict formats; CURP/RFC are Mexican and absent
     from the Spanish training data).
  2. Mexican rules (A5, on by default; HYBRID_MX_RULES=0 disables them to
     reproduce the "before" numbers):
       - MX phones (10 digits, +52 or after a phone cue) override ML pieces
       - NSS (11 digits after an "NSS" cue) and INE voter key (18 chars)
       - full names after "Nombre:", "Mi nombre es", CV heading, "Atentamente,"
       - long-form dates ("6 de mayo de 1979")
       - addresses: street + number, "Col.", "C.P.", Ciudad Juárez / state names
       - ML NAME spans extended over following capitalized surnames
  3. ML token classifier for everything else.
  4. Regex PHONE only where nothing else matched (fallback).
"""

import os
import re

from .detection import detect_pii_regex
from .token_classifier import detect_pii_ml

STRONG_REGEX_TYPES = {"EMAIL", "CURP", "RFC"}
FALLBACK_REGEX_TYPES = {"PHONE"}

_CAP = r"[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+"
_MESES = "enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre"
_ESTADOS = ("Aguascalientes|Baja California Sur|Baja California|Campeche|Chiapas|Chihuahua|Chih\\.|"
            "Coahuila|Colima|Durango|Guanajuato|Guerrero|Hidalgo|Jalisco|Michoacán|Morelos|Nayarit|"
            "Nuevo León|N\\.L\\.|Oaxaca|Puebla|Querétaro|Quintana Roo|San Luis Potosí|Sinaloa|Sonora|"
            "Tabasco|Tamaulipas|Tlaxcala|Veracruz|Yucatán|Zacatecas|CDMX|Ciudad de México")
# (type, regex, capture group). All are Mexican document conventions, not template-specific.
MX_RULES = [
    # Phones: 10 digits with MX grouping, only with +52 or a phone cue (keeps Spain unaffected)
    ("PHONE", re.compile(r"(?:\+52[\s-]?|(?<=Tel\. )|(?<=Tel: )|(?<=Teléfono: )|(?<=Celular: )|(?<=Cel\. )|(?<=contactarme al ))"
                         r"(?:\(\d{3}\)\s?|\d{3}[\s-]?)\d{3}[\s-]?\d{4}\b"), 0),
    ("ID_NUMBER", re.compile(r"\bNSS[:\s]+(\d{11})\b"), 1),
    ("ID_NUMBER", re.compile(r"\b[A-Z]{6}\d{8}[HM]\d{3}\b"), 0),
    # Full name after a cue: "Nombre:", "Mi nombre es", CV heading, letter sign-off
    ("NAME", re.compile(rf"(?:Nombre(?: completo)?:[ \t]*|[Mm]i nombre es[ \t]+|CURRICULUM VITAE\s+|Atentamente,\s+)"
                        rf"({_CAP}(?:[ \t]+{_CAP}){{0,4}})"), 1),
    # Long-form Spanish dates: "6 de mayo de 1979"
    ("DATE_TIME", re.compile(rf"\b\d{{1,2}} de (?:{_MESES}) de \d{{4}}\b"), 0),
    # Addresses: street + number, colonia, C.P., city and state names
    ("ADDRESS", re.compile(r"\b(?:Calle|Av\.|Avenida|Blvd\.|Boulevard|Privada|Prol\.|Andador|Callejón)\s+[^\n,]{1,60}?\s#?\d{1,5}\b"), 0),
    ("ADDRESS", re.compile(r"\bCol(?:\.|onia)\s+([^\n,]+)"), 1),
    ("ADDRESS", re.compile(r"\bC\.\s?P\.\s*(\d{5})\b"), 1),
    ("ADDRESS", re.compile(rf"\b(?:Ciudad Juárez|{_ESTADOS})(?=[\s,.]|$)"), 0),
]
_SURNAME = re.compile(rf"[ \t]+({_CAP})")
NOT_SURNAME = {"Calle", "Av", "Avenida", "Col", "Colonia", "Tel", "Teléfono", "Correo",
               "Ciudad", "Chihuahua", "Juárez", "Departamento", "Recursos", "Humanos"}


def mx_rules_enabled():
    return os.environ.get("HYBRID_MX_RULES", "1") != "0"


def _overlaps(a, b):
    return a["start"] < b["end"] and b["start"] < a["end"]


def _mx_detections(text):
    out = []
    for etype, rx, grp in MX_RULES:
        for m in rx.finditer(text):
            out.append({"entity_type": etype, "start": m.start(grp), "end": m.end(grp),
                        "source": "mx_rule", "text": m.group(grp)})
    return out


def _extend_names(text, spans):
    for d in spans:
        if d["entity_type"] != "NAME":
            continue
        while True:
            m = _SURNAME.match(text, d["end"])
            if not m or m.group(1) in NOT_SURNAME:
                break
            d["end"] = m.end(1)
        d["text"] = text[d["start"]:d["end"]]
    return spans


def _merge_overlaps(spans):
    """Merge overlapping spans so redaction covers their union (type of the longest part)."""
    merged = []
    for d in sorted(spans, key=lambda d: (d["start"], -(d["end"] - d["start"]))):
        if merged and d["start"] < merged[-1]["end"]:
            m = merged[-1]
            if d["end"] > m["end"]:
                if d["end"] - d["start"] > m["end"] - m["start"]:
                    m["entity_type"] = d["entity_type"]
                m["end"] = d["end"]
            continue
        merged.append(dict(d))
    return merged


# MX rule types that replace overlapping ML pieces (ML splits these badly);
# NAME / ADDRESS / DATE_TIME rules are combined with ML spans instead.
OVERRIDE_TYPES = {"PHONE", "ID_NUMBER"}


def detect_pii_hybrid(text):
    regex = detect_pii_regex(text)
    strong = [d for d in regex if d["entity_type"] in STRONG_REGEX_TYPES]
    mx = []
    if mx_rules_enabled():
        mx = [d for d in _mx_detections(text) if not any(_overlaps(d, s) for s in strong)]
    override = strong + [d for d in mx if d["entity_type"] in OVERRIDE_TYPES]
    ml = [d for d in detect_pii_ml(text)
          if d["entity_type"] not in STRONG_REGEX_TYPES
          and not any(_overlaps(d, s) for s in override)]
    if mx_rules_enabled():
        ml = _extend_names(text, ml)
    combined = override + ml + [d for d in mx if d["entity_type"] not in OVERRIDE_TYPES]
    fallback = [d for d in regex
                if d["entity_type"] in FALLBACK_REGEX_TYPES
                and not any(_overlaps(d, o) for o in combined)]
    spans = combined + fallback
    if mx_rules_enabled():
        spans = _merge_overlaps(spans)
        for d in spans:
            d["text"] = text[d["start"]:d["end"]]
    return sorted(spans, key=lambda d: (d["start"], -(d["end"] - d["start"])))
