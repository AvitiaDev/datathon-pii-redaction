import re
from typing import List, Dict, Any

PII_PATTERNS = {
    "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE": r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}',
    "RFC": r'[A-Z&Ñ]{3,4}\d{6}[A-V1-9][A-Z1-9][0-9A]',
    "CURP": r'[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d',
    # Detección heurística de nombres propios basados en capitalización consecutiva
    "NAME": r'\b[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+\b'
}

# Common Spanish words that frequently occur in organizational phrases.
# This heuristic reduces false positives; it does not validate person names.
NON_PERSON_NAME_WORDS = {
    "el", "la", "los", "las", "de", "del",
    "departamento", "recursos", "humanos",
    "universidad", "empresa", "instituto",
    "ministerio", "secretaría", "direccion", "dirección",
    "gerencia", "área", "equipo", "comité",
    "sistema", "atención", "servicio", "centro",
    "hospital", "escuela", "facultad",
    "administración", "gobierno", "desarrollo",
    "calidad", "operaciones", "producción",
    "finanzas", "tecnología", "informática",
    "talento", "contratación", "selección", "personal",
}


def detect_pii_regex(text: str) -> List[Dict[str, Any]]:
    results = []
    for entity_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text):
            value = match.group()

            if entity_type == "NAME":
                words = value.casefold().split()
                if any(word in NON_PERSON_NAME_WORDS for word in words):
                    continue

            results.append({
                "entity_type": entity_type,
                "text": value,
                "start": match.start(),
                "end": match.end(),
                "source": "regex_pattern"
            })
    return results

def detect_all_pii(text: str) -> List[Dict[str, Any]]:
    detections = detect_pii_regex(text)
    detections.sort(key=lambda x: x["start"])
    return detections

if __name__ == "__main__":
    sample_text = "El candidato Daniel Fernández con correo contacto@ejemplo.com, CURP AAAA010101HDFRRT01 y teléfono 656-123-4567 envió sus documentos."
    print("=== PROBANDO DETECCIÓN DE PII EN LINUXONE (MODO PURO) ===")
    print("Texto original:", sample_text)
    print("\nResultados:")
    for item in detect_all_pii(sample_text):
        print(f" - [{item['entity_type']}] '{item['text']}' (pos {item['start']}-{item['end']})")
