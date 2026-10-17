import re
from typing import List, Dict, Any

# 1. Definición de patrones Regex para entidades estructuradas
PII_PATTERNS = {
    "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE": r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}',
    "RFC": r'[A-Z&Ñ]{3,4}\d{6}[A-V1-9][A-Z1-9][0-9A]',
    "CURP": r'[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d'
}

def detect_pii_regex(text: str) -> List[Dict[str, Any]]:
    """
    Detecta PII basada en expresiones regulares.
    Devuelve una lista de diccionarios con el tipo de entidad, el texto detectado y sus posiciones (start, end).
    """
    results = []
    for entity_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text):
            results.append({
                "entity_type": entity_type,
                "text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "source": "regex"
            })
    return results

def detect_all_pii(text: str) -> List[Dict[str, Any]]:
    """
    Función principal que combina detección por Regex y reglas adicionales.
    """
    detections = detect_pii_regex(text)
    # Ordenar detecciones por la posición inicial en el texto
    detections.sort(key=lambda x: x["start"])
    return detections

if __name__ == "__main__":
    # Prueba rápida de funcionamiento en consola
    sample_text = "El candidato Daniel Fernández con correo contacto@ejemplo.com y teléfono 656-123-4567 envió sus documentos."
    print("Texto de prueba:", sample_text)
    print("Detecciones encontradas:")
    for item in detect_all_pii(sample_text):
        print(f" - [{item['entity_type']}] '{item['text']}' (pos {item['start']}-{item['end']})")