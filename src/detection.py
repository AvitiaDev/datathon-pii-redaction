import re
from typing import List, Dict, Any
import spacy

# Cargar el modelo de lenguaje en español de spaCy
# (Asegúrate de haber corrido: python -m spacy download es_core_news_sm)
try:
    nlp = spacy.load("es_core_news_sm")
except OSError:
    # Fallback por si no está descargado aún
    import os
    os.system("python -m spacy download es_core_news_sm")
    nlp = spacy.load("es_core_news_sm")

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

def detect_pii_spacy(text: str) -> List[Dict[str, Any]]:
    """
    Detecta nombres de personas y otras entidades usando spaCy (NER).
    """
    results = []
    doc = nlp(text)
    for ent in doc.ents:
        # Nos interesa principalmente detectar personas (PER)
        if ent.label_ == "PER":
            results.append({
                "entity_type": "NAME",
                "text": ent.text,
                "start": ent.start_char,
                "end": ent.end_char,
                "source": "spacy"
            })
    return results

def detect_all_pii(text: str) -> List[Dict[str, Any]]:
    """
    Combina la detección por Regex y spaCy, ordenando las detecciones 
    por su posición inicial en el texto.
    """
    detections = detect_pii_regex(text) + detect_pii_spacy(text)
    
    # Ordenar detecciones por la posición inicial en el texto
    detections.sort(key=lambda x: x["start"])
    return detections

if __name__ == "__main__":
    sample_text = "El candidato Daniel Fernández con correo contacto@ejemplo.com y teléfono 656-123-4567 envió sus documentos."
    print("Texto de prueba:", sample_text)
    print("\nDetecciones encontradas:")
    for item in detect_all_pii(sample_text):
        print(f" - [{item['entity_type']}] '{item['text']}' (pos {item['start']}-{item['end']}) [via {item['source']}]")