"""Generative layer: only redacted text ever reaches the LLM (IBM Granite).

Flow:  raw text -> detector -> redact -> build prompt -> leak guard -> LLM
The leak guard asserts that no detected PII string appears in the prompt.
Only a SHA-256 of the model output is logged: never the prompt, raw text or output.

Backend chosen with LLM_BACKEND:
  ollama  -> OLLAMA_URL (default http://localhost:11434), OLLAMA_MODEL (default granite3.3:2b)
  watsonx -> WATSONX_APIKEY, WATSONX_PROJECT_ID, WATSONX_URL
             (default https://us-south.ml.cloud.ibm.com),
             WATSONX_MODEL (default ibm/granite-3-8b-instruct)
  mock    -> deterministic offline stub (default; used by tests and demos without a backend)
"""

import hashlib
import json
import logging
import os
import urllib.parse
import urllib.request

from .hybrid_detection import detect_pii_hybrid
from .pii_redactor import PIIRedactor

log = logging.getLogger("llm_gateway")

PROMPT_TEMPLATE = (
    "You are an HR assistant. The document below has had personal data replaced "
    "with placeholders such as [NAME_REDACTED]. Do not guess or reconstruct any "
    "redacted value. Summarize the document in 3 short bullet points.\n\n"
    "Document:\n{doc}\n\nSummary:"
)

# Spans shorter than this (e.g. "M", "F", "12") would match ordinary prompt
# text by accident. They are still redacted; they are just not used as guard needles.
MIN_GUARD_LEN = 3


class PIILeakError(RuntimeError):
    """Raised when a detected PII string would reach the LLM prompt."""


def build_prompt(redacted_text):
    return PROMPT_TEMPLATE.format(doc=redacted_text)


def assert_no_pii(prompt, spans):
    """Raise PIILeakError if any detected PII string appears in the prompt."""
    for s in spans:
        if len(s.strip()) >= MIN_GUARD_LEN and s in prompt:
            # Do not put the PII value itself in the exception message.
            raise PIILeakError("detected PII span found in prompt; request blocked")


def _post_json(url, payload, headers=None, timeout=120):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _call_ollama(prompt):
    url = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.environ.get("OLLAMA_MODEL", "granite3.3:2b")
    out = _post_json(f"{url}/api/generate",
                     {"model": model, "prompt": prompt, "stream": False,
                      "options": {"temperature": 0}})
    return out["response"].strip(), model


def _call_watsonx(prompt):
    key = os.environ["WATSONX_APIKEY"]
    project = os.environ["WATSONX_PROJECT_ID"]
    base = os.environ.get("WATSONX_URL", "https://us-south.ml.cloud.ibm.com").rstrip("/")
    model = os.environ.get("WATSONX_MODEL", "ibm/granite-3-8b-instruct")
    data = urllib.parse.urlencode({
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": key}).encode()
    req = urllib.request.Request(
        "https://iam.cloud.ibm.com/identity/token", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        token = json.loads(r.read().decode())["access_token"]
    out = _post_json(
        f"{base}/ml/v1/text/generation?version=2024-05-01",
        {"model_id": model, "project_id": project, "input": prompt,
         "parameters": {"decoding_method": "greedy", "max_new_tokens": 200}},
        headers={"Authorization": f"Bearer {token}"})
    return out["results"][0]["generated_text"].strip(), model


def _call_mock(prompt):
    doc = prompt.split("Document:\n", 1)[-1].split("\n\nSummary:", 1)[0]
    placeholders = sorted({w for w in doc.split() if w.startswith("[") and "]" in w})
    return ("- Document received with personal data removed.\n"
            f"- {len(doc.split())} words; placeholders: {', '.join(placeholders) or 'none'}.\n"
            "- (mock backend: set LLM_BACKEND=ollama or watsonx for Granite)"), "mock"


BACKENDS = {"ollama": _call_ollama, "watsonx": _call_watsonx, "mock": _call_mock}


class LLMGateway:
    def __init__(self, detector=detect_pii_hybrid, backend=None, redactor=None):
        self.detector = detector
        self.backend = backend or os.environ.get("LLM_BACKEND", "mock")
        if self.backend not in BACKENDS:
            raise ValueError(f"unknown LLM_BACKEND {self.backend!r}")
        self.redactor = redactor or PIIRedactor(detector=detector)

    def summarize(self, text):
        detections = self.detector(text)
        spans = [text[d["start"]:d["end"]] for d in detections]
        redacted = self.redactor.process_text(text)["redacted_text"]
        prompt = build_prompt(redacted)
        assert_no_pii(prompt, spans)  # hard stop before anything leaves the process

        output, model = BACKENDS[self.backend](prompt)
        out_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()
        log.info("llm_call backend=%s model=%s detections=%d output_sha256=%s",
                 self.backend, model, len(detections), out_hash)
        return {"summary": output, "output_sha256": out_hash, "model": model,
                "backend": self.backend, "redacted_text": redacted,
                "detection_count": len(detections)}


def main():
    import argparse
    p = argparse.ArgumentParser(description="Redact a document, then summarize it with Granite.")
    p.add_argument("file", nargs="?", help="text file (default: built-in synthetic demo)")
    p.add_argument("--backend", choices=sorted(BACKENDS))
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    text = open(a.file, encoding="utf-8").read() if a.file else (
        "Solicitud de empleo. Nombre: Laura Gómez Ruiz. Correo: laura.gomez@example.com. "
        "Teléfono: 656 123 4567. CURP: GORL900101MCHMZR09. Experiencia: 5 años como analista "
        "de datos en Ciudad Juárez; busca puesto de científica de datos.")
    r = LLMGateway(backend=a.backend).summarize(text)
    print("Redacted prompt input:\n" + r["redacted_text"] + "\n")
    print(f"Summary ({r['backend']}/{r['model']}):\n{r['summary']}\n")
    print("output_sha256:", r["output_sha256"])


if __name__ == "__main__":
    main()
