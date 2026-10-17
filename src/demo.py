"""One-command end-to-end demo (task T6).

  1. A synthetic CV is encrypted at rest (AES-256-GCM, CPACF on s390x); no plaintext file.
  2. It is decrypted in memory only.
  3. The gateway detects + redacts PII and refuses to send anything that leaks.
  4. Granite (or any LLM_BACKEND) summarizes the redacted text.
  5. Redaction and LLM call are written to the signed, hash-chained audit log
     (HMAC-SHA-512 or ML-DSA-65, per PII_SIGNER). The HMAC key is itself stored encrypted.
  6. The log verifies; one entry is edited in a copy; verification fails.

Run (on the VM):
  python3 -m src.demo                                   # mock LLM, fast
  LLM_BACKEND=llamacpp python3 -m src.demo              # real Granite
  PII_SIGNER=ml-dsa-65 PII_MLDSA_KEY_DIR=keys LLM_BACKEND=llamacpp python3 -m src.demo

Only synthetic data is used. Keys live in ~/.config/pii-vault (chmod 600), outside the repo.
"""

import argparse
import json
import os
import secrets
import shutil
import time

from . import vault
from .audit import AuditLog, verify_log
from .pii_redactor import PIIRedactor

DEMO_CV = (
    "Solicitud de empleo - Ciudad Juárez\n"
    "Nombre completo: Ana Martínez Soto\n"
    "Correo: ana.martinez.soto@example.com\n"
    "Teléfono: +52 656 123 4567\n"
    "CURP: MASA900215MCHRTN08\n"
    "RFC: MASA900215AB1\n"
    "Experiencia: 5 años como analista de datos en la industria maquiladora. "
    "Busca puesto de científica de datos."
)

CONFIG_DIR = os.path.expanduser("~/.config/pii-vault")


def _say(step, text):
    print(f"\n[{step}] {text}")


def _ensure_keys():
    """Create the vault key and an encrypted HMAC key on first run (never inside the repo)."""
    os.environ.setdefault("PII_VAULT_KEY_FILE", os.path.join(CONFIG_DIR, "vault.key"))
    if not os.path.exists(os.environ["PII_VAULT_KEY_FILE"]):
        vault.keygen()
        print(f"  created vault key {os.environ['PII_VAULT_KEY_FILE']} (chmod 600)")
    if not os.environ.get("PII_HMAC_KEY_FILE") and not os.environ.get("PII_HMAC_KEY"):
        enc = os.path.join(CONFIG_DIR, "hmac.key.enc")
        if not os.path.exists(enc):
            blob = vault.encrypt_bytes(secrets.token_hex(64).encode("ascii"))
            fd = os.open(enc, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            print(f"  created HMAC key, stored encrypted: {enc}")
        os.environ["PII_HMAC_KEY_FILE"] = enc


def _pick_detector(name):
    if name == "hybrid":
        try:
            from .hybrid_detection import detect_pii_hybrid
            detect_pii_hybrid("prueba")  # loads the model; fails fast if missing
            return detect_pii_hybrid, "hybrid (regex + NumPy model)"
        except Exception as exc:  # model file not present
            print(f"  hybrid detector unavailable ({exc.__class__.__name__}); using regex")
    from .detection import detect_pii_regex
    return detect_pii_regex, "regex"


def run(workdir="data/demo", backend=None, detector="hybrid", quiet_llm=False):
    t0 = time.perf_counter()
    os.makedirs(workdir, exist_ok=True)
    log_path = os.path.join(workdir, "audit_demo.jsonl")
    if os.path.exists(log_path):
        os.remove(log_path)

    _say(0, "Keys")
    _ensure_keys()
    print(f"  vault: AES-256-GCM via {vault.get_backend().name}")

    _say(1, "Encrypt the CV at rest (no plaintext file is ever written)")
    enc_path = os.path.join(workdir, "cv_demo.txt.enc")
    blob = vault.encrypt_bytes(DEMO_CV.encode("utf-8"))
    with open(enc_path, "wb") as fh:
        fh.write(blob)
    print(f"  {enc_path}: {len(blob)} bytes, plaintext visible in file: "
          f"{'CURP' in blob.decode('latin-1')}")

    _say(2, "Decrypt in memory only")
    text = vault.open_document(enc_path)
    print(f"  {len(text)} characters held in memory")

    _say(3, "Detect + redact, leak guard, then LLM")
    detect, det_name = _pick_detector(detector)
    log = AuditLog(log_path)
    print(f"  detector: {det_name} | audit signer: {log.signer.name}")
    from .llm_gateway import LLMGateway
    gw = LLMGateway(detector=detect, backend=backend,
                    redactor=PIIRedactor(detector=detect, audit_log=log))
    t_llm = time.perf_counter()
    result = gw.summarize(text)
    t_llm = time.perf_counter() - t_llm
    print("  --- sent to the LLM (redacted) ---")
    for line in result["redacted_text"].splitlines():
        print(f"  | {line}")
    leaked = [s for s in ("MASA900215MCHRTN08", "ana.martinez.soto@example.com",
                          "MASA900215AB1") if s in result["redacted_text"]]
    print(f"  original CURP/RFC/email in prompt: {'YES - ' + str(leaked) if leaked else 'none'}")

    _say(4, f"Answer from {result['backend']} ({t_llm:.1f} s)")
    if not quiet_llm:
        for line in result["summary"].strip().splitlines():
            print(f"  {line}")

    _say(5, "Signed audit entries (hashes only, no PII)")
    log.record(result["redacted_text"], result["summary"], [],
               detector=f"llm:{result['backend']}:{os.path.basename(str(result['model']))}")
    with open(log_path, encoding="utf-8") as fh:
        entries = [json.loads(l) for l in fh if l.strip()]
    for e in entries:
        print(f"  #{e['seq']} {e['detector']:<28} counts={e['counts']} "
              f"sig={e['sig_alg']} {e['signature'][:16]}...")

    _say(6, "Verify, then tamper with a copy")
    ok = verify_log(log_path, log.signer)
    print(f"  original log: {'VALID' if ok['ok'] else 'INVALID'} ({ok['entries']} entries)")
    tampered = log_path.replace(".jsonl", "_tampered.jsonl")
    shutil.copyfile(log_path, tampered)
    with open(tampered, encoding="utf-8") as fh:
        lines = fh.readlines()
    first = json.loads(lines[0])
    first["counts"] = {}  # an insider hides that PII was found
    lines[0] = json.dumps(first, ensure_ascii=False) + "\n"
    with open(tampered, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    bad = verify_log(tampered, log.signer)
    print(f"  edited copy:  {'VALID' if bad['ok'] else 'TAMPER DETECTED'}")
    for err in bad["errors"][:3]:
        print(f"    - {err}")

    total = time.perf_counter() - t0
    print(f"\nDone in {total:.1f} s. Head hash to record: {ok['head_hash'][:32]}...")
    return {"valid": ok["ok"], "tamper_detected": not bad["ok"], "leaked": leaked,
            "seconds": total, "entries": ok["entries"]}


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m src.demo")
    p.add_argument("--backend", default=None, help="mock | llamacpp | ollama | watsonx (default: LLM_BACKEND or mock)")
    p.add_argument("--detector", default="hybrid", choices=["hybrid", "regex"])
    p.add_argument("--workdir", default="data/demo")
    a = p.parse_args(argv)
    run(a.workdir, a.backend, a.detector)


if __name__ == "__main__":
    main()
