"""Tamper-evident audit log for redaction events (Redbook SG24-8525 section 3.3).

Each redaction appends one JSON line. The log never contains raw PII:

  seq, timestamp, policy_version, detector,
  input_hmac   - keyed HMAC of the original text (a plain hash of short PII
                 could be brute-forced, so the input digest is always keyed)
  output_hash  - hash of the redacted text
  counts       - detections per entity type
  prev_hash    - hash of the previous full entry (hash chain)
  sig_alg, key_id, signature - stamp over all fields above

Editing, reordering or deleting any entry breaks a signature or the chain.
Limitation: deleting entries from the END cannot be detected from the file
alone; `verify` prints the head hash so it can be recorded elsewhere
(screenshot, ticket, second system) as an external anchor.

CLI:
  python3 -m src.audit keygen [--signer hmac|ml-dsa-65] [--out keys]
  python3 -m src.audit demo   [--log logs/audit_demo.jsonl]
  python3 -m src.audit verify --log logs/audit.jsonl [--signer ...]
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from collections import Counter
from datetime import datetime, timezone

from . import crypto_config
from .signers import get_signer, MlDsaSigner

GENESIS = "0" * 128
POLICY_VERSION = "2026.10.17-1"


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _entry_hash(entry: dict) -> str:
    return hashlib.new(crypto_config.hash_alg(), _canonical(entry)).hexdigest()


class AuditLog:
    def __init__(self, path: str, signer=None, policy_version: str = POLICY_VERSION):
        self.path = path
        self.signer = signer or get_signer()
        self.policy_version = policy_version
        self.alg = crypto_config.hash_alg()
        self._digest_key = crypto_config.hmac_key(required=True)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._seq, self._prev = self._load_tail()

    def _load_tail(self):
        seq, prev = 0, GENESIS
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        entry = json.loads(line)
                        seq, prev = entry["seq"], _entry_hash(entry)
        return seq, prev

    def record(self, input_text: str, output_text: str, detections, detector: str = "unknown") -> dict:
        counts = Counter(d["entity_type"] for d in detections)
        entry = {
            "seq": self._seq + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "policy_version": self.policy_version,
            "detector": detector,
            "hash_alg": self.alg,
            "input_hmac": hmac.new(self._digest_key, input_text.encode("utf-8"), self.alg).hexdigest(),
            "output_hash": hashlib.new(self.alg, output_text.encode("utf-8")).hexdigest(),
            "counts": dict(sorted(counts.items())),
            "prev_hash": self._prev,
            "sig_alg": self.signer.name,
            "key_id": self.signer.key_id,
        }
        entry["signature"] = self.signer.sign(_canonical(entry))
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._seq, self._prev = entry["seq"], _entry_hash(entry)
        return entry


def verify_log(path: str, signer) -> dict:
    """Return {"ok", "entries", "head_hash", "errors": [...]}."""
    errors, prev, expected_seq, n = [], GENESIS, 1, 0
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            n += 1
            try:
                entry = json.loads(line)
                body = {k: v for k, v in entry.items() if k != "signature"}
                if entry.get("seq") != expected_seq:
                    errors.append(f"line {lineno}: seq {entry.get('seq')} != expected {expected_seq}")
                if entry.get("prev_hash") != prev:
                    errors.append(f"line {lineno}: hash chain broken")
                if entry.get("key_id") != signer.key_id:
                    errors.append(f"line {lineno}: unknown key_id")
                elif not signer.verify(_canonical(body), entry.get("signature", "")):
                    errors.append(f"line {lineno}: signature INVALID")
                prev = _entry_hash(entry)
                expected_seq = entry.get("seq", expected_seq) + 1
            except (ValueError, KeyError, TypeError) as exc:
                errors.append(f"line {lineno}: unreadable ({exc.__class__.__name__})")
    return {"ok": not errors and n > 0, "entries": n, "head_hash": prev, "errors": errors}


# ---------------------------------------------------------------- CLI
def _cmd_keygen(args):
    os.makedirs(args.out, exist_ok=True)
    if args.signer == "hmac":
        path = os.path.join(args.out, "hmac.key")
        if os.path.exists(path):
            sys.exit(f"{path} exists; refusing to overwrite.")
        with open(path, "w", encoding="ascii") as fh:
            fh.write(secrets.token_hex(crypto_config.MIN_KEY_BYTES * 2))  # 512-bit key
        os.chmod(path, 0o600)
        print(f"Wrote {path}\nexport PII_HMAC_KEY_FILE={path}")
    else:
        alg = MlDsaSigner.keygen(args.signer, args.out)
        print(f"Wrote {alg} keypair in {args.out}\nexport PII_SIGNER={args.signer} PII_MLDSA_KEY_DIR={args.out}")


def _cmd_verify(args):
    signer = get_signer(args.signer, verify_only=True)
    rep = verify_log(args.log, signer)
    status = "VALID" if rep["ok"] else "TAMPERED / INVALID"
    print(f"Log: {args.log}\nSigner: {signer.name} (key {signer.key_id})")
    print(f"Entries: {rep['entries']}\nResult: {status}")
    for err in rep["errors"][:20]:
        print("  -", err)
    print(f"Head hash (record externally): {rep['head_hash'][:32]}...")
    sys.exit(0 if rep["ok"] else 1)


def _cmd_demo(args):
    """Synthetic end-to-end demo: redact, log, verify, tamper, verify again."""
    from .pii_redactor import PIIRedactor
    if os.path.exists(args.log):
        os.remove(args.log)
    log = AuditLog(args.log)
    redactor = PIIRedactor(audit_log=log)
    samples = [
        "Candidata: correo ana.ejemplo@example.com, tel +52 656 123 4567.",
        "CURP de prueba GODE561231HDFXXX09 y RFC ABCD9001011A2.",
        "Texto sin datos personales.",
    ]
    for s in samples:
        print("REDACTED:", redactor.process_text(s)["redacted_text"])
    signer = log.signer
    print("\n[1] Verify untouched log:", "VALID" if verify_log(args.log, signer)["ok"] else "INVALID")
    with open(args.log, encoding="utf-8") as fh:
        lines = fh.readlines()
    e = json.loads(lines[1])
    e["counts"] = {}  # attacker hides that PII was found
    lines[1] = json.dumps(e, ensure_ascii=False) + "\n"
    with open(args.log, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    rep = verify_log(args.log, signer)
    print("[2] After editing entry 2:", "VALID" if rep["ok"] else "TAMPER DETECTED")
    for err in rep["errors"]:
        print("    -", err)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m src.audit")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--signer", default="hmac", choices=["hmac", *MlDsaSigner.VARIANTS])
    k.add_argument("--out", default="keys")
    v = sub.add_parser("verify")
    v.add_argument("--log", required=True)
    v.add_argument("--signer", default=None)
    d = sub.add_parser("demo")
    d.add_argument("--log", default="logs/audit_demo.jsonl")
    args = p.parse_args(argv)
    {"keygen": _cmd_keygen, "verify": _cmd_verify, "demo": _cmd_demo}[args.cmd](args)


if __name__ == "__main__":
    main()
