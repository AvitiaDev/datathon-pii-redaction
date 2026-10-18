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

Hash agility rules (B1)
  * Every entry records its own `hash_alg`; that algorithm is used for its
    input_hmac, output_hash and for hashing the entry when the NEXT entry
    links to it. Verification never depends on the current PII_HASH_ALG, so
    a log written with SHA-512 still verifies after switching to SHA3-512.
  * `hash_alg` must be in crypto_config.ALLOWED_HASHES and digests must have
    that algorithm's length; anything else (md5, sha1, wrong length) is an
    error, so a log cannot be downgraded. `hash_alg` is covered by the
    signature, so it cannot be changed without breaking the entry.
  * The per-entry stamp is checked with the algorithm named in that entry's
    signed `sig_alg` (e.g. HMAC-SHA3-512), with the verifier's key; an
    unknown or non-allowed `sig_alg` is an error.
  * Algorithms may change between entries (key/algorithm rotation); each
    link is checked with the previous entry's own algorithm.
  * An existing log is fully verified before appending; a corrupted or
    tampered log is never extended (AuditLogCorrupt).
Limitation: deleting entries from the END cannot be detected from the file
alone; `verify` prints the head hash so it can be recorded elsewhere
(screenshot, ticket, second system) as an external anchor.

CLI:
  python3 -m src.audit keygen [--signer hmac|ml-dsa-65|dual] [--out keys]
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
from .signers import get_signer, MlDsaSigner, Ed25519Signer

GENESIS = "0" * 128
POLICY_VERSION = "2026.10.17-1"


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class AuditLogCorrupt(RuntimeError):
    """Raised when appending to a log that does not verify."""


def _entry_alg(entry: dict) -> str:
    alg = entry.get("hash_alg")
    if alg not in crypto_config.ALLOWED_HASHES:
        raise ValueError(f"unsupported hash_alg {alg!r}")
    return alg


def _entry_hash(entry: dict, alg: str = None) -> str:
    """Hash of a full entry (signature included), with the entry's own algorithm."""
    return hashlib.new(alg or _entry_alg(entry), _canonical(entry)).hexdigest()


def _is_hex_digest(value, alg: str) -> bool:
    n = hashlib.new(alg).digest_size * 2
    return (isinstance(value, str) and len(value) == n
            and all(c in "0123456789abcdef" for c in value))


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
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return 0, GENESIS
        rep = verify_log(self.path, self.signer)
        if not rep["ok"]:
            raise AuditLogCorrupt(
                f"{self.path} does not verify ({len(rep['errors'])} problem(s)); "
                "refusing to append. First: " + (rep["errors"][0] if rep["errors"] else "unknown"))
        return rep["entries"], rep["head_hash"]

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
    """Return {"ok", "entries", "head_hash", "errors": [...]}.

    ok is True only if the file exists, has at least one entry, and every
    entry has the expected seq, a valid link to the previous entry, an
    allowed hash_alg with well-formed digests, a known key_id and a valid
    signature.
    """
    errors, prev, expected_seq, n = [], GENESIS, 1, 0
    if not os.path.exists(path):
        return {"ok": False, "entries": 0, "head_hash": GENESIS, "errors": ["log file not found"]}
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            n += 1
            try:
                entry = json.loads(line)
                if not isinstance(entry, dict):
                    raise TypeError("entry is not an object")
                alg = _entry_alg(entry)
                if not (_is_hex_digest(entry.get("input_hmac"), alg)
                        and _is_hex_digest(entry.get("output_hash"), alg)):
                    errors.append(f"line {lineno}: digest does not match hash_alg {alg}")
                body = {k: v for k, v in entry.items() if k != "signature"}
                if entry.get("seq") != expected_seq:
                    errors.append(f"line {lineno}: seq {entry.get('seq')} != expected {expected_seq}")
                if entry.get("prev_hash") != prev:
                    errors.append(f"line {lineno}: hash chain broken")
                checker = (signer.for_entry(entry.get("sig_alg"))
                           if hasattr(signer, "for_entry") else signer)
                if entry.get("key_id") != signer.key_id:
                    errors.append(f"line {lineno}: unknown key_id")
                elif checker is None:
                    errors.append(f"line {lineno}: unsupported sig_alg for this verifier")
                elif not checker.verify(_canonical(body), entry.get("signature", "")):
                    errors.append(f"line {lineno}: signature INVALID")
                prev = _entry_hash(entry, alg)
                seq = entry.get("seq")
                expected_seq = (seq if isinstance(seq, int) and not isinstance(seq, bool)
                                else expected_seq) + 1
            except (ValueError, KeyError, TypeError) as exc:
                errors.append(f"line {lineno}: unreadable ({exc.__class__.__name__})")
                prev = None  # nothing after an unreadable line can link correctly
    if n == 0:
        errors.append("log is empty")
    return {"ok": not errors, "entries": n, "head_hash": prev or GENESIS, "errors": errors}


# ---------------------------------------------------------------- CLI
def _cmd_keygen(args):
    os.makedirs(args.out, exist_ok=True)
    if args.signer == "hmac":
        path = os.path.join(args.out, "hmac.key")
        try:  # created 0600 atomically; never overwrites
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            sys.exit(f"{path} exists; refusing to overwrite.")
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(secrets.token_hex(crypto_config.MIN_KEY_BYTES * 2))  # 512-bit key
        print(f"Wrote {path}\nexport PII_HMAC_KEY_FILE={path}")
    elif args.signer == "dual":
        # Ed25519 + ML-DSA (Redbook dual signing). Reuses an existing ML-DSA pair.
        try:
            Ed25519Signer.keygen(args.out)
        except FileExistsError as exc:
            sys.exit(f"{exc}; refusing to overwrite.")
        pqc = os.environ.get("PII_DUAL_PQC", "ml-dsa-65")
        if os.path.exists(os.path.join(args.out, "mldsa_public.key")):
            note = "existing ML-DSA keypair reused"
        else:
            MlDsaSigner.keygen(pqc, args.out)
            note = f"{pqc.upper()} keypair created"
        print(f"Wrote Ed25519 keypair in {args.out} ({note})\n"
              f"export PII_SIGNER=dual PII_MLDSA_KEY_DIR={args.out}")
    else:
        try:
            alg = MlDsaSigner.keygen(args.signer, args.out)
        except FileExistsError as exc:
            sys.exit(f"{exc}; refusing to overwrite.")
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
    k.add_argument("--signer", default="hmac", choices=["hmac", *MlDsaSigner.VARIANTS, "dual"])
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
