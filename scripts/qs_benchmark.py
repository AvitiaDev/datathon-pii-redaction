"""Quantum-safe benchmark against IBM Redbook SG24-8525-01.

Measures this project on the current machine (run it on the LinuxONE VM) and
compares it with the reference tables in "Transitioning to Quantum-Safe
Cryptography on IBM Z" (Dec 2025):

  Table 1-1  quantum impact per algorithm   -> every crypto use in the project
  Table 6-1  key / signature sizes          -> measured ML-DSA sizes (liboqs)
                                               and classical RSA / ECC / Ed25519
  Table 2-1  quantum-safe journey stages    -> project scorecard with evidence
  Table 2-4  cryptographic agility          -> project scorecard with evidence
  (performance is not in the Redbook; measured here for context:
   sign/verify ops/s, hash/MAC/AES throughput, audit-log cost per entry)

Writes reports/qs_benchmark.json and reports/figures_data/qs_*.csv.
Charts: Rscript r/plot_qs_benchmark.R

Usage:
  python3 scripts/qs_benchmark.py            # ~30-60 s on the VM
  python3 scripts/qs_benchmark.py --quick    # fewer iterations
Synthetic data only; no keys are written to the repository.
"""

import argparse
import csv
import hashlib
import hmac
import json
import os
import platform
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT_JSON = os.path.join(ROOT, "reports", "qs_benchmark.json")
OUT_DIR = os.path.join(ROOT, "reports", "figures_data")

# ---------------------------------------------------------------- Redbook references
# Table 6-1 (bytes). ML-DSA private token includes the public key.
REDBOOK_T61 = {
    "RSA-4096 (CRT)": {"public": 1104, "private": 2504, "signature": 512},
    "ECC Ed448":      {"public": 79,   "private": 323,  "signature": 114},
    "ML-DSA-44":      {"public": 1312, "private": 3872, "signature": 2420},
    "ML-DSA-65":      {"public": 1952, "private": 5984, "signature": 3293},
    "ML-DSA-87":      {"public": 2592, "private": 7488, "signature": 4595},
}
# Table 1-1
REDBOOK_T11 = {"AES": "Secure", "SHA-2/SHA-3": "Secure", "RSA": "Broken",
               "ECDSA/ECDH/EdDSA": "Broken", "DSA": "Broken"}

# Every crypto use in this project, classified with Table 1-1 (+ FIPS 204 for ML-DSA).
INVENTORY = [
    # component, purpose, algorithm, family, redbook_status, in_pipeline
    ("vault.py", "Documents and HMAC key at rest", "AES-256-GCM", "AES", "Secure", True),
    ("audit.py", "Output hash, hash chain", "SHA-512", "SHA-2/SHA-3", "Secure", True),
    ("audit.py", "Keyed input fingerprint", "HMAC-SHA-512", "SHA-2/SHA-3", "Secure", True),
    ("policies.py", "Pseudonyms (HASH policy)", "HMAC-SHA-512", "SHA-2/SHA-3", "Secure", True),
    ("signers.py", "Audit entry signature", "ML-DSA-65", "ML-DSA (FIPS 204)", "Quantum-safe", True),
    ("signers.py", "Audit entry stamp (fallback)", "HMAC-SHA-512", "SHA-2/SHA-3", "Secure", True),
    ("signers.py", "Classical half of dual signature (always paired with ML-DSA)", "Ed25519",
     "ECDSA/ECDH/EdDSA", "Broken alone, paired with ML-DSA", True),
    ("llm_gateway.py", "Answer fingerprint in logs", "SHA-256", "SHA-2/SHA-3", "Secure", True),
    ("team workflow", "Git over SSH", "Ed25519", "ECDSA/ECDH/EdDSA", "Broken", False),
]

# Table 2-1 journey and Table 2-4 agility, scored 0 = not done, 1 = partial, 2 = done.
JOURNEY = [
    ("Preparation", 2, "Team studied SG24-8525; NIST FIPS 203/204/205 followed; plan in project docs"),
    ("Discovery", 2, "Crypto inventory (docs/CRYPTO_INVENTORY.md) + CycloneDX 1.6 CBOM (docs/CBOM.json); data classified as PII"),
    ("Risk assessment", 2, "Each use classified with Table 1-1; harvest-now-decrypt-later risk on stored CVs identified"),
    ("Risk mitigation", 2, "Unkeyed SHA-256 pseudonyms fixed (keyed HMAC); Ed25519 accepted as out of scope"),
    ("Migration to PQC", 2, "ML-DSA-65 signatures on s390x; dual signing Ed25519 + ML-DSA-65 (Redbook 2.2.6), both must verify; ML-KEM not applicable (no key exchange)"),
]
AGILITY = [
    ("Algorithm", 2, "PII_HASH_ALG and PII_SIGNER select algorithms; per-entry hash_alg/sig_alg; rotation inside one log tested"),
    ("Protocol", None, "Not applicable: the pipeline runs on one machine and uses no network protocol (no TLS)"),
    ("Implementation", 2, "Signer interface: HMAC today, ML-DSA via liboqs; vault: cryptography or ctypes libcrypto"),
    ("Platform", 2, "Pure-Python/NumPy on s390x; OpenSSL uses CPACF; path to ICSF CCA/EP11 documented"),
    ("Retirement", 2, "Weak algorithms (md5, sha1, unkeyed SHA-256 pseudonyms) rejected or retired; no-downgrade check"),
]
# Table 2-3 inventory questionnaire areas covered by docs/CRYPTO_INVENTORY.md + CBOM
QUESTIONNAIRE = [
    ("Identity", 2), ("Symmetric crypto", 2), ("Asymmetric crypto", 2), ("Hashing", 2),
    ("Crypto services", 2), ("Interoperability", 1), ("Policies/standards", 2),
    ("Key management", 2), ("Preliminary assessment", 2),
]


# ---------------------------------------------------------------- timing helpers
def rate(fn, min_time=1.0, min_iter=3):
    """Calls per second of fn(), measured for at least min_time seconds."""
    fn()  # warm-up
    n, t0 = 0, time.perf_counter()
    while True:
        fn()
        n += 1
        dt = time.perf_counter() - t0
        if dt >= min_time and n >= min_iter:
            return n / dt


def throughput_mb_s(fn, size, min_time=1.0):
    return rate(fn, min_time) * size / 1e6


# ---------------------------------------------------------------- benchmarks
def bench_mldsa(min_time):
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import oqs
    except Exception as exc:  # liboqs not installed on this machine
        return [], f"liboqs not available ({exc.__class__.__name__}); run scripts/setup_mldsa.sh"
    rows, msg = [], secrets.token_bytes(1024)
    for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        with oqs.Signature(alg) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
            sig = s.sign(msg)
            assert s.verify(msg, sig, pk)
            keygen = rate(lambda: oqs.Signature(alg).generate_keypair(), min_time)
            sign = rate(lambda: s.sign(msg), min_time)
            verify = rate(lambda: s.verify(msg, sig, pk), min_time)
        ref = REDBOOK_T61[alg]
        rows.append({"algorithm": alg, "family": "PQC (FIPS 204)", "source": "liboqs on " + platform.machine(),
                     "public": len(pk), "private": len(sk) + len(pk), "signature": len(sig),
                     "ref_public": ref["public"], "ref_private": ref["private"], "ref_signature": ref["signature"],
                     "keygen_per_s": keygen, "sign_per_s": sign, "verify_per_s": verify})
    return rows, None


def bench_classical(min_time):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
    except ImportError:
        return [], "cryptography package not installed"
    msg = secrets.token_bytes(1024)
    der = dict(encoding=serialization.Encoding.DER)
    rows = []

    def add(name, sk, sign, verify, pub_bytes, priv_bytes, ref=None):
        sig = sign()
        verify(sig)
        r = {"algorithm": name, "family": "Classical (Shor: broken)", "source": "OpenSSL via cryptography",
             "public": pub_bytes, "private": priv_bytes, "signature": len(sig),
             "ref_public": None, "ref_private": None, "ref_signature": None,
             "keygen_per_s": None, "sign_per_s": rate(sign, min_time),
             "verify_per_s": rate(lambda: verify(sig), min_time)}
        if ref:
            r.update(ref_public=ref["public"], ref_private=ref["private"], ref_signature=ref["signature"])
        rows.append(r)

    k = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    add("RSA-4096 (CRT)", k, lambda: k.sign(msg, pss, hashes.SHA256()),
        lambda s: k.public_key().verify(s, msg, pss, hashes.SHA256()),
        len(k.public_key().public_bytes(format=serialization.PublicFormat.SubjectPublicKeyInfo, **der)),
        len(k.private_bytes(format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption(), **der)),
        REDBOOK_T61["RSA-4096 (CRT)"])

    k = ec.generate_private_key(ec.SECP256R1())
    add("ECDSA P-256", k, lambda: k.sign(msg, ec.ECDSA(hashes.SHA256())),
        lambda s: k.public_key().verify(s, msg, ec.ECDSA(hashes.SHA256())), 65, 32 + 65)

    k = ed25519.Ed25519PrivateKey.generate()
    add("Ed25519", k, lambda: k.sign(msg), lambda s: k.public_key().verify(s, msg), 32, 64)

    try:
        k = ed448.Ed448PrivateKey.generate()
        add("ECC Ed448", k, lambda: k.sign(msg), lambda s: k.public_key().verify(s, msg), 57, 57 + 57,
            REDBOOK_T61["ECC Ed448"])
    except Exception:
        pass
    return rows, None


def bench_symmetric(min_time):
    size = 1 << 20  # 1 MiB
    data = secrets.token_bytes(size)
    key = secrets.token_bytes(64)
    rows = []
    for name, fn in [
        ("SHA-256", lambda: hashlib.sha256(data).digest()),
        ("SHA-512", lambda: hashlib.sha512(data).digest()),
        ("SHA3-512", lambda: hashlib.sha3_512(data).digest()),
        ("HMAC-SHA-512", lambda: hmac.new(key, data, "sha512").digest()),
    ]:
        rows.append({"algorithm": name, "mb_per_s": throughput_mb_s(fn, size, min_time),
                     "redbook_quantum": "Secure"})
    try:
        from src import vault
        k = secrets.token_bytes(32)
        rows.append({"algorithm": "AES-256-GCM (vault)",
                     "mb_per_s": throughput_mb_s(lambda: vault.encrypt_bytes(data, key=k), size, min_time),
                     "redbook_quantum": "Secure"})
    except Exception as exc:
        rows.append({"algorithm": "AES-256-GCM (vault)", "mb_per_s": None,
                     "redbook_quantum": "Secure", "note": exc.__class__.__name__})
    return rows


def bench_audit(min_time, mldsa_available):
    """Entries per second and bytes per entry for each signer."""
    from src.audit import AuditLog
    from src.signers import HmacSigner
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        os.environ.setdefault("PII_HMAC_KEY", secrets.token_hex(64))
        signers = [("HMAC-SHA-512", lambda: HmacSigner())]
        if mldsa_available:
            from src.signers import MlDsaSigner
            kd = os.path.join(tmp, "keys")
            MlDsaSigner.keygen("ml-dsa-65", kd)
            signers.append(("ML-DSA-65", lambda: MlDsaSigner("ml-dsa-65", key_dir=kd)))
            try:
                from src.signers import DualSigner, Ed25519Signer
                Ed25519Signer.keygen(kd)
                signers.append(("Ed25519 + ML-DSA-65 (dual)", lambda: DualSigner(
                    Ed25519Signer(key_dir=kd), MlDsaSigner("ml-dsa-65", key_dir=kd))))
            except Exception as exc:  # cryptography missing
                print("  dual signer skipped:", exc.__class__.__name__)
        for name, make in signers:
            path = os.path.join(tmp, f"{name}.jsonl")
            log = AuditLog(path, signer=make())
            text = "Nombre completo: [NAME_REDACTED] CURP: [CURP_REDACTED] Correo: [EMAIL_REDACTED]"
            dets = [{"entity_type": t} for t in ("NAME", "CURP", "EMAIL")]
            per_s = rate(lambda: log.record(text, text, dets), min_time)
            with open(path, encoding="utf-8") as fh:
                lines = [l for l in fh if l.strip()]
            avg = sum(len(l.encode()) for l in lines) / len(lines)
            from src.audit import verify_log
            t0 = time.perf_counter()
            rep = verify_log(path, make())
            vps = len(lines) / (time.perf_counter() - t0)
            rows.append({"signer": name, "entries_per_s": per_s, "bytes_per_entry": avg,
                         "verify_entries_per_s": vps, "verified": rep["ok"], "entries": len(lines)})
    return rows


def write_csv(name, rows, fields):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in fields})
    print("wrote", os.path.relpath(path, ROOT))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args(argv)
    t = 0.3 if a.quick else 1.0

    print("ML-DSA (liboqs)...")
    pqc, pqc_note = bench_mldsa(t)
    print("classical signatures...")
    classical, cl_note = bench_classical(t)
    print("hash / MAC / AES throughput...")
    sym = bench_symmetric(t)
    print("audit log cost...")
    audit = bench_audit(t, bool(pqc))

    inv = [dict(zip(("component", "purpose", "algorithm", "family", "redbook_status", "in_pipeline"), r))
           for r in INVENTORY]
    pipeline = [r for r in inv if r["in_pipeline"]]
    # A use counts as safe unless its protection relies on a broken algorithm alone.
    safe_share = sum(r["redbook_status"] != "Broken" for r in pipeline) / len(pipeline)
    journey = [{"stage": s, "score": v, "max": 2, "evidence": e} for s, v, e in JOURNEY]
    agility = [{"dimension": s, "score": v, "max": 0 if v is None else 2, "evidence": e} for s, v, e in AGILITY]
    quest = [{"area": s, "score": v, "max": 2} for s, v in QUESTIONNAIRE]

    sigs = pqc + classical
    summary = {
        "pipeline_crypto_uses": len(pipeline),
        "pipeline_quantum_safe_or_resilient_share": safe_share,
        "shor_vulnerable_uses_in_pipeline": sum(r["redbook_status"] == "Broken" for r in pipeline),
        "journey_score": f"{sum(j['score'] for j in journey)}/{2 * len(journey)}",
        "agility_score": f"{sum(x['score'] or 0 for x in agility)}/{sum(x['max'] for x in agility)} applicable"
                         + "".join(f" ({x['dimension']} n/a)" for x in agility if x['score'] is None),
        "questionnaire_coverage": f"{sum(q['score'] for q in quest)}/{2 * len(quest)}",
    }
    for r in pqc:
        if r["algorithm"] == "ML-DSA-65":
            summary["mldsa65_signature_bytes_measured_vs_redbook"] = [r["signature"], r["ref_signature"]]
            summary["mldsa65_sign_per_s"] = round(r["sign_per_s"])
            summary["mldsa65_verify_per_s"] = round(r["verify_per_s"])
    for r in audit:
        summary[f"audit_entries_per_s_{r['signer']}"] = round(r["entries_per_s"])
        summary[f"audit_bytes_per_entry_{r['signer']}"] = round(r["bytes_per_entry"])

    result = {
        "reference": "IBM Redbook SG24-8525-01, Transitioning to Quantum-Safe Cryptography on IBM Z (Dec 2025): Tables 1-1, 2-1, 2-3, 2-4, 6-1",
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": {"machine": platform.machine(), "python": platform.python_version(),
                 "openssl": __import__("ssl").OPENSSL_VERSION},
        "notes": [n for n in (pqc_note, cl_note) if n] + [
            "Redbook Table 6-1 ML-DSA sizes are CCA key tokens; liboqs returns raw FIPS 204 keys. "
            "Private size here = raw private + public key, to match the token definition.",
            "Performance figures are not in the Redbook; they are context for this VM only.",
        ],
        "summary": summary, "inventory": inv, "signatures": sigs, "symmetric": sym,
        "audit": audit, "journey": journey, "agility": agility, "questionnaire": quest,
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    print("wrote", os.path.relpath(OUT_JSON, ROOT))

    write_csv("qs_inventory.csv", inv, ["component", "purpose", "algorithm", "family", "redbook_status", "in_pipeline"])
    write_csv("qs_signatures.csv", sigs, ["algorithm", "family", "source", "public", "private", "signature",
                                          "ref_public", "ref_private", "ref_signature",
                                          "keygen_per_s", "sign_per_s", "verify_per_s"])
    write_csv("qs_symmetric.csv", sym, ["algorithm", "mb_per_s", "redbook_quantum"])
    write_csv("qs_audit.csv", audit, ["signer", "entries_per_s", "bytes_per_entry", "verify_entries_per_s", "verified"])
    write_csv("qs_scorecard.csv",
              [{"framework": "Journey (Table 2-1)", "item": j["stage"], "score": j["score"], "max": 2, "evidence": j["evidence"]} for j in journey] +
              [{"framework": "Agility (Table 2-4)", "item": x["dimension"], "score": x["score"], "max": x["max"], "evidence": x["evidence"]} for x in agility] +
              [{"framework": "Inventory questionnaire (Table 2-3)", "item": q["area"], "score": q["score"], "max": 2, "evidence": ""} for q in quest],
              ["framework", "item", "score", "max", "evidence"])

    print("\nSummary")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    for n in result["notes"][:2]:
        print("  note:", n)


if __name__ == "__main__":
    main()
