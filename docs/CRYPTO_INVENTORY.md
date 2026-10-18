# Crypto inventory and quantum-safe status

Following the IBM Redbook *Transitioning to Quantum-Safe Cryptography on IBM Z*
(SG24-8525-01): inventory first (§4.2.2), crypto agility (§4.2.3), secure logging (§3.3).

## Inventory

| Where | Purpose | Algorithm | Key | Quantum status |
|---|---|---|---|---|
| `policies.py` HASH strategy | Stable pseudonyms for PII | HMAC-SHA-512 (configurable) | 512-bit secret | Resilient: Grover only halves strength, ~256-bit margin remains |
| `audit.py` `input_hmac` | Prove which input was processed without storing it | HMAC-SHA-512 | same secret | Resilient |
| `audit.py` `output_hash`, `prev_hash` | Integrity + hash chain | SHA-512 | none | Resilient |
| `audit.py` signature (default) | Tamper evidence on each entry | HMAC-SHA-512 | same secret | Resilient, but **symmetric**: not a digital signature |
| `audit.py` signature (`PII_SIGNER=ml-dsa-65`) | Publicly verifiable signature | ML-DSA-65 (FIPS 204) via liboqs | keypair | **Quantum-safe — verified on LinuxONE s390x** (liboqs 0.14.0 + liboqs-python 0.16.0, Oct 17 2026) |
| `signers.py` dual (`PII_SIGNER=dual`) | Redbook §2.2.6 dual signing: classical + post-quantum over the same entry; **both must verify** | Ed25519 + ML-DSA-65 | two keypairs in `keys/` (private 0600) | **Quantum-safe while ML-DSA holds; still safe today if ML-DSA were ever broken** |
| `vault.py` | Encryption at rest of input documents and the HMAC key file | AES-256-GCM (OpenSSL → CPACF on s390x) | 256-bit vault key, `chmod 600`, outside repo | Resilient (Grover → ~128-bit) |
| Git over SSH (team workflow) | Push code | Ed25519 | per-user | Vulnerable to a future CRQC (Shor); out of scope for the prototype |

Previous state: HASH used unkeyed SHA-256 truncated to 10 hex characters. A CURP
or phone number has a small search space, so that hash could be reversed by brute
force. It is now keyed.

## Machine-readable CBOM

The same inventory as a CycloneDX 1.6 Cryptographic Bill of Materials: [`docs/CBOM.json`](CBOM.json)
(algorithms with OIDs, classical and NIST quantum security levels, and the keys that protect each other).

## Crypto agility

No algorithm is hardcoded. `src/crypto_config.py` reads:

- `PII_HASH_ALG` = `sha512` (default) | `sha3_512` | `sha384` | `sha3_384` | `sha256`
- `PII_HMAC_KEY_FILE` (or `PII_HMAC_KEY`)
- `PII_SIGNER` = `hmac` (default) | `ml-dsa-44` | `ml-dsa-65` | `ml-dsa-87` | `dual` (Ed25519 + ML-DSA, `PII_DUAL_PQC` picks the variant)
- `PII_MLDSA_KEY_DIR`

Switching the audit log from HMAC to ML-DSA is an environment change, not a code change.

## Hardware on the LinuxONE VM

- CPU flag `msa` → CPACF present. OpenSSL/hashlib on s390x use it for SHA-2 and AES.
- `/dev/z90crypt` exists → check `lszcrypt` to see whether a Crypto Express card is assigned.
- OpenSSL 3.0.13 → no native ML-DSA/ML-KEM (added in OpenSSL 3.5). Hence liboqs.

## Honest wording for the pitch

- With HMAC: "tamper-evident audit log with quantum-resilient HMAC-SHA-512, designed to swap in ML-DSA."
- With `PII_SIGNER=ml-dsa-65`: "audit log signed with ML-DSA (FIPS 204) on LinuxONE". Verified on the VM: sign/verify True, tamper rejected; `python3 -m src.demo` end to end in 26 s with Granite, log VALID, edited copy TAMPER DETECTED.
- To reproduce: `bash scripts/setup_mldsa.sh`, `python3 -m src.audit keygen --signer ml-dsa-65 --out keys`, then `LLM_BACKEND=llamacpp PII_SIGNER=ml-dsa-65 PII_MLDSA_KEY_DIR=keys python3 -m src.demo`.
- With `PII_SIGNER=dual`: "every audit entry carries a classical and a post-quantum signature, as IBM does for Z firmware; an attacker must break both." Setup: `python3 -m src.audit keygen --signer dual --out keys` (reuses the ML-DSA pair).
- Truncation/rollback: `python3 -m src.audit anchor` writes a signed checkpoint; `verify --anchor` fails on a shorter or rewritten log. The checkpoint must live off-host to be meaningful.
- `PII_SECURITY_PROFILE=pq` refuses HMAC-only signing (fail closed).
- Out of prototype scope: HSM/Crypto Express key custody, key rotation/revocation runbook, PQ/hybrid TLS and SSH transport.
