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
| `audit.py` signature (`PII_SIGNER=ml-dsa-65`) | Publicly verifiable signature | ML-DSA-65 (FIPS 204) via liboqs | keypair | **Quantum-safe** — only if liboqs runs on the VM |
| `vault.py` | Encryption at rest of input documents and the HMAC key file | AES-256-GCM (OpenSSL → CPACF on s390x) | 256-bit vault key, `chmod 600`, outside repo | Resilient (Grover → ~128-bit) |
| Git over SSH (team workflow) | Push code | Ed25519 | per-user | Vulnerable to a future CRQC (Shor); out of scope for the prototype |

Previous state: HASH used unkeyed SHA-256 truncated to 10 hex characters. A CURP
or phone number has a small search space, so that hash could be reversed by brute
force. It is now keyed.

## Crypto agility

No algorithm is hardcoded. `src/crypto_config.py` reads:

- `PII_HASH_ALG` = `sha512` (default) | `sha3_512` | `sha384` | `sha3_384` | `sha256`
- `PII_HMAC_KEY_FILE` (or `PII_HMAC_KEY`)
- `PII_SIGNER` = `hmac` (default) | `ml-dsa-44` | `ml-dsa-65` | `ml-dsa-87`
- `PII_MLDSA_KEY_DIR`

Switching the audit log from HMAC to ML-DSA is an environment change, not a code change.

## Hardware on the LinuxONE VM

- CPU flag `msa` → CPACF present. OpenSSL/hashlib on s390x use it for SHA-2 and AES.
- `/dev/z90crypt` exists → check `lszcrypt` to see whether a Crypto Express card is assigned.
- OpenSSL 3.0.13 → no native ML-DSA/ML-KEM (added in OpenSSL 3.5). Hence liboqs.

## Honest wording for the pitch

- With HMAC: "tamper-evident audit log with quantum-resilient HMAC-SHA-512, designed to swap in ML-DSA."
- Only say "quantum-safe signed" if `scripts/setup_mldsa.sh` succeeded and the demo ran with `PII_SIGNER=ml-dsa-65`.
- Known limit: deleting entries from the end of the log is only detectable against an externally recorded head hash.
