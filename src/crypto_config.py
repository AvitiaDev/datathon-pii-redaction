"""Central crypto configuration (crypto agility, Redbook SG24-8525 section 4.2.3).

No algorithm or key is hardcoded in the pipeline. Everything is read here,
from environment variables, so an algorithm can be swapped without touching
detection, redaction, or audit code.

Environment variables
---------------------
PII_HASH_ALG      Hash used for HMAC pseudonyms and audit digests.
                  Allowed: sha512 (default), sha3_512, sha384, sha3_384.
                  SHA-256 is accepted only if set explicitly; 384/512-bit
                  digests keep a wide margin against Grover's algorithm.
PII_HMAC_KEY_FILE Path to a file holding the secret key (hex, >= 32 bytes).
PII_HMAC_KEY      Same key given inline as hex (handy for CI; prefer the file).
PII_SIGNER        Audit signer: "hmac" (default) or "ml-dsa-65" / "ml-dsa-87"
                  (requires liboqs-python; see docs/CRYPTO_INVENTORY.md).
PII_MLDSA_KEY_DIR Directory with ml-dsa private.key / public.key.
"""

import hashlib
import os
import secrets
import warnings

ALLOWED_HASHES = ("sha512", "sha3_512", "sha384", "sha3_384", "sha256")
DEFAULT_HASH = "sha512"
MIN_KEY_BYTES = 32  # 256-bit key: quantum-resilient for symmetric use

_ephemeral_key = None


def hash_alg() -> str:
    alg = os.environ.get("PII_HASH_ALG", DEFAULT_HASH).lower().replace("-", "")
    if alg not in ALLOWED_HASHES:
        raise ValueError(f"PII_HASH_ALG={alg!r} not in {ALLOWED_HASHES}")
    hashlib.new(alg)  # fail early if this OpenSSL build lacks it
    return alg


def hmac_key(required: bool = False) -> bytes:
    """Return the HMAC key. If none is configured:

    - required=True  -> raise (audit logs must be verifiable later)
    - required=False -> per-process random key with a warning (pseudonyms
      will not be stable across runs).
    """
    global _ephemeral_key
    raw = None
    path = os.environ.get("PII_HMAC_KEY_FILE")
    if path:
        with open(path, "r", encoding="ascii") as fh:
            raw = fh.read().strip()
    elif os.environ.get("PII_HMAC_KEY"):
        raw = os.environ["PII_HMAC_KEY"].strip()

    if raw:
        key = bytes.fromhex(raw)
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"HMAC key must be >= {MIN_KEY_BYTES} bytes")
        return key

    if required:
        raise RuntimeError(
            "No HMAC key configured. Run: python3 -m src.audit keygen "
            "then export PII_HMAC_KEY_FILE=keys/hmac.key"
        )
    if _ephemeral_key is None:
        warnings.warn("No PII_HMAC_KEY(_FILE) set; using an ephemeral key.")
        _ephemeral_key = secrets.token_bytes(MIN_KEY_BYTES)
    return _ephemeral_key


def signer_name() -> str:
    return os.environ.get("PII_SIGNER", "hmac").lower()
