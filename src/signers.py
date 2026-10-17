"""Swappable signers for the audit log.

HmacSigner  - works today with the Python standard library. Symmetric:
              tamper-evident against anyone without the key, but it is NOT a
              digital signature (whoever can verify can also forge).
MlDsaSigner - FIPS 204 ML-DSA via liboqs-python (import is lazy). A real
              quantum-safe public-key signature: verifiers only need the
              public key.

Both expose: name, key_id, sign(bytes) -> hex, verify(bytes, hex) -> bool.
"""

import hashlib
import hmac
import os

from . import crypto_config


class HmacSigner:
    def __init__(self, key: bytes = None, alg: str = None):
        self.key = key if key is not None else crypto_config.hmac_key(required=True)
        self.alg = alg or crypto_config.hash_alg()
        self.name = f"HMAC-{self.alg.upper().replace('_', '-')}"
        # Identifies the key without revealing it.
        self.key_id = hmac.new(self.key, b"key-id", hashlib.sha256).hexdigest()[:16]

    def sign(self, message: bytes) -> str:
        return hmac.new(self.key, message, self.alg).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


class MlDsaSigner:
    VARIANTS = {"ml-dsa-44": "ML-DSA-44", "ml-dsa-65": "ML-DSA-65",
                "ml-dsa-87": "ML-DSA-87"}

    def __init__(self, variant: str = "ml-dsa-65", key_dir: str = None,
                 verify_only: bool = False):
        try:
            import oqs  # liboqs-python
        except ImportError as exc:
            raise RuntimeError(
                "ML-DSA needs liboqs + liboqs-python. See docs/CRYPTO_INVENTORY.md"
            ) from exc
        self._oqs = oqs
        self.name = self.VARIANTS[variant.lower()]
        key_dir = key_dir or os.environ.get("PII_MLDSA_KEY_DIR", "keys")
        with open(os.path.join(key_dir, "mldsa_public.key"), "rb") as fh:
            self.public_key = fh.read()
        self.secret_key = None
        if not verify_only:
            with open(os.path.join(key_dir, "mldsa_private.key"), "rb") as fh:
                self.secret_key = fh.read()
        self.key_id = hashlib.sha256(self.public_key).hexdigest()[:16]

    @classmethod
    def keygen(cls, variant: str, key_dir: str):
        import oqs
        alg = cls.VARIANTS[variant.lower()]
        with oqs.Signature(alg) as sig:
            public = sig.generate_keypair()
            secret = sig.export_secret_key()
        os.makedirs(key_dir, exist_ok=True)
        priv = os.path.join(key_dir, "mldsa_private.key")
        with open(priv, "wb") as fh:
            fh.write(secret)
        os.chmod(priv, 0o600)
        with open(os.path.join(key_dir, "mldsa_public.key"), "wb") as fh:
            fh.write(public)
        return alg

    def sign(self, message: bytes) -> str:
        if self.secret_key is None:
            raise RuntimeError("Signer opened in verify-only mode")
        with self._oqs.Signature(self.name, self.secret_key) as sig:
            return sig.sign(message).hex()

    def verify(self, message: bytes, signature: str) -> bool:
        with self._oqs.Signature(self.name) as sig:
            return sig.verify(message, bytes.fromhex(signature), self.public_key)


def get_signer(name: str = None, verify_only: bool = False):
    name = (name or crypto_config.signer_name()).lower()
    if name == "hmac":
        return HmacSigner()
    if name in MlDsaSigner.VARIANTS:
        return MlDsaSigner(name, verify_only=verify_only)
    raise ValueError(f"Unknown signer {name!r}")
