"""Swappable signers for the audit log.

HmacSigner  - works today with the Python standard library. Symmetric:
              tamper-evident against anyone without the key, but it is NOT a
              digital signature (whoever can verify can also forge).
MlDsaSigner - FIPS 204 ML-DSA via liboqs-python (import is lazy). A real
              quantum-safe public-key signature: verifiers only need the
              public key.
Ed25519Signer - classical EdDSA via the `cryptography` package (broken by a
              future quantum computer; used only as half of a dual signature).
DualSigner  - Redbook SG24-8525 §2.2.6 "dual signing": classical Ed25519 AND
              ML-DSA over the same message. Verification passes only if BOTH
              signatures verify, so an attacker must break both algorithms.

Both expose: name, key_id, sign(bytes) -> hex, verify(bytes, hex) -> bool.
"""

import hashlib
import hmac
import os
import stat

from . import crypto_config


def _write_new(path: str, data: bytes, mode: int) -> None:
    """Create a file with `mode` atomically; never overwrite an existing one."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _check_private(path: str) -> None:
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise PermissionError(f"{path} is readable by others (mode {oct(mode)}); run chmod 600")


class HmacSigner:
    def __init__(self, key: bytes = None, alg: str = None):
        self.key = key if key is not None else crypto_config.hmac_key(required=True)
        self.alg = alg or crypto_config.hash_alg()
        self.name = f"HMAC-{self.alg.upper().replace('_', '-')}"
        # Identifies the key without revealing it.
        self.key_id = hmac.new(self.key, b"key-id", hashlib.sha256).hexdigest()[:16]

    @staticmethod
    def alg_from_name(sig_alg: str):
        """'HMAC-SHA3-512' -> 'sha3_512'; None if not an allowed HMAC algorithm."""
        if not isinstance(sig_alg, str) or not sig_alg.startswith("HMAC-"):
            return None
        alg = sig_alg[5:].lower().replace("-", "_", 1) if sig_alg[5:].upper().startswith("SHA3-") \
            else sig_alg[5:].lower().replace("-", "")
        return alg if alg in crypto_config.ALLOWED_HASHES else None

    def for_entry(self, sig_alg: str):
        """Same key, the algorithm the entry says it was stamped with (or None)."""
        alg = self.alg_from_name(sig_alg)
        if alg is None:
            return None
        return self if alg == self.alg else HmacSigner(key=self.key, alg=alg)

    def sign(self, message: bytes) -> str:
        return hmac.new(self.key, message, self.alg).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or not isinstance(message, bytes):
            return False
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
        if variant.lower() not in self.VARIANTS:
            raise ValueError(f"Unknown ML-DSA variant {variant!r}")
        self.name = self.VARIANTS[variant.lower()]
        key_dir = key_dir or os.environ.get("PII_MLDSA_KEY_DIR", "keys")
        pub = os.path.join(key_dir, "mldsa_public.key")
        if not os.path.exists(pub):
            raise RuntimeError(f"No ML-DSA public key in {key_dir}. Run: "
                               f"python3 -m src.audit keygen --signer {variant.lower()} --out {key_dir}")
        with open(pub, "rb") as fh:
            self.public_key = fh.read()
        self.secret_key = None
        if not verify_only:
            priv = os.path.join(key_dir, "mldsa_private.key")
            _check_private(priv)
            with open(priv, "rb") as fh:
                self.secret_key = fh.read()
        self.key_id = hashlib.sha256(self.public_key).hexdigest()[:16]

    def for_entry(self, sig_alg: str):
        return self if sig_alg == self.name else None

    @classmethod
    def keygen(cls, variant: str, key_dir: str):
        import oqs
        alg = cls.VARIANTS[variant.lower()]
        with oqs.Signature(alg) as sig:
            public = sig.generate_keypair()
            secret = sig.export_secret_key()
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        priv = os.path.join(key_dir, "mldsa_private.key")
        pub = os.path.join(key_dir, "mldsa_public.key")
        for path in (priv, pub):
            if os.path.exists(path):
                raise FileExistsError(path)
        _write_new(priv, secret, 0o600)   # never briefly world-readable
        _write_new(pub, public, 0o644)
        return alg

    def sign(self, message: bytes) -> str:
        if self.secret_key is None:
            raise RuntimeError("Signer opened in verify-only mode")
        with self._oqs.Signature(self.name, self.secret_key) as sig:
            return sig.sign(message).hex()

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            raw = bytes.fromhex(signature)
        except (TypeError, ValueError):
            return False
        try:
            with self._oqs.Signature(self.name) as sig:
                return bool(sig.verify(message, raw, self.public_key))
        except Exception:  # malformed signature/key inside liboqs -> not valid
            return False


class Ed25519Signer:
    name = "Ed25519"

    def __init__(self, key_dir: str = None, verify_only: bool = False):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:
            raise RuntimeError("Ed25519 needs the `cryptography` package (pip install cryptography)") from exc
        self._ed = ed25519
        key_dir = key_dir or os.environ.get("PII_MLDSA_KEY_DIR", "keys")
        pub = os.path.join(key_dir, "ed25519_public.key")
        if not os.path.exists(pub):
            raise RuntimeError(f"No Ed25519 public key in {key_dir}. Run: "
                               f"python3 -m src.audit keygen --signer dual --out {key_dir}")
        with open(pub, "rb") as fh:
            self.public_key = fh.read()
        self._pub = ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
        self._priv = None
        if not verify_only:
            priv = os.path.join(key_dir, "ed25519_private.key")
            _check_private(priv)
            with open(priv, "rb") as fh:
                self._priv = ed25519.Ed25519PrivateKey.from_private_bytes(fh.read())
        self.key_id = hashlib.sha256(self.public_key).hexdigest()[:16]

    @staticmethod
    def keygen(key_dir: str):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        priv = os.path.join(key_dir, "ed25519_private.key")
        pub = os.path.join(key_dir, "ed25519_public.key")
        for path in (priv, pub):
            if os.path.exists(path):
                raise FileExistsError(path)
        k = ed25519.Ed25519PrivateKey.generate()
        raw = serialization.Encoding.Raw
        _write_new(priv, k.private_bytes(raw, serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption()), 0o600)
        _write_new(pub, k.public_key().public_bytes(raw, serialization.PublicFormat.Raw), 0o644)
        return "Ed25519"

    def for_entry(self, sig_alg: str):
        return self if sig_alg == self.name else None

    def sign(self, message: bytes) -> str:
        if self._priv is None:
            raise RuntimeError("Signer opened in verify-only mode")
        return self._priv.sign(message).hex()

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            self._pub.verify(bytes.fromhex(signature), message)
            return True
        except Exception:  # bad hex, wrong length, invalid signature
            return False


class DualSigner:
    """Classical + post-quantum signature; both must verify (no downgrade to one)."""
    SEP = "."

    def __init__(self, classical, pqc):
        self.classical, self.pqc = classical, pqc
        self.name = f"{classical.name}+{pqc.name}"
        self.key_id = hashlib.sha256(f"{classical.key_id}|{pqc.key_id}".encode()).hexdigest()[:16]

    def for_entry(self, sig_alg: str):
        return self if sig_alg == self.name else None

    def sign(self, message: bytes) -> str:
        return self.classical.sign(message) + self.SEP + self.pqc.sign(message)

    def verify(self, message: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or signature.count(self.SEP) != 1:
            return False
        c, q = signature.split(self.SEP)
        ok_c = self.classical.verify(message, c)
        ok_q = self.pqc.verify(message, q)  # always check both; no short-circuit
        return bool(ok_c and ok_q)


def _dual(verify_only: bool):
    variant = os.environ.get("PII_DUAL_PQC", "ml-dsa-65").lower()
    return DualSigner(Ed25519Signer(verify_only=verify_only),
                      MlDsaSigner(variant, verify_only=verify_only))


def get_signer(name: str = None, verify_only: bool = False):
    name = (name or crypto_config.signer_name()).strip().lower()
    crypto_config.enforce_profile(name)
    if name == "hmac":
        return HmacSigner()
    if name in MlDsaSigner.VARIANTS:
        return MlDsaSigner(name, verify_only=verify_only)
    if name == "dual":
        return _dual(verify_only)
    raise ValueError(f"Unknown signer {name!r}")


def security_report(signer) -> str:
    """One line for startup logs: profile, signer, key id, quantum status."""
    pq = signer.name.startswith("ML-DSA") or "+ML-DSA" in signer.name
    status = "post-quantum" if pq else "WARNING: symmetric HMAC only, not a post-quantum signature"
    return (f"[security] profile={crypto_config.security_profile()} signer={signer.name} "
            f"key_id={signer.key_id} hash={crypto_config.hash_alg()} -> {status}")
