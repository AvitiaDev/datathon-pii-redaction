"""Encryption at rest for input documents and secret keys (task T4).

AES-256-GCM (authenticated encryption). Both backends call OpenSSL's libcrypto,
which on IBM Z / LinuxONE (s390x) uses the CPACF on-chip crypto instructions
(KMA/KM, CPU flag `msa`). AES-256 is quantum-resilient: Grover's algorithm only
reduces it to ~128-bit strength (Redbook SG24-8525 Table 1-1).

Backends (picked automatically):
  1. `cryptography` package, if installed
  2. ctypes binding to libcrypto.so.3 (no pip needed)

File format: b"PIIV1" | key_id(8) | nonce(12) | ciphertext | tag(16)
The header is authenticated as associated data, so it cannot be altered either.

Plaintext is only ever returned in memory (`open_document`); this module never
writes decrypted files.

Key: 32 random bytes as hex in PII_VAULT_KEY_FILE
     (default ~/.config/pii-vault/vault.key, chmod 600, outside the repo).

CLI:
  python3 -m src.vault keygen
  python3 -m src.vault encrypt data/demo/cv.txt          # writes cv.txt.enc
  python3 -m src.vault encrypt data/demo/cv.txt --shred  # and deletes the plaintext
  python3 -m src.vault check  data/demo/cv.txt.enc       # decrypts in memory, prints size only
  python3 -m src.vault info                              # backend + key id
"""

import argparse
import ctypes
import ctypes.util
import hashlib
import os
import secrets
import stat
import sys

MAGIC = b"PIIV1"
NONCE_LEN, TAG_LEN, KEY_LEN = 12, 16, 32
DEFAULT_KEY_FILE = os.path.expanduser("~/.config/pii-vault/vault.key")


class VaultError(Exception):
    pass


# ------------------------------------------------------------- backends
class _CryptographyBackend:
    name = "cryptography (OpenSSL libcrypto)"

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._AESGCM = AESGCM

    def seal(self, key, nonce, data, aad):
        return self._AESGCM(key).encrypt(nonce, data, aad)

    def open(self, key, nonce, blob, aad):
        from cryptography.exceptions import InvalidTag
        try:
            return self._AESGCM(key).decrypt(nonce, blob, aad)
        except InvalidTag as exc:
            raise VaultError("authentication failed: wrong key or tampered file") from exc


class _LibcryptoBackend:
    """Minimal EVP AES-256-GCM via ctypes; OpenSSL 3 on s390x routes this to CPACF."""
    name = "ctypes libcrypto (OpenSSL)"
    _SET_IVLEN, _GET_TAG, _SET_TAG = 0x9, 0x10, 0x11

    def __init__(self):
        path = ctypes.util.find_library("crypto") or "libcrypto.so.3"
        L = self.L = ctypes.CDLL(path)
        vp, ip, cp = ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p
        L.EVP_CIPHER_CTX_new.restype = vp
        L.EVP_CIPHER_CTX_free.argtypes = [vp]
        L.EVP_aes_256_gcm.restype = vp
        for fn in ("EVP_EncryptInit_ex", "EVP_DecryptInit_ex"):
            getattr(L, fn).argtypes = [vp, vp, vp, cp, cp]
        for fn in ("EVP_EncryptUpdate", "EVP_DecryptUpdate"):
            getattr(L, fn).argtypes = [vp, vp, ip, cp, ctypes.c_int]
        for fn in ("EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"):
            getattr(L, fn).argtypes = [vp, vp, ip]
        L.EVP_CIPHER_CTX_ctrl.argtypes = [vp, ctypes.c_int, ctypes.c_int, vp]

    def _run(self, encrypt, key, nonce, data, aad, tag=None):
        L, ctx = self.L, self.L.EVP_CIPHER_CTX_new()
        if not ctx:
            raise VaultError("EVP_CIPHER_CTX_new failed")
        init = L.EVP_EncryptInit_ex if encrypt else L.EVP_DecryptInit_ex
        update = L.EVP_EncryptUpdate if encrypt else L.EVP_DecryptUpdate
        final = L.EVP_EncryptFinal_ex if encrypt else L.EVP_DecryptFinal_ex
        try:
            n = ctypes.c_int(0)
            ok = init(ctx, L.EVP_aes_256_gcm(), None, None, None)
            ok &= L.EVP_CIPHER_CTX_ctrl(ctx, self._SET_IVLEN, NONCE_LEN, None)
            ok &= init(ctx, None, None, key, nonce)
            ok &= update(ctx, None, ctypes.byref(n), aad, len(aad))
            out = ctypes.create_string_buffer(len(data) + 16)
            base = ctypes.addressof(out)
            ok &= update(ctx, base, ctypes.byref(n), data, len(data))
            total = n.value
            if not encrypt:
                tbuf = ctypes.create_string_buffer(tag, TAG_LEN)
                ok &= L.EVP_CIPHER_CTX_ctrl(ctx, self._SET_TAG, TAG_LEN, tbuf)
            if not ok:
                raise VaultError("libcrypto setup failed")
            if final(ctx, base + total, ctypes.byref(n)) != 1:
                raise VaultError("authentication failed: wrong key or tampered file")
            total += n.value
            if encrypt:
                tbuf = ctypes.create_string_buffer(TAG_LEN)
                L.EVP_CIPHER_CTX_ctrl(ctx, self._GET_TAG, TAG_LEN, tbuf)
                return out.raw[:total] + tbuf.raw
            return out.raw[:total]
        finally:
            L.EVP_CIPHER_CTX_free(ctx)

    def seal(self, key, nonce, data, aad):
        return self._run(True, key, nonce, data, aad)

    def open(self, key, nonce, blob, aad):
        if len(blob) < TAG_LEN:
            raise VaultError("ciphertext too short")
        return self._run(False, key, nonce, blob[:-TAG_LEN], aad, tag=blob[-TAG_LEN:])


def get_backend(name: str = None):
    name = name or os.environ.get("PII_VAULT_BACKEND", "auto")
    if name in ("auto", "cryptography"):
        try:
            return _CryptographyBackend()
        except ImportError:
            if name == "cryptography":
                raise
    return _LibcryptoBackend()


# ----------------------------------------------------------------- keys
def key_path() -> str:
    return os.environ.get("PII_VAULT_KEY_FILE", DEFAULT_KEY_FILE)


def load_key(path: str = None) -> bytes:
    path = path or key_path()
    if not os.path.exists(path):
        raise VaultError(f"No vault key at {path}. Run: python3 -m src.vault keygen")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise VaultError(f"{path} is readable by others (mode {oct(mode)}); run chmod 600")
    with open(path, encoding="ascii") as fh:
        key = bytes.fromhex(fh.read().strip())
    if len(key) != KEY_LEN:
        raise VaultError("vault key must be 32 bytes (AES-256)")
    return key


def key_id(key: bytes) -> bytes:
    return hashlib.sha256(b"pii-vault-key-id" + key).digest()[:8]


def keygen(path: str = None) -> str:
    path = path or key_path()
    if os.path.exists(path):
        raise VaultError(f"{path} exists; refusing to overwrite")
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(secrets.token_hex(KEY_LEN))
    return path


# ------------------------------------------------------------ public API
def encrypt_bytes(data: bytes, key: bytes = None, backend=None) -> bytes:
    key = key if key is not None else load_key()
    backend = backend or get_backend()
    header = MAGIC + key_id(key)
    nonce = secrets.token_bytes(NONCE_LEN)
    return header + nonce + backend.seal(key, nonce, data, header)


def decrypt_bytes(blob: bytes, key: bytes = None, backend=None) -> bytes:
    key = key if key is not None else load_key()
    backend = backend or get_backend()
    hlen = len(MAGIC) + 8
    if len(blob) < hlen + NONCE_LEN + TAG_LEN or not blob.startswith(MAGIC):
        raise VaultError("not a vault file")
    header, nonce, body = blob[:hlen], blob[hlen:hlen + NONCE_LEN], blob[hlen + NONCE_LEN:]
    if header[len(MAGIC):] != key_id(key):
        raise VaultError("file was encrypted with a different vault key")
    return backend.open(key, nonce, body, header)


def encrypt_file(src: str, dst: str = None, shred: bool = False) -> str:
    dst = dst or src + ".enc"
    with open(src, "rb") as fh:
        blob = encrypt_bytes(fh.read())
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    if shred:
        size = os.path.getsize(src)
        with open(src, "r+b") as fh:
            fh.write(secrets.token_bytes(size))
            fh.flush()
            os.fsync(fh.fileno())
        os.remove(src)
    return dst


def open_document(path: str, encoding: str = "utf-8") -> str:
    """Decrypt a .enc file into memory only. Never writes plaintext to disk."""
    with open(path, "rb") as fh:
        return decrypt_bytes(fh.read()).decode(encoding)


# ------------------------------------------------------------------ CLI
def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m src.vault")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("info")
    e = sub.add_parser("encrypt")
    e.add_argument("path")
    e.add_argument("-o", "--out")
    e.add_argument("--shred", action="store_true", help="overwrite and delete the plaintext")
    c = sub.add_parser("check")
    c.add_argument("path")
    a = p.parse_args(argv)
    try:
        if a.cmd == "keygen":
            print(f"Wrote {keygen()} (chmod 600)")
        elif a.cmd == "info":
            key = load_key()
            print(f"Backend: {get_backend().name}\nAlgorithm: AES-256-GCM\n"
                  f"Key: {key_path()} (id {key_id(key).hex()})")
        elif a.cmd == "encrypt":
            out = encrypt_file(a.path, a.out, a.shred)
            print(f"Encrypted -> {out} ({os.path.getsize(out)} bytes, AES-256-GCM)"
                  + ("; plaintext shredded" if a.shred else ""))
        elif a.cmd == "check":
            text = open_document(a.path)
            print(f"OK: {a.path} decrypts and authenticates ({len(text)} chars, kept in memory)")
    except VaultError as exc:
        print(f"VAULT ERROR: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
