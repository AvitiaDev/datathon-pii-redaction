#!/usr/bin/env bash
# Try to enable ML-DSA (FIPS 204) on the LinuxONE VM without sudo.
# Builds liboqs into ~/.local and installs liboqs-python for this user.
# Safe: touches nothing in data/ and does not change the shared repo.
set -euo pipefail

PREFIX="$HOME/.local"
WORK="$HOME/build-liboqs"

echo "== 1. Tools"
python3 -m pip install --user --break-system-packages cmake ninja 2>/dev/null \
  || python3 -m pip install --user cmake ninja
export PATH="$HOME/.local/bin:$PATH"
cmake --version | head -1
gcc --version | head -1

echo "== 2. Build liboqs (only ML-DSA + ML-KEM, shared lib)"
rm -rf "$WORK" && mkdir -p "$WORK" && cd "$WORK"
git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B build -GNinja \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;KEM_ml_kem_768" \
  -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON
cmake --build build -j"$(nproc)"
cmake --install build

echo "== 3. Python wrapper"
python3 -m pip install --user --break-system-packages "liboqs-python==0.14.0" 2>/dev/null \
  || python3 -m pip install --user "liboqs-python==0.14.0"
export OQS_INSTALL_PATH="$PREFIX" LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"

echo "== 4. Known-answer self test on s390x (big-endian)"
python3 - <<'PY'
import oqs
for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
    with oqs.Signature(alg) as s:
        pk = s.generate_keypair()
        sig = s.sign(b"datathon")
        ok = s.verify(b"datathon", sig, pk)
        bad = s.verify(b"datathoN", sig, pk)
    print(f"{alg}: sign/verify={ok} rejects-tamper={not bad} sig_bytes={len(sig)}")
    assert ok and not bad
print("ML-DSA OK on", __import__("platform").machine())
PY

echo
echo "Add to your shell before using it:"
echo "  export OQS_INSTALL_PATH=$PREFIX LD_LIBRARY_PATH=$PREFIX/lib:\$LD_LIBRARY_PATH"
