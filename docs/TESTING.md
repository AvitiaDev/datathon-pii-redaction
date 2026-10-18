# Testing

```bash
python3 -m compileall -q src app tests scripts     # syntax
python3 -m unittest discover -s tests              # unit tests (about 1 s)
```

CI runs both on every pull request (`.github/workflows/ci.yml`), on x86-64 Ubuntu with Python 3.12,
in two configurations: **full** (numpy + cryptography) and **no-cryptography** (vault falls back to OpenSSL libcrypto through ctypes).
s390x is verified by running the same commands on the LinuxONE VM.

## Tests that skip unless something extra is present

| Needs | Tests | How to enable |
|---|---|---|
| Trained model `models/pii_token_clf.npz` | 5 in `test_ml_detection.py`, 2 hybrid tests in `test_ui_pipeline.py` | `python3 -m src.token_classifier --max-docs 30000` (needs the local dataset below) |
| Local AI4Privacy dataset in `data/processed/` | model training and `src.evaluation` (not unit tests) | download per `docs/MODEL.md` |
| `cryptography` package | 1 interoperability test in `test_vault.py` | `pip install cryptography` |
| liboqs (real ML-DSA) | none in the unit suite; ML-DSA logic is tested with a fake `oqs` module in `test_signers_keys.py` | `bash scripts/setup_mldsa.sh`, then `python3 -m src.demo` with `PII_SIGNER=ml-dsa-65` |

Expected result: `OK (skipped=7)` in a fresh clone; `OK` with no skips on the VM with the model present.

## What the security tests cover

- `test_audit.py`, `test_audit_hardening.py`: tamper, delete, reorder, wrong key; every allowed hash algorithm; verifying after the setting changes; algorithm rotation inside one log; downgrade to md5 and wrong digest length rejected; missing, empty, garbage, truncated and duplicated logs; refusing to append to a corrupted log; no PII in error messages.
- `test_signers_keys.py`: key files created 0600 and never overwritten; world-readable keys refused; missing keys, unknown variants and signers; malformed signatures return False instead of crashing; ML-DSA audit round trip.
- `test_vault.py`: round trip on both backends; tampered nonce, ciphertext, tag and header; truncated and empty inputs; wrong key; bad key files; plaintext passed as ciphertext.
