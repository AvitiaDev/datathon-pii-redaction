# Security and repository hygiene

## What must never be committed

| Kind | Where it lives | Guard |
|---|---|---|
| HMAC key | `keys/hmac.key` (chmod 600) or `~/.config/pii-vault/hmac.key.enc` | `.gitignore` (`keys/`, `*.key`, `*.enc`), CI check |
| Vault key (AES-256) | `~/.config/pii-vault/vault.key`, outside the repo | `.gitignore` (`.config/`), loader refuses group/other-readable files |
| ML-DSA private key | `keys/mldsa_private.key`, created 0600 atomically | `.gitignore`, CI check, loader refuses group/other-readable files |
| SSH keys, `.pem`, `.env` | your home folder | `.gitignore` |
| Raw AI4Privacy data | `data/raw/`, `data/processed/` | `.gitignore`, CI check |
| Trained model | `models/pii_token_clf.npz` (rebuilt in ~1 min) | `.gitignore`, CI check |
| Audit logs and demo output | `logs/`, `data/demo/` | `.gitignore`, CI check |

CI (`.github/workflows/ci.yml`) fails if any of these paths are tracked.

## Key handling rules (code)

- All keys are created with `os.open(..., O_CREAT | O_EXCL, 0o600)`: never briefly world-readable, never overwritten. To rotate, move the old key away first.
- HMAC, vault and ML-DSA private keys are refused if group or other can read them (`chmod 600` fixes it).
- Error messages never include key material, input text or detected PII.
- External CURP/RFC verification providers (`app/verification.py`) are off unless an API key **and** `ENABLE_UNVERIFIED_EXTERNAL_CHECKS=1` are set. Leave them off: they would send identifiers off the machine.

## Audit log guarantees

See `src/audit.py` docstring. In short: per-entry hash algorithm (no downgrade, no dependency on the current setting), hash chain, per-entry stamp (HMAC-SHA-512 or ML-DSA-65), and a corrupted or tampered log is never appended to. Deleting entries from the end is only detectable against the head hash recorded elsewhere.

## Audit of tracked files (17 Oct 2026, tag v1.0-submission)

- No private keys, tokens, `.pem`, `.env`, models or raw datasets are tracked.
- `data/synthetic/mx_eval.jsonl` is synthetic. Its e-mail addresses use real public domains (gmail, hotmail, outlook, yahoo.com.mx), so a generated address could coincide with a real one. Prefer `example.com` / `example.mx` in the generator in a future change.
- `notebooks/00_environment_check.ipynb` stores about 1 MB of `pip install` logs and VM home paths in its outputs. No secrets, but clear the outputs before publishing (owner's decision).
- Before deleting anything from a shared folder, check tracking with `git ls-files <path>` and `git status --short`; untracked local data is not backed up anywhere.

## Reporting

Found a problem? Open a private issue to the repository owner. Do not paste real personal data into issues or PRs.
