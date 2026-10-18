#!/usr/bin/env bash
# run_all.sh — Reproducible end-to-end workflow for datathon-pii-redaction.
# Run from any directory: the script always operates from the repo root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
step()  { echo -e "\n${CYAN}==> $*${NC}"; }
ok()    { echo -e "${GREEN}    OK: $*${NC}"; }
fail()  { echo -e "${RED}FAIL: $*${NC}" >&2; exit 1; }
warn()  { echo -e "${YELLOW}WARN: $*${NC}" >&2; }

# guard_output FILE
# Refuse to overwrite FILE whether it is git-tracked or merely exists on disk,
# unless the caller explicitly opts in.
#
#   Default (safe):  refuse if FILE exists (tracked or untracked).
#   Opt-in env var:  OVERWRITE_REPORTS=1  — allows overwriting any existing file.
#                    (Legacy alias OVERWRITE_TRACKED_REPORTS=1 also accepted.)
#
# Usage: guard_output reports/metrics_foo.json
guard_output() {
    local f="$1"
    local tracked=0 present=0

    git ls-files --error-unmatch "$f" >/dev/null 2>&1 && tracked=1
    [[ -e "$f" ]] && present=1

    if [[ $present -eq 1 ]]; then
        local reason
        if [[ $tracked -eq 1 ]]; then
            reason="tracked by git"
        else
            reason="untracked but already exists on disk"
        fi
        warn "$f is $reason. Running this step will overwrite it."
        if [[ "${OVERWRITE_REPORTS:-${OVERWRITE_TRACKED_REPORTS:-0}}" != "1" ]]; then
            fail "Refusing to overwrite '$f'. " \
                 "Set OVERWRITE_REPORTS=1 to allow overwriting existing reports, e.g.:" \
                 "    OVERWRITE_REPORTS=1 bash run_all.sh"
        fi
        warn "OVERWRITE_REPORTS=1 is set — proceeding with overwrite of '$f'."
    fi
}

# Keep the old name as an alias so any external callers still work.
guard_tracked_output() { guard_output "$@"; }

# ── Prerequisite checks ───────────────────────────────────────────────────────
step "Checking prerequisites"

command -v python3 >/dev/null 2>&1  || fail "'python3' not found. Install Python 3.10+."
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" \
    || fail "Python 3.10+ required (found $PY_VER)."
ok "python3 $PY_VER"

for mod in numpy; do
    python3 -c "import $mod" 2>/dev/null || fail "Python module '$mod' is not installed."
    ok "import $mod"
done

[[ -f data/processed/pii_validation_exact.jsonl ]] \
    || fail "Validation dataset not found: data/processed/pii_validation_exact.jsonl. It is git-ignored; obtain it separately."

[[ -f data/synthetic/mx_eval.jsonl ]] \
    || fail "MX synthetic dataset not found: data/synthetic/mx_eval.jsonl. Run: bash scripts/make_mx_eval.sh"

[[ -f models/pii_token_clf.npz ]] \
    || fail "Token classifier model not found: models/pii_token_clf.npz. Train it first: python3 -m src.token_classifier --max-docs 30000"

# ── Step 1: Unit tests ────────────────────────────────────────────────────────
step "Step 1 — Unit tests (python3 -m unittest)"
python3 -m unittest discover -s tests -q
ok "All unit tests passed"

# ── Step 2: Validate MX synthetic dataset ────────────────────────────────────
step "Step 2 — Validate MX synthetic dataset (scripts/validate_mx_synthetic.py)"
python3 scripts/validate_mx_synthetic.py data/synthetic/mx_eval.jsonl
ok "MX synthetic dataset is valid"

# ── Step 3: Regex evaluation — Spanish validation set ────────────────────────
step "Step 3 — Regex evaluation on Spanish validation set"
guard_tracked_output reports/metrics_validation.json
python3 -m src.evaluation --detector regex \
    --data data/processed/pii_validation_exact.jsonl \
    --out reports/metrics_validation.json
ok "Saved reports/metrics_validation.json"

# ── Step 4: Hybrid evaluation — Spanish validation set ───────────────────────
step "Step 4 — Hybrid evaluation on Spanish validation set"
guard_tracked_output reports/metrics_validation_hybrid.json
python3 -m src.evaluation --detector hybrid \
    --data data/processed/pii_validation_exact.jsonl \
    --out reports/metrics_validation_hybrid.json
ok "Saved reports/metrics_validation_hybrid.json"

# ── Step 5: Regex evaluation — MX synthetic (separate, no mixing) ────────────
step "Step 5 — Regex evaluation on MX synthetic dataset"
guard_output reports/metrics_mx_synthetic_regex.json
python3 -m src.evaluation --detector regex \
    --data data/synthetic/mx_eval.jsonl \
    --out reports/metrics_mx_synthetic_regex.json
ok "Saved reports/metrics_mx_synthetic_regex.json"

# ── Step 6: Hybrid evaluation — MX synthetic (separate, no mixing) ───────────
step "Step 6 — Hybrid evaluation on MX synthetic dataset"
guard_output reports/metrics_mx_synthetic_hybrid.json
python3 -m src.evaluation --detector hybrid \
    --data data/synthetic/mx_eval.jsonl \
    --out reports/metrics_mx_synthetic_hybrid.json
ok "Saved reports/metrics_mx_synthetic_hybrid.json"

# ── Step 7: Before/after comparison for MX (B5) ──────────────────────────────
step "Step 7 — Before/after MX comparison (scripts/compare_mx.py)"
guard_output reports/metrics_mx.json
python3 scripts/compare_mx.py \
    reports/metrics_mx_before.json \
    reports/metrics_mx_after.json \
    reports/metrics_mx.json
ok "Saved reports/metrics_mx.json"

echo -e "\n${GREEN}run_all.sh completed successfully.${NC}"
