#!/usr/bin/env bash
# Build the C generator and produce the Mexican synthetic eval set (synthetic data only).
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-400}"; SEED="${2:-42}"
gcc -O2 -Wall -o data/synthetic/generador data/synthetic/generador_sintetico.c
data/synthetic/generador "$N" "$SEED" > data/synthetic/mx_eval.jsonl
python3 scripts/validate_mx_synthetic.py data/synthetic/mx_eval.jsonl
