"""A6: end-to-end threshold sweep for the hybrid detector (Spain + MX sets).

Writes reports/threshold_sweep.json. Counts only, no PII values.
"""
import json

from src import token_classifier as tc
from src.evaluation import evaluate
from src.hybrid_detection import detect_pii_hybrid

SETS = {"spain": "data/processed/pii_validation_exact.jsonl",
        "mx": "data/synthetic/mx_eval.jsonl"}
THRESHOLDS = [0.5, 0.7, 0.85, 0.95]


def micro_precision(r):
    tp = n = 0
    for t in r["per_type"].values():
        n += t["predicted"]
        tp += round(t["overlap"]["precision"] * t["predicted"])
    return tp / n if n else 0.0


rows = []
print(f"{'thr':>5} {'set':<6} {'leak':>6} {'coverage':>9} {'precision':>9} {'NAME P':>7} {'NAME R':>7}")
for thr in THRESHOLDS:
    tc.load_model()["o_threshold"] = thr
    for name, path in SETS.items():
        r = evaluate(path, detector=detect_pii_hybrid)
        row = {"threshold": thr, "set": name, "leak_rate": r["leak_rate"],
               "char_coverage": r["char_coverage_all_pii"],
               "micro_precision": round(micro_precision(r), 4),
               "name_precision": r["per_type"]["NAME"]["overlap"]["precision"],
               "name_recall": r["per_type"]["NAME"]["overlap"]["recall"]}
        rows.append(row)
        print(f"{thr:>5} {name:<6} {row['leak_rate']:>6.3f} {row['char_coverage']:>9.3f} "
              f"{row['micro_precision']:>9.3f} {row['name_precision']:>7.3f} {row['name_recall']:>7.3f}")
json.dump(rows, open("reports/threshold_sweep.json", "w"), indent=2)
print("Saved: reports/threshold_sweep.json")
