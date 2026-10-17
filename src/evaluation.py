"""Evaluate the regex PII detector against AI4Privacy annotations.

Only counts and labels are printed or saved; raw PII values never are.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

from .detection import detect_pii_regex

# Detector type -> dataset labels it is responsible for.
LABEL_MAP = {
    "EMAIL": {"EMAIL"},
    "PHONE": {"TEL"},
    "NAME": {"GIVENNAME1", "GIVENNAME2", "LASTNAME1", "LASTNAME2", "LASTNAME3"},
}


def _overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _prf(tp_pred, n_pred, tp_gold, n_gold):
    p = tp_pred / n_pred if n_pred else 0.0
    r = tp_gold / n_gold if n_gold else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def evaluate(path, limit=None):
    stats = {t: Counter() for t in LABEL_MAP}
    label_total, label_covered = Counter(), Counter()
    gold_chars = covered_chars = docs = 0

    with open(path, encoding="utf-8") as f:
        for line in f:
            if limit and docs >= limit:
                break
            rec = json.loads(line)
            docs += 1
            text = rec["source_text"]
            gold = [(m["start"], m["end"], m["label"]) for m in rec["privacy_mask"]]
            preds = [(d["start"], d["end"], d["entity_type"]) for d in detect_pii_regex(text)]

            # Character-level coverage of all annotated PII (leakage view).
            mask = bytearray(len(text))
            for s, e, _ in preds:
                mask[s:e] = b"\x01" * (e - s)
            for s, e, label in gold:
                label_total[label] += 1
                gold_chars += e - s
                covered_chars += sum(mask[s:e])
                if any(_overlaps((s, e), (ps, pe)) for ps, pe, _ in preds):
                    label_covered[label] += 1

            # Per detector type, against its mapped labels only.
            for t, labels in LABEL_MAP.items():
                g = [(s, e) for s, e, l in gold if l in labels]
                other = [(s, e) for s, e, l in gold if l not in labels]
                p = [(s, e) for s, e, et in preds if et == t]
                gset, pset = set(g), set(p)
                st = stats[t]
                st["gold"] += len(g)
                st["pred"] += len(p)
                st["exact_pred_tp"] += sum(1 for x in p if x in gset)
                st["exact_gold_tp"] += sum(1 for y in g if y in pset)
                st["overlap_pred_tp"] += sum(
                    1 for x in p if any(_overlaps(x, y) for y in g))
                st["overlap_gold_tp"] += sum(
                    1 for y in g if any(_overlaps(x, y) for x in p))
                st["fp_on_other_pii"] += sum(
                    1 for x in p
                    if not any(_overlaps(x, y) for y in g)
                    and any(_overlaps(x, y) for y in other))

    per_type = {}
    for t, st in stats.items():
        per_type[t] = {
            "gold": st["gold"],
            "predicted": st["pred"],
            "exact": _prf(st["exact_pred_tp"], st["pred"], st["exact_gold_tp"], st["gold"]),
            "overlap": _prf(st["overlap_pred_tp"], st["pred"], st["overlap_gold_tp"], st["gold"]),
            "false_positives_on_other_pii": st["fp_on_other_pii"],
        }

    return {
        "dataset": str(path),
        "documents": docs,
        "per_type": per_type,
        "char_coverage_all_pii": round(covered_chars / gold_chars, 4) if gold_chars else 0.0,
        "coverage_by_gold_label": {
            l: round(label_covered[l] / label_total[l], 4)
            for l in sorted(label_total, key=label_total.get, reverse=True)
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/pii_validation_exact.jsonl")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default="reports/metrics_validation.json")
    args = ap.parse_args()

    results = evaluate(Path(args.data), args.limit)

    print(f"Documents: {results['documents']}")
    print(f"{'type':<6} {'gold':>7} {'pred':>7} | exact P/R/F1        | overlap P/R/F1      | FP on other PII")
    for t, r in results["per_type"].items():
        ex, ov = r["exact"], r["overlap"]
        print(f"{t:<6} {r['gold']:>7} {r['predicted']:>7} | "
              f"{ex['precision']:.3f} {ex['recall']:.3f} {ex['f1']:.3f} | "
              f"{ov['precision']:.3f} {ov['recall']:.3f} {ov['f1']:.3f} | "
              f"{r['false_positives_on_other_pii']}")
    print(f"\nCharacter coverage of ALL annotated PII: {results['char_coverage_all_pii']:.3f}")
    print("Coverage by gold label (any overlapping detection):")
    for l, c in results["coverage_by_gold_label"].items():
        print(f"  {l:<14} {c:.3f}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
