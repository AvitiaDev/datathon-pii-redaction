"""Combine before/after MX evaluations into reports/metrics_mx.json and print a table."""
import json
import sys

before_p, after_p, out_p = (sys.argv[1:4] if len(sys.argv) > 3 else
    ("reports/metrics_mx_before.json", "reports/metrics_mx_after.json", "reports/metrics_mx.json"))
b, a = json.load(open(before_p)), json.load(open(after_p))

rows = []
print(f"{'type':<10} {'F1 before':>9} {'F1 after':>9} | {'R before':>8} {'R after':>8} | {'leak before':>11} {'leak after':>10}")
for t in a["per_type"]:
    pb, pa = b["per_type"][t], a["per_type"][t]
    if pa["gold"] == 0:
        continue
    lb = b["leak_rate_by_type"].get(t, 0.0)
    la = a["leak_rate_by_type"].get(t, 0.0)
    rows.append({"type": t, "gold": pa["gold"],
                 "f1_before": pb["overlap"]["f1"], "f1_after": pa["overlap"]["f1"],
                 "recall_before": pb["overlap"]["recall"], "recall_after": pa["overlap"]["recall"],
                 "leak_before": lb, "leak_after": la})
    print(f"{t:<10} {pb['overlap']['f1']:>9.3f} {pa['overlap']['f1']:>9.3f} | "
          f"{pb['overlap']['recall']:>8.3f} {pa['overlap']['recall']:>8.3f} | {lb:>11.3f} {la:>10.3f}")
print(f"\nDoc leak rate:  {b['leak_rate']:.3f} -> {a['leak_rate']:.3f}")
print(f"Char coverage:  {b['char_coverage_all_pii']:.3f} -> {a['char_coverage_all_pii']:.3f}")

json.dump({"dataset": a["dataset"], "documents": a["documents"], "detector": "hybrid",
           "leak_rate": {"before": b["leak_rate"], "after": a["leak_rate"]},
           "char_coverage_all_pii": {"before": b["char_coverage_all_pii"], "after": a["char_coverage_all_pii"]},
           "per_type_overlap": rows, "before": b, "after": a},
          open(out_p, "w"), indent=2)
print(f"Saved: {out_p}")
