"""Export evaluation metrics to tidy CSV files for plotting in R.

Only aggregate numbers are written; no PII values.
"""

import csv
import json
from pathlib import Path

OUT = Path("reports/figures_data")
OUT.mkdir(parents=True, exist_ok=True)

REPORTS = {
    "regex": "reports/metrics_validation.json",
    "ml": "reports/metrics_validation_ml.json",
    "hybrid": "reports/metrics_validation_hybrid.json",
}
R = {k: json.load(open(v, encoding="utf-8")) for k, v in REPORTS.items()}


def write(name, header, rows):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"wrote {OUT / name} ({len(rows)} rows)")


write("coverage_by_detector.csv", ["detector", "coverage"],
      [[k, r["char_coverage_all_pii"]] for k, r in R.items()])

rows = []
for det, r in R.items():
    for t, m in r["per_type"].items():
        if m["gold"] == 0 or m["predicted"] == 0:
            continue
        for match in ("exact", "overlap"):
            s = m[match]
            rows.append([det, t, match, s["precision"], s["recall"], s["f1"]])
write("f1_by_type.csv", ["detector", "type", "match", "precision", "recall", "f1"], rows)

write("coverage_by_label.csv", ["detector", "label", "coverage"],
      [[det, l, c] for det in ("regex", "hybrid")
       for l, c in R[det]["coverage_by_gold_label"].items()])

dev = json.load(open("reports/token_clf_dev.json", encoding="utf-8"))
write("dev_by_group.csv", ["group", "metric", "value"],
      [[g, metric, m[metric]] for g, m in dev["per_group"].items()
       for metric in ("precision", "recall", "f1")])

# Token level, dev split, from the full training run (23,144 docs). Figure 03 only;
# the end-to-end sweep (threshold_sweep.csv) is the source for figure 08.
write("threshold_tradeoff.csv", ["threshold", "precision", "recall"],
      [[0.5, 0.953, 0.962], [0.7, 0.940, 0.980],
       [0.85, 0.917, 0.990], [0.95, 0.856, 0.996]])

# A7: leak rate per detector (Spain) + hybrid on the synthetic Mexican set.
mx = json.load(open("reports/metrics_mx.json", encoding="utf-8"))
rows = [[det, "spain", r["leak_rate"], r["char_coverage_all_pii"]] for det, r in R.items()]
rows.append(["hybrid", "mx_synthetic", mx["after"]["leak_rate"], mx["after"]["char_coverage_all_pii"]])
write("leak_by_detector.csv", ["detector", "set", "leak_rate", "coverage"], rows)

# A7: MX per-type results before vs after the A5 Mexican rules.
write("mx_before_after.csv",
      ["type", "gold", "stage", "recall", "leak_rate", "f1"],
      [[t["type"], t["gold"], stage, t[f"recall_{stage}"], t[f"leak_{stage}"], t[f"f1_{stage}"]]
       for t in mx["per_type_overlap"] for stage in ("before", "after")])

# A7: end-to-end hybrid threshold sweep (A6). The token-level table above is kept
# for figure 03; this one drives figure 08.
sweep = json.load(open("reports/threshold_sweep.json", encoding="utf-8"))
write("threshold_sweep.csv",
      ["threshold", "set", "leak_rate", "char_coverage", "micro_precision"],
      [[s["threshold"], s["set"], s["leak_rate"], s["char_coverage"], s["micro_precision"]]
       for s in sweep])
