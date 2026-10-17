"""Validate data/synthetic/mx_eval.jsonl: offsets, check digits, counts.

Prints counts only, never PII values (the data is synthetic anyway).
"""
import json
import re
import sys
from collections import Counter

CURP_D = "0123456789ABCDEFGHIJKLMN#OPQRSTUVWXYZ"
RFC_D = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ"


def curp_ok(c):
    if not re.fullmatch(r"[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d", c):
        return False
    s = sum(CURP_D.index(ch) * (18 - i) for i, ch in enumerate(c[:17]))
    return int(c[17]) == (10 - s % 10) % 10


def rfc_ok(r):
    if not re.fullmatch(r"[A-Z&]{4}\d{6}[A-Z0-9]{2}[0-9A]", r):
        return False
    s = sum(RFC_D.index(ch) * (13 - i) for i, ch in enumerate(r[:12]))
    d = 0 if s % 11 == 0 else 11 - s % 11
    return r[12] == ("A" if d == 10 else str(d))


def nss_ok(n):
    if not re.fullmatch(r"\d{11}", n):
        return False
    s = 0
    for i, ch in enumerate(n[:10]):
        v = int(ch) * (2 if i % 2 else 1)
        s += v // 10 + v % 10
    return int(n[10]) == (10 - s % 10) % 10


CHECKS = {
    "CURP": curp_ok,
    "RFC": rfc_ok,
    "NSS": nss_ok,
    "INE": lambda v: bool(re.fullmatch(r"[A-Z]{6}\d{8}[HM]\d{3}", v)),
    "TEL": lambda v: "656" in v,
    "EMAIL": lambda v: bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z.]+", v)),
}


def main(path="data/synthetic/mx_eval.jsonl"):
    docs, labels, bad = 0, Counter(), Counter()
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        docs += 1
        assert r.get("synthetic") is True
        t = r["source_text"]
        last_end = -1
        for m in sorted(r["privacy_mask"], key=lambda m: m["start"]):
            s, e, lab = m["start"], m["end"], m["label"]
            v = t[s:e]
            labels[lab] += 1
            if not (0 <= s < e <= len(t)) or v != v.strip() or s < last_end:
                bad["offset"] += 1
            last_end = e
            if lab in CHECKS and not CHECKS[lab](v):
                bad[lab] += 1
    print(f"documents: {docs}")
    print("spans by label:", dict(labels.most_common()))
    print("invalid:", dict(bad) or "none")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
