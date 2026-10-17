# s390x timings (A1) — 2026-10-17

Host: LinuxONE VM, arch s390x, Python 3.12.3

| Step | Wall time | Notes |
|---|---|---|
| Train token classifier (30k docs → 23,144 train / 2,608 dev, 3 epochs) | 1m17s | features 26s, ~17s/epoch, model 11.2 MB |
| Eval regex (6,987 docs) | 1.3s | char coverage 0.270 |
| Eval ml | 8.1s | char coverage 0.978 |
| Eval hybrid | 8.7s | char coverage 0.976 |

Dev binary PII @ threshold 0.7: P 0.940 / R 0.980.
