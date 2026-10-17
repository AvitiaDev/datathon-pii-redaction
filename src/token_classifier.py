"""Lightweight PII token classifier implemented with NumPy only.

Runs natively on s390x without scikit-learn. Each word token gets 21 hashed
features (word, shape, prefix/suffix, neighbours, line position). A softmax
(multinomial logistic regression) model trained with mini-batch Adagrad
assigns a PII group or "O". Consecutive tokens of the same group are merged
into spans. Never prints or stores raw PII values.
"""

import argparse
import json
import re
import time
import zlib
from functools import lru_cache
from pathlib import Path

import numpy as np

TOKEN_RE = re.compile(r"\w+|[^\w\s]")
N_FEATURES = 2 ** 18
MODEL_PATH = Path("models/pii_token_clf.npz")

CLASSES = ["O", "NAME", "ADDRESS", "ID_NUMBER", "DATE_TIME", "USERNAME",
           "EMAIL", "PHONE", "PASSWORD", "IP", "DEMOGRAPHIC", "OTHER_PII"]
CLASS_INDEX = {c: i for i, c in enumerate(CLASSES)}

LABEL_GROUPS = {
    "GIVENNAME1": "NAME", "GIVENNAME2": "NAME",
    "LASTNAME1": "NAME", "LASTNAME2": "NAME", "LASTNAME3": "NAME",
    "STREET": "ADDRESS", "BUILDING": "ADDRESS", "SECADDRESS": "ADDRESS",
    "CITY": "ADDRESS", "STATE": "ADDRESS", "POSTCODE": "ADDRESS",
    "COUNTRY": "ADDRESS", "GEOCOORD": "ADDRESS",
    "IDCARD": "ID_NUMBER", "PASSPORT": "ID_NUMBER",
    "DRIVERLICENSE": "ID_NUMBER", "SOCIALNUMBER": "ID_NUMBER",
    "DATE": "DATE_TIME", "BOD": "DATE_TIME", "TIME": "DATE_TIME",
    "USERNAME": "USERNAME", "EMAIL": "EMAIL", "TEL": "PHONE",
    "PASS": "PASSWORD", "IP": "IP",
    "SEX": "DEMOGRAPHIC", "TITLE": "DEMOGRAPHIC", "CARDISSUER": "DEMOGRAPHIC",
}

_MODEL = None


@lru_cache(maxsize=1 << 20)
def _h(feature):
    # Deterministic across processes, unlike Python's built-in hash().
    return zlib.crc32(feature.encode("utf-8")) & (N_FEATURES - 1)


def tokenize(text):
    return [(m.group(), m.start(), m.end()) for m in TOKEN_RE.finditer(text)]


def _shape(word):
    s = "".join(
        "X" if c.isupper() else "x" if c.islower() else "d" if c.isdigit() else c
        for c in word
    )
    return re.sub(r"(.)\1+", r"\1", s)


def featurize(tokens, text):
    """Return an int32 array (n_tokens, 21) of hashed feature indices."""
    words = [t[0] for t in tokens]
    lowers = [w.lower() for w in words]
    shapes = [_shape(w) for w in words]
    n = len(tokens)
    rows = []
    for i, (w, s, _e) in enumerate(tokens):
        lw = lowers[i]
        line_start = text.rfind("\n", 0, s) + 1
        f = [
            "bias", "w=" + lw, "p3=" + lw[:3], "s3=" + lw[-3:], "s2=" + lw[-2:],
            "shape=" + shapes[i], "len=" + str(min(len(w), 12)),
            "title=%d" % w.istitle(), "upper=%d" % w.isupper(),
            "digit=%d" % w.isdigit(),
            "hasdigit=%d" % any(c.isdigit() for c in w),
            "linestart=%d" % (text[line_start:s].strip() == ""),
            "bigram=" + (lowers[i - 1] if i else "<s>") + "|" + lw,
        ]
        for k in (-2, -1, 1, 2):
            j = i + k
            if 0 <= j < n:
                f.append(f"w{k}={lowers[j]}")
                f.append(f"shape{k}={shapes[j]}")
            else:
                f.append(f"w{k}=<pad>")
                f.append(f"shape{k}=<pad>")
        rows.append([_h(x) for x in f])
    return np.array(rows, dtype=np.int32).reshape(-1, 21)


def token_labels(text, tokens, spans):
    char = [None] * len(text)
    for m in spans:
        group = LABEL_GROUPS.get(m["label"], "OTHER_PII")
        for c in range(m["start"], m["end"]):
            char[c] = group
    out = []
    for _w, s, e in tokens:
        lab = next((char[c] for c in range(s, e) if char[c]), None) or "O"
        out.append(CLASS_INDEX[lab])
    return out


def load_split(path, want_dev, max_docs=None):
    """Deterministic 90/10 train/dev split of the training file by record id."""
    Xs, ys, docs = [], [], 0
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f):
            rec = json.loads(line)
            rid = str(rec.get("id", line_no)).encode()
            if (zlib.crc32(rid) % 10 == 0) != want_dev:
                continue
            if max_docs and docs >= max_docs:
                break
            text = rec["source_text"]
            toks = tokenize(text)
            if not toks:
                continue
            docs += 1
            Xs.append(featurize(toks, text))
            ys.extend(token_labels(text, toks, rec["privacy_mask"]))
    return np.vstack(Xs), np.array(ys, dtype=np.int64), docs


def predict_proba(W, X, chunk=50000):
    out = []
    for s in range(0, len(X), chunk):
        logits = W[X[s:s + chunk]].sum(axis=1)
        logits -= logits.max(axis=1, keepdims=True)
        p = np.exp(logits)
        p /= p.sum(axis=1, keepdims=True)
        out.append(p)
    return np.vstack(out)


def labels_from_proba(p, o_threshold):
    """Predict a PII class whenever P(O) < o_threshold (higher = more recall)."""
    q = p.copy()
    q[:, 0] = -1.0
    return np.where(p[:, 0] < o_threshold, q.argmax(axis=1), 0)


def train(X, y, epochs=3, batch=2048, lr=0.1, seed=42):
    n, k = X.shape
    c = len(CLASSES)
    W = np.zeros((N_FEATURES, c), dtype=np.float32)
    G = np.zeros((N_FEATURES, c), dtype=np.float32)
    rng = np.random.default_rng(seed)
    for epoch in range(epochs):
        t = time.time()
        order = rng.permutation(n)
        total_loss = 0.0
        for s in range(0, n, batch):
            bi = order[s:s + batch]
            idx, yb = X[bi], y[bi]
            logits = W[idx].sum(axis=1)
            logits -= logits.max(axis=1, keepdims=True)
            p = np.exp(logits)
            p /= p.sum(axis=1, keepdims=True)
            rows = np.arange(len(bi))
            total_loss += -np.log(p[rows, yb] + 1e-12).sum()
            p[rows, yb] -= 1.0  # gradient of the loss w.r.t. logits
            uniq, inv = np.unique(idx.ravel(), return_inverse=True)
            agg = np.zeros((len(uniq), c), dtype=np.float32)
            np.add.at(agg, inv.ravel(), np.repeat(p, k, axis=0))
            G[uniq] += agg * agg
            W[uniq] -= lr * agg / (np.sqrt(G[uniq]) + 1e-8)
        print(f"  epoch {epoch + 1}/{epochs}: loss {total_loss / n:.4f} "
              f"({time.time() - t:.0f}s)")
    return W


def per_class_report(gold, pred):
    rows = {}
    for ci, name in enumerate(CLASSES[1:], start=1):
        tp = int(np.sum((pred == ci) & (gold == ci)))
        pp, gg = int(np.sum(pred == ci)), int(np.sum(gold == ci))
        if gg == 0 and pp == 0:
            continue
        p = tp / pp if pp else 0.0
        r = tp / gg if gg else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        rows[name] = {"precision": round(p, 4), "recall": round(r, 4),
                      "f1": round(f, 4), "support": gg}
    return rows


def load_model(path=MODEL_PATH):
    global _MODEL
    if _MODEL is None:
        d = np.load(path, allow_pickle=False)
        if int(d["n_features"]) != N_FEATURES:
            raise ValueError("Model was trained with a different N_FEATURES")
        from .config import PII_O_THRESHOLD
        # Operating point comes from src/config.py (A6), not from training time.
        _MODEL = {"W": d["W"], "classes": [str(c) for c in d["classes"]],
                  "o_threshold": PII_O_THRESHOLD,
                  "trained_o_threshold": float(d["o_threshold"])}
    return _MODEL


def detect_pii_ml(text, model=None):
    """Return detections in the same format as detect_pii_regex."""
    m = model or load_model()
    toks = tokenize(text)
    if not toks:
        return []
    labels = labels_from_proba(predict_proba(m["W"], featurize(toks, text)),
                               m["o_threshold"])
    spans = []
    for (_w, s, e), li in zip(toks, labels):
        if li == 0:
            continue
        lab = m["classes"][li]
        if spans and spans[-1]["entity_type"] == lab:
            gap = text[spans[-1]["end"]:s]
            if gap == "" or (gap.isspace() and "\n" not in gap):
                spans[-1]["end"] = e
                continue
        spans.append({"entity_type": lab, "start": s, "end": e,
                      "source": "ml_token_classifier"})
    for sp in spans:
        sp["text"] = text[sp["start"]:sp["end"]]
    return spans


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/pii_train_exact.jsonl")
    ap.add_argument("--max-docs", type=int, default=8000)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--o-threshold", type=float, default=0.7)
    ap.add_argument("--out", default=str(MODEL_PATH))
    args = ap.parse_args()

    t0 = time.time()
    Xtr, ytr, ntr = load_split(args.data, want_dev=False, max_docs=args.max_docs)
    Xdv, ydv, ndv = load_split(args.data, want_dev=True, max_docs=args.max_docs // 5)
    print(f"Train: {ntr} docs, {len(ytr)} tokens | Dev: {ndv} docs, {len(ydv)} tokens "
          f"| features built in {time.time() - t0:.0f}s")

    W = train(Xtr, ytr, epochs=args.epochs)

    P = predict_proba(W, Xdv)
    print("\nDev, binary PII vs O (token level):")
    print(" threshold  precision  recall")
    for th in (0.5, 0.7, 0.85, 0.95):
        pred = labels_from_proba(P, th)
        tp = np.sum((pred != 0) & (ydv != 0))
        prec = tp / max(np.sum(pred != 0), 1)
        rec = tp / max(np.sum(ydv != 0), 1)
        print(f"   {th:<8} {prec:9.3f} {rec:7.3f}")

    report = per_class_report(ydv, labels_from_proba(P, args.o_threshold))
    print(f"\nDev per group at threshold {args.o_threshold}:")
    print(f"{'group':<12} {'P':>6} {'R':>6} {'F1':>6} {'support':>8}")
    for g, r in report.items():
        print(f"{g:<12} {r['precision']:6.3f} {r['recall']:6.3f} "
              f"{r['f1']:6.3f} {r['support']:8d}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out, W=W, classes=np.array(CLASSES),
                        n_features=N_FEATURES, o_threshold=args.o_threshold)
    Path("reports").mkdir(exist_ok=True)
    Path("reports/token_clf_dev.json").write_text(
        json.dumps({"train_docs": ntr, "dev_docs": ndv, "epochs": args.epochs,
                    "o_threshold": args.o_threshold, "per_group": report}, indent=2),
        encoding="utf-8")
    print(f"\nSaved model: {out} ({out.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
