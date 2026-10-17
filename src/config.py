"""Detector operating point (A6).

PII_O_THRESHOLD: the token classifier predicts a PII class whenever P(O) < threshold.
Higher = more recall, more over-redaction. Chosen to favour recall because a missed
PII value costs more than an over-redacted word (see README, "Operating point").
Override at runtime with the PII_O_THRESHOLD environment variable.
"""
import os

PII_O_THRESHOLD = float(os.environ.get("PII_O_THRESHOLD", "0.85"))
