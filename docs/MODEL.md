# Model Card: PII Redaction Prototype

## Overview

This research prototype detects and redacts personally identifiable information (PII) in Spanish text. It combines regular expressions, Mexican-specific heuristics, and a NumPy token classifier, with support for IBM LinuxONE (s390x).

It is not a certified privacy product and cannot guarantee that all personal information will be detected or removed.

## Intended Use

- Educational experimentation with PII detection and redaction.
- Evaluation on synthetic Spanish-language documents.
- Demonstration of redaction before sending text to a language model.

Do not use it as the sole privacy safeguard for production, employment, medical, financial, or other sensitive records. Human review and independent validation are required.

## Detection Method

The hybrid detector in `src/hybrid_detection.py` combines strict EMAIL, CURP, and RFC regular expressions; Mexican-specific rules for selected phone, identifier, name, date, and address formats; a token classifier; and a PHONE fallback.

The classifier in `src/token_classifier.py` uses multinomial logistic regression with softmax probabilities, hashed token features, and mini-batch Adagrad. It is implemented with NumPy.

The runtime threshold is `PII_O_THRESHOLD=0.85` by default. A token is classified as PII when P(not-PII) is below the threshold. A higher threshold generally increases recall but can also increase false positives and over-redaction.

## Data and Licensing

The repository includes AI4Privacy-related Spanish data files named `spanish_openpii_29k.jsonl` and `spanish_openpii_8k.jsonl`, a processed Spanish validation set, and a separate synthetic Mexican evaluation set.

Upstream dataset page: https://huggingface.co/datasets/ai4privacy/pii-masking-300k

The exact upstream revision and applicable dataset license were not recorded alongside the local data files. Verify the upstream dataset card, license, and redistribution terms before reusing or publishing the data. Dataset terms are separate from the software or language-model license.

## Evaluation Results

### Spanish validation set

Reported in `reports/metrics_validation_hybrid.json`:

| Measure | Result |
|---|---:|
| Documents evaluated | 6,987 |
| Document leak rate | 18.68% |
| Documents with at least one annotated PII value left uncovered | 1,305 |
| Character coverage of annotated PII | 98.51% |

Per-type overlap F1 scores: NAME 0.8331; ADDRESS 0.8809; ID_NUMBER 0.9438; DATE_TIME 0.9319; USERNAME 0.8662; EMAIL 0.9759; PHONE 0.8628; PASSWORD 0.7480; IP 0.8166; DEMOGRAPHIC 0.9505.

CURP had no annotated examples in this validation set. RFC predictions cannot establish RFC accuracy when there are no RFC gold examples.

### Synthetic Mexican evaluation set

Historical A7 before/after comparison, saved in `reports/metrics_mx.json`, using 400 generated documents. This is a comparison of the earlier rules-disabled and rules-enabled runs; it is not the current threshold sweep:

| Measure | Historical rules-disabled run | Historical rules-enabled run |
|---|---:|---:|
| Document leak rate | 100.0% | 2.5% |
| Character coverage | 85.06% | 99.79% |

The current detector and threshold-sweep results are reported separately below. All results apply to synthetic data and are not estimates of performance on real Mexican documents. Template-based synthetic data may share patterns with the rules being tested.

## Threshold Trade-off

Current results from `reports/threshold_sweep.json`. The Mexican evaluation uses 400 synthetic documents. The reported micro-precision is an estimate calculated by the sweep script, not an exact aggregate span-precision calculation:

| Threshold | Spanish leak | Spanish approx. micro-precision | Mexican synthetic leak | Mexican approx. micro-precision |
|---:|---:|---:|---:|---:|
| 0.50 | 37.9% | 0.8932 | 7.0% | 0.8063 |
| 0.70 | 26.45% | 0.8696 | 2.0% | 0.7917 |
| 0.85 | 18.68% | 0.8308 | 0.0% | 0.7029 |
| 0.95 | 12.44% | 0.7324 | 0.0% | 0.5954 |

The default threshold trades precision for fewer missed PII spans. Mexican precision at 0.85 is substantially lower than Spanish precision, so the threshold is not universally optimal. A zero leak rate here means no annotated PII was left uncovered in this synthetic evaluation; it does not guarantee safety on real documents.

## Limitations and Safeguards

- The detector can miss PII that is absent from training examples or not covered by its rules.
- Names, addresses, passwords, and IP addresses can produce false positives or false negatives.
- Character coverage and overlap metrics do not guarantee that sensitive information is safe to disclose.
- The LLM gateway redacts detected spans and blocks a prompt when a detected PII string of at least three characters remains in it.
- The gateway guard only checks detected spans. It cannot catch PII that the detector misses.
- The gateway logs backend/model information, detection counts, and an output SHA-256 hash rather than intentionally logging the prompt or raw output.
- Remote backends send prompts to an external service. Review its data-handling terms before using it.

Use synthetic or authorized data during development. Validate false negatives as well as false positives, and do not send real personal data to an external model without appropriate authorization and review.

## Reproducibility

Inspect the current CLI options and dataset paths before running experiments. Typical commands include:

```bash
python3 -m src.token_classifier --max-docs 30000
python3 -m src.evaluation --detector regex
python3 -m src.evaluation --detector ml
python3 -m src.evaluation --detector hybrid
```

Review evaluation scripts before running them because some commands may overwrite reports. Preserve existing data and report files when reproducing experiments.
