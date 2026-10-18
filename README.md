# Datathon PII Redaction Prototype (IBM LinuxONE)

Prototipo de detección y redacción automática de datos de identificación personal (PII) diseñado para entornos z/OS e IBM LinuxONE (`s390x`), con enfoque en la validación de identificadores y datos sintéticos en español[cite: 1].


**Model card:** [Methodology, evaluation results, limitations, and safeguards](docs/MODEL.md).
---

## 📂 Estructura del Repositorio

- `src/`: Módulos de lógica central y procesamiento.
  - `detection.py`: Detección basada en patrones y expresiones regulares optimizada para la arquitectura `s390x`.
  - `policies.py`: Reglas de enmascaramiento y estrategias de redacción (`LABEL`, `MASK`, `HASH`).
- `notebooks/`:
  - `00_environment_check.ipynb`: Verificación del entorno de ejecución, soporte s390x y librerías instaladas[cite: 1, 10].
  - `01_dataset_exploration.ipynb`: Exploración inicial del conjunto de datos y validación de campos[cite: 9, 10].
  - `02_pii_baseline.ipynb`: Baseline de detección e integración con expresiones regulares[cite: 1, 8].
  - `03_model_evaluation.ipynb`: Evaluación del modelo y métricas de detección frente a datos sintéticos[cite: 7].

---

## ⚙️ Requisitos y Configuración

- **Sistema:** Debian-based en IBM LinuxONE (`s390x`)[cite: 1]
- **Python:** 3.10+ (Entorno configurado en `/home/linux1/shared/datathon-pii-redaction`)[cite: 1, 10]
- **Librerías principales:** Pandas, NumPy, Scikit-Learn[cite: 1, 10]

---

## 🚀 Ejecución Rápida

1. Iniciar el entorno de Jupyter Lab en el contenedor asignado.
2. Abrir y ejecutar los notebooks ubicados en `notebooks/` para validar el pipeline de detección y redacción en datos sintéticos o conjuntos de datos de Hugging Face[cite: 1, 7, 8, 9, 10].
3. También puedes ejecutar directamente el módulo de detección desde la terminal:
   ```bash
   python3 src/detection.py
   ```

4. Para reproducir el flujo completo de evaluación (tests → evaluación española → evaluación MX sintética):
   ```bash
   # Prerequisite: numpy installed, models/pii_token_clf.npz trained, data/processed/ present
   bash run_all.sh
   ```
   See `run_all.sh` for exact prerequisite checks and every command it runs.

## ML token classifier (NumPy only)

The detector combines strict regex rules (EMAIL, CURP, RFC, and a PHONE fallback) with a
token classifier: multinomial logistic regression on hashed features, trained with
mini-batch Adagrad. It uses only NumPy, so it runs natively on s390x (LinuxONE) without
scikit-learn.

Train the model (about 1 minute; writes `models/pii_token_clf.npz`, which is not committed):

    python3 -m src.token_classifier --max-docs 30000

Evaluate on the validation split:

    python3 -m src.evaluation --detector regex|ml|hybrid

| Detector | Character coverage of all annotated PII |
|---|---|
| Regex baseline | 0.270 |
| Hybrid (regex + ML) | 0.978 |

Limitation: training and validation data are synthetic Spanish (Spain) documents.
On Mexican documents, CURP, RFC and email are handled by regex; the model redacts
Mexican names and addresses but sometimes mislabels them.

## Operating point (detection threshold)

The token classifier flags a token as PII whenever P(not-PII) < `PII_O_THRESHOLD`, set in `src/config.py` (default **0.85**, overridable with the `PII_O_THRESHOLD` environment variable).

**Why 0.85:** we favour recall because a missed PII value costs more than an over-redacted word. At 0.85, the document leak rate falls to 18.7% (Spain) and 2.5% (Mexico), while precision is 0.8308 (Spain) and 0.6982 (Mexico). Raising the threshold to 0.95 reduces Spanish leaks further but lowers precision; Mexican leak rate does not improve at that threshold.

| Threshold | Spain leak | Spain precision | MX leak | MX precision |
|---|---|---|---|---|
| 0.5 | 37.9% | 0.893 | 7.2% | 0.800 |
| 0.7 | 26.5% | 0.870 | 3.7% | 0.786 |
| **0.85** | **18.7%** | **0.831** | **2.5%** | **0.698** |
| 0.95 | 12.4% | 0.732 | 3.0% | 0.591 |

End-to-end hybrid detector, from `scripts/threshold_sweep.py` → `reports/threshold_sweep.json`. Token-level view: `reports/figures/03_threshold_tradeoff.png`.
