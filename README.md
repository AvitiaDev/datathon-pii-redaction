# datathon-pii-redaction
# Datathon PII Redaction Prototype (IBM LinuxONE)

Prototipo de detección y redacción automática de datos de identificación personal (PII) diseñado para entornos z/OS e IBM LinuxONE (s390x).

## Estructura del Repositorio
- `src/`: Módulos de lógica central (`detection.py`).
- `notebooks/`:
  - `00_environment_check.ipynb`: Verificación del entorno de ejecución y soporte s390x.
  - `02_pii_baseline.ipynb`: Baseline de detección e integración con expresiones regulares.

## Requisitos y Configuración
- Python 3.10+
- Pandas, Scikit-Learn

## Ejecución Rápida
1. Iniciar el entorno de Jupyter Lab en el contenedor asignado.
2. Abrir y ejecutar el notebook `notebooks/02_pii_baseline.ipynb` para validar el pipeline de redacción en datos sintéticos.