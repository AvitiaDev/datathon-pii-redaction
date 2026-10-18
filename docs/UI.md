# Streamlit UI Reference

This document describes the Streamlit web interface for the PII Redaction
Pipeline. It covers architecture, navigation, components, display preferences,
and known constraints.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Launching the UI](#launching-the-ui)
4. [Navigation Sections](#navigation-sections)
   - [Overview](#overview-section)
   - [Document Processing](#document-processing)
   - [Workspace Settings](#workspace-settings)
   - [Diagnostics](#diagnostics)
5. [Sidebar Controls](#sidebar-controls)
6. [Display Preferences](#display-preferences)
7. [Verification Panel](#verification-panel)
8. [Security Constraints](#security-constraints)
9. [Module Reference](#module-reference)
10. [Known Limitations](#known-limitations)

---

## Overview

The Streamlit interface provides a browser-accessible front-end for the PII
detection and redaction pipeline. It is aimed at prototyping and development;
it is **not** a production deployment. All processing happens in the same
Python process — no external state is written.

Key design decisions:

- **No real PII is required.** A synthetic demo document is bundled.
- **Secrets never appear in the UI.** API keys show as `configured` / `not set`.
- **Raw detected values never appear in the results table** — only type, span
  length, and masked-character placeholders (`████`).
- **Carbon Design System** visual language (IBM Plex Sans/Mono, colour tokens,
  Carbon notification and tag patterns) via injected CSS; no React bundle.
- **Session-only preferences.** All display preferences are held in
  `st.session_state` and reset on page reload.

---

## Architecture

```
browser
  │
  ▼
app/ui.py          ← Streamlit entry point; page config, routing
  │
  ├── app/styles.py       ← Carbon-inspired CSS + helper functions
  │                           pii_tag_html(), verification_tile_html()
  │
  ├── app/preferences.py  ← st.session_state preferences (init / get / set / reset)
  │
  ├── app/pipeline.py     ← Bridge to src/ detection modules
  │                           validate_upload(), run_detection(), get_diagnostics()
  │
  └── app/verification.py ← Local format checks + external provider stubs
                              validate_curp_format(), validate_rfc_format(),
                              validate_ine_format(), run_document_checks(),
                              RENAPOProvider, MetamapIDProvider
```

`app/ui.py` never imports `src/` directly — it goes through `app/pipeline.py`.
This keeps the UI decoupled from model internals and makes unit-testing
straightforward (no Streamlit server needed).

---

## Launching the UI

### Prerequisites

```bash
pip install streamlit pandas    # if not already installed
```

### Start

```bash
# From the repo root
streamlit run app/ui.py

# On a specific port
streamlit run app/ui.py --server.port 8502

# With a specific detector pre-selected (env var, not a flag)
HYBRID_MX_RULES=1 streamlit run app/ui.py
```

Streamlit prints the local URL, typically `http://localhost:8501`.

### Health check

Once started, the process responds to HTTP GET on the server port.  A `200 OK`
from `http://localhost:<port>/` confirms the server is up.

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8501/
# Expected: 200
```

---

## Navigation Sections

### Overview Section

Displays four system-status metrics (detectors available, ML model state,
platform, Python version) and two capability columns — implemented features and
those that require credentials or are outside scope.

Also shows a **synthetic-data warning** banner reminding users not to upload
real identity documents.

### Document Processing

Three input methods (radio selector):

| Method | Description |
|--------|-------------|
| **Paste text** | Free-form text area; runs on any text up to 64 KB |
| **Upload file** | `.txt` or `.md` only, max 64 KB; validated before reading |
| **Use demo document** | Synthetic CV with CURP, RFC, email, phone, address; no real PII |

After input is accepted, the **🔍 Detect & Redact** button runs the selected
detector via `pipeline.run_detection()`.

Results render a summary row (detection count, distinct types, active
detector), a side-by-side original/redacted view, and a filterable detection
table. A **⬇ Download redacted text** button lets the user save the output.

The detection table columns are configurable (see [Display Preferences](#display-preferences)).

### Workspace Settings

Controls which panels and columns are visible. Changes take effect immediately
and are lost on reload. Includes a **↩ Reset all to defaults** button.

### Diagnostics

Shows runtime environment: Python version, platform, available detectors,
model file existence, import errors, and environment variable status.

API key presence is shown as `configured` or `not set` — never the key value.

---

## Sidebar Controls

| Control | Default | Description |
|---------|---------|-------------|
| Navigation radio | Overview | Routes to the four main sections |
| Verification panel checkbox | On | Show/hide verification panel after detection |
| Audit & integrity checkbox | On | Show/hide audit info panel |
| System diagnostics checkbox | Off | Show/hide the diagnostics panel |
| Active detector selectbox | hybrid | Switch between `hybrid`, `regex`, `ml` |
| Reset to defaults button | — | Resets all `st.session_state` preferences |

---

## Display Preferences

Preferences are initialised by `app/preferences.py` with these defaults:

| Key | Default | Description |
|-----|---------|-------------|
| `show_verification` | `True` | Show verification panel |
| `show_audit` | `True` | Show audit & integrity panel |
| `show_diagnostics` | `False` | Show system diagnostics |
| `show_col_entity_type` | `True` | Include entity type column |
| `show_col_position` | `True` | Include start/end offset columns |
| `show_col_source` | `True` | Include source (regex / hybrid / ml) column |
| `show_col_redacted_value` | `False` | Show `████` mask length; **never raw value** |
| `detector` | `hybrid` | Active detector |

---

## Verification Panel

The verification panel appears below the detection table when
`show_verification` is on and at least one verifiable entity was detected.

Verifiable entity types: `CURP`, `RFC`, `ID_NUMBER`.

For each detected verifiable entity (up to 5 per document):

1. An expander shows entity type and span character count (not the raw value).
2. `run_document_checks()` is called with the raw span text.
3. Each check result renders as a **verification tile** (colour-coded by status):
   - 🟢 `verified` — only reachable via live external API with credentials
   - 🔴 `not_verified` — local check found a structural error
   - 🟡 `inconclusive` — local format checks passed; no registry lookup
   - ⬜ `unavailable` — provider not configured
   - 🔴 `error` — unexpected failure (connection error, timeout, malformed response)

4. A caption lists the checks performed.

> **Important:** Without `RENAPO_API_KEY`/`TRUORA_API_KEY` configured,
> all external checks return `unavailable`. Only local format checks run.
> Local checks confirm document *structure* only — they do not confirm the
> document is genuine, belongs to a real person, or matches any registry.

---

## Security Constraints

The UI enforces several security properties:

| Property | Implementation |
|----------|---------------|
| Raw PII never in detection metadata | `PIIRedactor` omits the `text` field from detection dicts |
| Secrets never in UI | `get_diagnostics()` shows `"configured"` or `"not set"` only |
| External API not called without credentials | `RENAPOProvider` and `MetamapIDProvider` check `_is_configured()` before any network I/O |
| API errors do not echo input value | Exception messages use `type(exc).__name__`, never the CURP/RFC value |
| File uploads validated before reading | `validate_upload()` checks extension and size before `read_upload()` |
| Session state only | No preferences or document content written to disk by the UI |

---

## Module Reference

### `app/ui.py`

Entry point. Calls `st.set_page_config()` (must be first Streamlit call), then
routes to one of four section functions based on the sidebar navigation radio.

Key functions:

- `_section_overview()` — metrics + capability matrix
- `_section_processing()` — upload / paste / demo → detect & redact
- `_render_result(result, source_text)` — detection summary, tables, verification
- `_render_verification_panel(detections, source_text)` — per-entity check tiles
- `_section_workspace()` — preference controls
- `_section_diagnostics()` — runtime environment display

### `app/pipeline.py`

Bridge between the UI and `src/` modules. Handles import errors gracefully so
the UI starts even if optional dependencies (ML model, Granite backend) are
missing.

- `DEMO_TEXT` — synthetic CV with structurally valid but non-real identifiers
- `validate_upload(file)` → `(bool, str)` — extension and size check
- `read_upload(file)` → `str` — UTF-8 with latin-1 fallback
- `run_detection(text, detector_name)` → result dict with no raw PII
- `get_diagnostics()` → safe diagnostics dict

### `app/styles.py`

Carbon Design System CSS (injected via `st.markdown(..., unsafe_allow_html=True)`)
plus two HTML-generation helpers:

- `pii_tag_html(entity_type)` → inline Carbon tag span
- `verification_tile_html(check_name, result)` → coloured verification result div

### `app/preferences.py`

Session-state preference management.

- `init_prefs()` — populate defaults (idempotent)
- `reset_prefs()` — restore all defaults
- `get(key)` → current value
- `set_pref(key, value)` — update a preference

### `app/verification.py`

See [`docs/SYSTEM_VERIFICATION.md`](SYSTEM_VERIFICATION.md) for full details.

---

## Known Limitations

| Limitation | Impact |
|-----------|--------|
| PDF, image, binary files not supported | Upload restricted to `.txt` and `.md` |
| Max upload 64 KB | Large documents must be split before upload |
| ML detector requires `models/pii_token_clf.npz` | Train with `python3 -m src.token_classifier --max-docs 30000`; falls back gracefully |
| Audit log not written by UI | Use `python3 -m src.audit demo` or the CLI pipeline for persistent audit |
| Preferences reset on reload | No cookie/database persistence is intentional |
| CURP century heuristic | See [`docs/SYSTEM_VERIFICATION.md`](SYSTEM_VERIFICATION.md#two-digit-year-century-heuristic) |
| External verification not tested live | RENAPO requires institutional agreement; Truora requires paid API key |
| Biometric / face-match not implemented | No document image capture or liveness detection |
| **Browser UI: NOT MANUALLY TESTED** | Streamlit health-check (HTTP 200) confirms the server process responds, but no human has navigated the browser interface, interacted with file upload, or run the detection flow end-to-end in a browser. All UI logic coverage is via headless unit tests of the underlying Python modules only. |
| Truora API schema unverified | `check_type`, `national_id_type` fields and `not_found` response status could not be verified against current Truora docs; the stub sends a best-guess payload. See [`docs/SYSTEM_VERIFICATION.md`](SYSTEM_VERIFICATION.md#metamapidprovider-truora-stub). |
