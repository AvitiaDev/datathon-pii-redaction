"""PII Redaction Pipeline — Streamlit interface.

Launch:
    streamlit run app/ui.py [-- --server.port 8501]

Or from the repo root:
    python3 -m streamlit run app/ui.py

Design follows the IBM Carbon Design System visual language.
No real personal data is required; a synthetic demo document is provided.
"""

from __future__ import annotations

import html as _html
import sys
from pathlib import Path

import streamlit as st

# ── Repo root on path ─────────────────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── App modules ───────────────────────────────────────────────────────────────
from app import styles, preferences, pipeline
from app.verification import run_document_checks

# ═══════════════════════════════════════════════════════════════════════════════
# Page config (must be the first Streamlit call)
# ═══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="PII Redaction Pipeline",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.markdown(styles.CARBON_CSS, unsafe_allow_html=True)
preferences.init_prefs()

# ═══════════════════════════════════════════════════════════════════════════════
# Sidebar — navigation and display preferences
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🔒 PII Redaction")
    st.markdown("*IBM LinuxONE · s390x*")
    st.divider()

    st.markdown("### Navigation")
    nav = st.radio(
        "Go to",
        ["Overview", "Document Processing", "Workspace Settings", "Diagnostics"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("### Display")

    show_verification = st.checkbox(
        "Verification panel", value=preferences.get("show_verification"), key="show_verification"
    )
    show_audit = st.checkbox(
        "Audit & integrity", value=preferences.get("show_audit"), key="show_audit"
    )
    show_diagnostics = st.checkbox(
        "System diagnostics", value=preferences.get("show_diagnostics"), key="show_diagnostics"
    )

    st.divider()
    st.markdown("### Detector")
    detector_choice = st.selectbox(
        "Active detector",
        options=["hybrid", "regex", "ml"],
        index=["hybrid", "regex", "ml"].index(preferences.get("detector")),
        key="detector",
        help=(
            "**hybrid** — regex for structured IDs + ML classifier (recommended)\n\n"
            "**regex** — rules only, no model required\n\n"
            "**ml** — token classifier only (requires models/pii_token_clf.npz)"
        ),
    )

    if st.button("Reset to defaults", use_container_width=True):
        preferences.reset_prefs()
        st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _notification(kind: str, message: str, *, safe_html: bool = False) -> None:
    """Render a Carbon notification banner.

    Pass ``safe_html=True`` only for messages built from hardcoded literals.
    All user-derived or exception-derived content must be passed as plain text
    (the default) and will be HTML-escaped before rendering.
    """
    cls = f"c-notification c-notification-{kind}"
    body = message if safe_html else _html.escape(message)
    st.markdown(f'<div class="{cls}">{body}</div>', unsafe_allow_html=True)


def _tag(entity_type: str) -> str:
    return styles.pii_tag_html(entity_type)


def _detection_table(detections: list[dict], text: str) -> None:
    """Render detections as a styled table honouring display preferences."""
    if not detections:
        st.info("No PII detected.")
        return

    import pandas as pd

    rows = []
    for d in detections:
        row = {"Type": d["entity_type"], "Source": d.get("source", "—")}
        if preferences.get("show_col_position"):
            row["Start"] = d["start"]
            row["End"] = d["end"]
        if preferences.get("show_col_redacted_value"):
            # Show redacted span only (already redacted), never raw value
            redacted_char = "█" * (d["end"] - d["start"])
            row["Span (masked)"] = redacted_char[:30]
        rows.append(row)

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Section: Overview
# ═══════════════════════════════════════════════════════════════════════════════

def _section_overview() -> None:
    st.markdown("# PII Redaction Pipeline")
    st.markdown(
        "Automatic detection and redaction of Personally Identifiable Information "
        "in Spanish text, optimised for Mexican identity documents and IBM LinuxONE (s390x)."
    )
    st.divider()

    diag = pipeline.get_diagnostics()
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        avail = len(diag["available_detectors"])
        st.metric("Detectors available", avail, help="regex, ml, hybrid")

    with c2:
        model_ok = diag["model_exists"]
        st.metric("ML model", "✅ loaded" if model_ok else "⚠️ missing",
                  help="models/pii_token_clf.npz")

    with c3:
        st.metric("Platform", diag["platform"])

    with c4:
        st.metric("Python", diag["python_version"])

    st.divider()
    st.markdown("### Capabilities")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**✅ Implemented and tested**")
        st.markdown(
            "- Regex detector for EMAIL, CURP, RFC, PHONE, NAME\n"
            "- Hybrid detector: regex + NumPy token classifier\n"
            "- Mexican document rules: INE, NSS, CURP, RFC, addresses, names, dates\n"
            "- Configurable redaction policies: LABEL, MASK, HASH\n"
            "- Tamper-evident audit log with HMAC-SHA-512 or ML-DSA-65\n"
            "- AES-256-GCM encryption at rest (CPACF on s390x)\n"
            "- PII leak guard before LLM prompt delivery\n"
            "- Local format validation for CURP, RFC, INE"
        )

    with col2:
        st.markdown("**⚠️ Not available / requires credentials**")
        st.markdown(
            "- RENAPO official CURP API (institutional agreement required)\n"
            "- Truora CURP/RFC/INE verification (API key required)\n"
            "- Granite LLM backend (needs Ollama, watsonx.ai, or llama.cpp)\n"
            "- Biometric / face-match verification\n"
            "- PDF, image, or binary file processing\n"
            "- Real-world zero-leak guarantee (all results are best-effort)"
        )

    st.divider()
    _notification("warning",
        "⚠️ <strong>Synthetic data only.</strong> "
        "Do not upload real identity documents. Results from this prototype cannot "
        "guarantee complete PII removal. Human review is required before any sensitive "
        "document is shared or processed further.",
        safe_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Section: Document Processing
# ═══════════════════════════════════════════════════════════════════════════════

def _section_processing() -> None:
    st.markdown("## Document Processing")
    _notification("info",
        "ℹ️ Upload a plain-text file (.txt or .md, max 64 KB) or paste text directly. "
        "Use synthetic data during development — never upload real identity documents."
    )

    # ── Input method ───────────────────────────────────────────────────────────
    input_method = st.radio(
        "Input method",
        ["Paste text", "Upload file", "Use demo document"],
        horizontal=True,
    )

    source_text: str = ""
    input_ok = False

    if input_method == "Use demo document":
        source_text = pipeline.DEMO_TEXT
        input_ok = True
        st.caption("Synthetic demonstration document (no real personal data).")

    elif input_method == "Paste text":
        source_text = st.text_area(
            "Document text",
            height=200,
            placeholder="Paste Spanish-language text containing PII here…",
        )
        input_ok = bool(source_text.strip())
        if not input_ok and source_text != "":
            _notification("warning", "⚠️ Text appears to be empty or whitespace only.")

    elif input_method == "Upload file":
        uploaded = st.file_uploader(
            "Upload a plain-text document",
            type=["txt", "md"],
            accept_multiple_files=False,
        )
        if uploaded is not None:
            ok, err = pipeline.validate_upload(uploaded)
            if not ok:
                _notification("error", f"❌ {err}")
            else:
                source_text = pipeline.read_upload(uploaded)
                input_ok = True
                st.caption(f"Loaded: **{uploaded.name}** ({uploaded.size} bytes)")

    if not input_ok:
        return

    # ── Preview ────────────────────────────────────────────────────────────────
    with st.expander("Preview input", expanded=False):
        st.text(source_text[:2000] + ("…" if len(source_text) > 2000 else ""))

    # ── Run detection ──────────────────────────────────────────────────────────
    detector_name = preferences.get("detector")
    run_btn = st.button("🔍 Detect & Redact", type="primary", use_container_width=False)

    if run_btn or "last_result" in st.session_state:
        if run_btn:
            with st.spinner("Running detection…"):
                result = pipeline.run_detection(source_text, detector_name)
            st.session_state["last_result"] = result
            st.session_state["last_text"] = source_text
        else:
            result = st.session_state["last_result"]
            source_text = st.session_state.get("last_text", source_text)

        _render_result(result, source_text)


def _render_result(result: dict, source_text: str) -> None:
    if not result["ok"]:
        _notification("error", f"❌ Processing failed: {result['error']}")
        return

    detections = result["detections"]
    redacted = result["redacted_text"]
    count = result["detection_count"]

    st.divider()

    # ── Summary row ────────────────────────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    c1.metric("PII spans detected", count)
    entity_types = sorted({d["entity_type"] for d in detections})
    c2.metric("Distinct PII types", len(entity_types))
    c3.metric("Detector", preferences.get("detector"))

    if entity_types:
        st.markdown("**Detected types:** " +
                    " ".join(_tag(et) for et in entity_types),
                    unsafe_allow_html=True)

    # ── Side-by-side original vs redacted ─────────────────────────────────────
    st.divider()
    col_orig, col_red = st.columns(2)

    with col_orig:
        st.markdown("**Original** *(display only — not stored)*")
        st.text_area("original_text_display", source_text,
                     height=250, label_visibility="collapsed", disabled=True)

    with col_red:
        st.markdown("**Redacted output**")
        st.text_area("redacted_text_display", redacted,
                     height=250, label_visibility="collapsed", disabled=True)
        st.download_button(
            "⬇ Download redacted text",
            data=redacted.encode("utf-8"),
            file_name="redacted_document.txt",
            mime="text/plain",
        )

    # ── Detection results table ────────────────────────────────────────────────
    st.divider()
    st.markdown("### Detection Results")

    col_opts = st.columns(4)
    with col_opts[0]:
        st.checkbox("Show positions", key="show_col_position")
    with col_opts[1]:
        st.checkbox("Show source", key="show_col_source")
    with col_opts[2]:
        st.checkbox("Show masked span", key="show_col_redacted_value",
                    help="Shows ████ placeholders, never raw values")

    # Filter by entity type
    all_types = sorted({d["entity_type"] for d in detections})
    selected_types = st.multiselect(
        "Filter by type (empty = all)",
        options=all_types,
        default=[],
        key="filter_entity_types",
    )
    visible = [d for d in detections
               if not selected_types or d["entity_type"] in selected_types]

    _detection_table(visible, source_text)

    # ── Verification panel ─────────────────────────────────────────────────────
    if preferences.get("show_verification") and detections:
        _render_verification_panel(detections, source_text)

    # ── Audit info ─────────────────────────────────────────────────────────────
    if preferences.get("show_audit"):
        _render_audit_info(result)


# ═══════════════════════════════════════════════════════════════════════════════
# Verification panel
# ═══════════════════════════════════════════════════════════════════════════════

_VERIFIABLE_TYPES = {"CURP", "RFC", "ID_NUMBER"}

def _render_verification_panel(detections: list[dict], source_text: str) -> None:
    st.divider()
    st.markdown("### Verification")
    _notification("warning",
        "⚠️ <strong>Verification scope:</strong> "
        "Local checks confirm document structure and format only. "
        "External API checks (when configured) confirm the existence of a record. "
        "Neither check proves document authenticity, identity ownership, or biometric match. "
        "External verification is only triggered when an API key is configured.",
        safe_html=True,
    )

    verifiable = [d for d in detections if d["entity_type"] in _VERIFIABLE_TYPES]
    if not verifiable:
        st.info("No verifiable identifier types (CURP, RFC, ID_NUMBER) were detected.")
        return

    for det in verifiable[:5]:  # limit to 5 to avoid excessive API calls
        etype = det["entity_type"]
        start, end = det["start"], det["end"]
        raw_val = source_text[start:end]

        with st.expander(f"{etype} at position {start}–{end}", expanded=True):
            st.markdown(
                f"**Entity type:** {_tag(etype)}",
                unsafe_allow_html=True,
            )
            # Show character count only, never the raw value in the UI label
            st.caption(f"Span: {end - start} characters")

            checks = run_document_checks(etype, raw_val)

            for check_name, vres in checks.items():
                html = styles.verification_tile_html(check_name, vres.as_dict())
                st.markdown(html, unsafe_allow_html=True)

            # Show checks_performed list
            all_checks = []
            for vr in checks.values():
                all_checks.extend(vr.checks_performed)
            if all_checks:
                st.caption(f"Checks performed: {', '.join(all_checks)}")


# ═══════════════════════════════════════════════════════════════════════════════
# Audit info
# ═══════════════════════════════════════════════════════════════════════════════

def _render_audit_info(result: dict) -> None:
    st.divider()
    st.markdown("### Audit & Integrity")
    _notification("info",
        "ℹ️ The audit log (when enabled) records a keyed HMAC of the input, "
        "a hash of the redacted output, detection counts, and a signature — "
        "never the raw document or PII values. "
        "To enable persistent audit logging, use <code>src.audit</code> or "
        "<code>python3 -m src.audit demo</code>.",
        safe_html=True,
    )
    st.markdown(
        "**In this UI session:** audit log is not written — "
        "only in-memory redaction is performed. "
        "Use the CLI pipeline for audit-logged processing."
    )
    col1, col2 = st.columns(2)
    col1.metric("Detections this run", result.get("detection_count", 0))
    col2.metric("Audit log", "CLI only (not UI)")


# ═══════════════════════════════════════════════════════════════════════════════
# Workspace Settings
# ═══════════════════════════════════════════════════════════════════════════════

def _section_workspace() -> None:
    st.markdown("## Workspace Settings")
    st.markdown(
        "Configure which result columns and UI panels are visible. "
        "These are display-only preferences — they never disable redaction, "
        "detection, audit generation, or security checks."
    )

    st.divider()
    st.markdown("### Visible panels")

    c1, c2 = st.columns(2)
    with c1:
        st.checkbox("Verification panel", key="show_verification")
        st.checkbox("Audit & integrity", key="show_audit")
    with c2:
        st.checkbox("System diagnostics", key="show_diagnostics")

    st.divider()
    st.markdown("### Result columns")

    c1, c2 = st.columns(2)
    with c1:
        st.checkbox("Show entity type", key="show_col_entity_type")
        st.checkbox("Show position offsets", key="show_col_position")
    with c2:
        st.checkbox("Show detection source", key="show_col_source")
        st.checkbox("Show masked span (████)", key="show_col_redacted_value",
                    help="Displays ████ characters — never the raw detected value")

    st.divider()
    st.markdown("### Detector")
    st.selectbox(
        "Active detector",
        options=list(pipeline.DETECTOR_MAP.keys()) or ["regex"],
        key="detector",
    )

    st.divider()
    if st.button("↩ Reset all to defaults"):
        preferences.reset_prefs()
        _notification("success", "✅ Preferences reset to defaults.")
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# Diagnostics
# ═══════════════════════════════════════════════════════════════════════════════

def _section_diagnostics() -> None:
    st.markdown("## System Diagnostics")
    _notification("info",
        "ℹ️ This panel shows dependency availability and environment configuration. "
        "API keys and secrets are shown as 'configured' or 'not set' only — never their values."
    )

    diag = pipeline.get_diagnostics()

    st.markdown("### Runtime")
    c1, c2 = st.columns(2)
    c1.metric("Python", diag["python_version"])
    c2.metric("Platform", diag["platform"])

    st.markdown("### Detectors")
    for name in ["regex", "ml", "hybrid"]:
        avail = name in diag["available_detectors"]
        icon = "✅" if avail else "❌"
        st.markdown(f"{icon} `{name}`")

    if diag["import_errors"]:
        st.markdown("### Import errors")
        for mod, err in diag["import_errors"].items():
            st.code(f"{mod}: {err}", language="text")

    st.markdown("### Model file")
    model_path = diag["model_file"]
    exists = diag["model_exists"]
    if exists:
        st.success(f"✅ {model_path}")
    else:
        st.warning(
            f"⚠️ {model_path} not found. "
            "Train it with: `python3 -m src.token_classifier --max-docs 30000`"
        )

    st.markdown("### Environment")
    for key, val in diag["env"].items():
        icon = "✅" if val not in ("not set", "(not set)") else "⬜"
        st.markdown(f"{icon} `{key}` = `{val}`")

    st.markdown("### Streamlit")
    import streamlit
    st.markdown(f"Streamlit version: `{streamlit.__version__}`")

    if preferences.get("show_diagnostics"):
        pass  # already showing — this section is self-contained

    st.divider()
    _notification("warning",
        "⚠️ This is a prototype. It does not guarantee complete PII removal. "
        "Use only with synthetic or authorized data. "
        "See <code>docs/MODEL.md</code> for evaluation limitations.",
        safe_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Router
# ═══════════════════════════════════════════════════════════════════════════════

if nav == "Overview":
    _section_overview()
elif nav == "Document Processing":
    _section_processing()
elif nav == "Workspace Settings":
    _section_workspace()
elif nav == "Diagnostics":
    _section_diagnostics()
