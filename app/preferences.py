"""Preferences persistence for the Streamlit UI.

Preferences are stored in st.session_state only — never in files, cookies,
or external storage. They reset on page reload, which is appropriate because
we must not persist document content or user identity.
"""
from __future__ import annotations

import streamlit as st

# ── Default preferences ───────────────────────────────────────────────────────

DEFAULTS: dict = {
    # Visible sections
    "show_overview": True,
    "show_processing": True,
    "show_results": True,
    "show_workspace": True,
    "show_verification": True,
    "show_audit": True,
    "show_diagnostics": False,
    # Result columns
    "show_col_entity_type": True,
    "show_col_position": True,
    "show_col_source": True,
    "show_col_redacted_value": False,   # hide by default — the value is redacted, not raw
    # Filters
    "filter_entity_types": [],          # empty = all types
    # Detector
    "detector": "hybrid",
    # Demo mode
    "use_demo_text": True,
}


def init_prefs() -> None:
    """Initialise session_state with defaults (idempotent)."""
    for key, val in DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = val


def reset_prefs() -> None:
    """Reset all preferences to defaults."""
    for key, val in DEFAULTS.items():
        st.session_state[key] = val


def get(key: str):
    return st.session_state.get(key, DEFAULTS.get(key))


def set_pref(key: str, value) -> None:
    st.session_state[key] = value
