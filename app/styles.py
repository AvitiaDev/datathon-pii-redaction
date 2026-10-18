"""Carbon Design System–inspired CSS injected as a Streamlit style block.

We use Carbon's visual language (spacing, colour tokens, typography) as a
reference but stay within plain Streamlit: no React bundle required.

IBM Plex Sans is loaded from Google Fonts only if the browser can reach it;
if not, the system sans-serif stack is used — the layout is unchanged.
"""

CARBON_CSS = """
<style>
/* ── Typography ──────────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', 'Helvetica Neue', Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    color: #161616;       /* Carbon $text-primary */
}

/* ── Carbon colour tokens ────────────────────────────────────────────── */
:root {
    --c-bg:           #f4f4f4;   /* $layer-01 */
    --c-surface:      #ffffff;
    --c-border:       #e0e0e0;   /* $border-subtle-01 */
    --c-interactive:  #0f62fe;   /* $interactive */
    --c-hover:        #0353e9;
    --c-text-primary: #161616;
    --c-text-helper:  #525252;   /* $text-helper */
    --c-success:      #198038;   /* $support-success */
    --c-warning:      #f1c21b;   /* $support-warning */
    --c-error:        #da1e28;   /* $support-error */
    --c-info:         #0043ce;
    --c-tag-blue:     #ddeeff;
    --c-tag-green:    #defbe6;
    --c-tag-red:      #fff1f1;
    --c-tag-yellow:   #fdf6dd;
    --c-tag-gray:     #e8e8e8;
}

/* ── App background ──────────────────────────────────────────────────── */
.stApp { background-color: var(--c-bg); }

/* ── Sidebar ─────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background-color: #262626;   /* Carbon $background-inverse */
    color: #f4f4f4;
}
section[data-testid="stSidebar"] * { color: #f4f4f4 !important; }
section[data-testid="stSidebar"] .stSelectbox label,
section[data-testid="stSidebar"] .stCheckbox label { color: #c6c6c6 !important; }

/* ── Headings ────────────────────────────────────────────────────────── */
h1 { font-size: 1.75rem; font-weight: 600; color: var(--c-text-primary); margin-bottom: 0.25rem; }
h2 { font-size: 1.25rem; font-weight: 600; color: var(--c-text-primary); }
h3 { font-size: 1rem;    font-weight: 600; color: var(--c-text-primary); }

/* ── Carbon Tag / Badge ──────────────────────────────────────────────── */
.c-tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 2px;
    font-size: 0.75rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    line-height: 1.6;
    margin: 2px 3px 2px 0;
    font-family: 'IBM Plex Sans', sans-serif;
}
.c-tag-blue   { background: #d0e2ff; color: #0043ce; }
.c-tag-green  { background: #defbe6; color: #0e6027; }
.c-tag-red    { background: #fff1f1; color: #a2191f; }
.c-tag-yellow { background: #fdf6dd; color: #684e00; }
.c-tag-gray   { background: #e8e8e8; color: #393939; }
.c-tag-teal   { background: #d9fbfb; color: #005d5d; }

/* ── Carbon inline notification ─────────────────────────────────────── */
.c-notification {
    border-left: 4px solid;
    padding: 12px 16px;
    margin: 8px 0;
    border-radius: 0 2px 2px 0;
    background: var(--c-surface);
    font-size: 0.875rem;
}
.c-notification-info    { border-color: var(--c-info);    }
.c-notification-success { border-color: var(--c-success); background: #defbe6; }
.c-notification-warning { border-color: #f1c21b;          background: #fdf6dd; }
.c-notification-error   { border-color: var(--c-error);   background: #fff1f1; }

/* ── Verification result tiles ───────────────────────────────────────── */
.vcheck {
    padding: 10px 14px;
    border-radius: 2px;
    margin-bottom: 8px;
    font-size: 0.875rem;
    border-left: 4px solid;
    background: #f4f4f4;
}
.vcheck-verified    { border-color: #198038; background: #defbe6; }
.vcheck-not_verified{ border-color: #da1e28; background: #fff1f1; }
.vcheck-inconclusive{ border-color: #f1c21b; background: #fdf6dd; }
.vcheck-unavailable { border-color: #8d8d8d; background: #f4f4f4; }
.vcheck-error       { border-color: #da1e28; background: #fff1f1; }

/* ── Code / mono ─────────────────────────────────────────────────────── */
code, pre {
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
    font-size: 0.8125rem;
}

/* ── Button ──────────────────────────────────────────────────────────── */
.stButton > button {
    background-color: var(--c-interactive);
    color: #ffffff;
    border: none;
    border-radius: 0;
    padding: 11px 24px;
    font-size: 0.875rem;
    font-weight: 500;
    font-family: 'IBM Plex Sans', sans-serif;
    transition: background 0.1s ease;
}
.stButton > button:hover { background-color: var(--c-hover); }
.stButton > button:active { background-color: #002d9c; }

/* ── Text inputs / textareas ─────────────────────────────────────────── */
.stTextArea textarea, .stTextInput input {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.875rem;
    border-radius: 0;
    border: 1px solid var(--c-border);
    border-bottom: 2px solid #8d8d8d;
    background: var(--c-surface);
    transition: border-color 0.1s;
}
.stTextArea textarea:focus, .stTextInput input:focus {
    border-bottom-color: var(--c-interactive);
    outline: none;
}

/* ── Divider ─────────────────────────────────────────────────────────── */
hr { border: none; border-top: 1px solid var(--c-border); margin: 16px 0; }

/* ── Metric tiles ────────────────────────────────────────────────────── */
[data-testid="metric-container"] {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-top: 3px solid var(--c-interactive);
    padding: 12px 16px;
    border-radius: 0;
}

/* ── DataFrames ──────────────────────────────────────────────────────── */
.stDataFrame { border-radius: 0; }

/* ── Expander ────────────────────────────────────────────────────────── */
.streamlit-expander { border-radius: 0; }

/* ── Redacted text highlight ─────────────────────────────────────────── */
.redacted-span {
    background-color: #a8a8a8;
    color: #161616;
    padding: 1px 3px;
    border-radius: 2px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
}
</style>
"""


# ── PII type colour map (Carbon palette) ─────────────────────────────────────
PII_COLOURS = {
    "NAME":        ("blue",   "👤"),
    "EMAIL":       ("teal",   "✉️"),
    "PHONE":       ("teal",   "📞"),
    "CURP":        ("green",  "🪪"),
    "RFC":         ("green",  "🏛️"),
    "ADDRESS":     ("yellow", "📍"),
    "ID_NUMBER":   ("green",  "🔢"),
    "DATE_TIME":   ("gray",   "📅"),
    "USERNAME":    ("blue",   "🔑"),
    "PASSWORD":    ("red",    "🔒"),
    "IP":          ("gray",   "🌐"),
    "DEMOGRAPHIC": ("gray",   "ℹ️"),
    "OTHER_PII":   ("gray",   "⚠️"),
}

DEFAULT_COLOUR = ("gray", "?")


def pii_tag_html(entity_type: str) -> str:
    import html as _html
    colour, icon = PII_COLOURS.get(entity_type, DEFAULT_COLOUR)
    return f'<span class="c-tag c-tag-{colour}">{icon} {_html.escape(entity_type)}</span>'


def verification_tile_html(check_name: str, result: dict) -> str:
    import html as _html
    status = result.get("status", "unavailable")
    # HTML-escape provider-originated strings before embedding in HTML.
    # In the current codebase all summaries are hardcoded literals, but
    # escaping is required for correctness when live API responses are
    # added in the future.
    summary = _html.escape(str(result.get("summary", "—")))
    provider = _html.escape(str(result.get("provider", "—")))
    cls = f"vcheck-{status}"
    icon = {
        "verified": "✅",
        "not_verified": "❌",
        "inconclusive": "⚠️",
        "unavailable": "⬜",
        "error": "🔴",
    }.get(status, "—")
    safe_name = _html.escape(str(check_name))
    return (
        f'<div class="vcheck {cls}">'
        f"<strong>{icon} {safe_name}</strong> "
        f"<span style='color:#525252;font-size:0.8em'>({provider})</span><br>"
        f"<span>{summary}</span>"
        f"</div>"
    )
