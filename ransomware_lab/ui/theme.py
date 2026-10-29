from __future__ import annotations

import streamlit as st

PAGE_TITLE = "Ransomware Behavior Lab"
PAGE_ICON = "🛡️"

_STYLESHEET = """
<style>
  :root {
    --lab-malicious: #d64545;
    --lab-benign: #1f9d55;
    --lab-accent: #f2b63c;
    --lab-muted: #8b93a7;
  }
  .block-container { padding-top: 2.4rem; padding-bottom: 4rem; max-width: 1400px; }
  h1 { letter-spacing: -0.02em; }
  h2, h3 { letter-spacing: -0.01em; }
  [data-testid="stMetricValue"] { font-size: 1.9rem; font-weight: 600; }
  [data-testid="stMetricLabel"] { color: var(--lab-muted); text-transform: uppercase;
    font-size: 0.72rem; letter-spacing: 0.08em; }
  [data-testid="stSidebarUserContent"] h3 { font-size: 0.78rem; text-transform: uppercase;
    letter-spacing: 0.1em; color: var(--lab-muted); margin-bottom: 0.2rem; }
  .lab-badge { display: inline-block; padding: 0.35rem 0.95rem; border-radius: 999px;
    font-weight: 700; letter-spacing: 0.06em; font-size: 0.95rem; }
  .lab-badge--malicious { background: var(--lab-malicious); color: #fff; }
  .lab-badge--benign { background: var(--lab-benign); color: #fff; }
  .lab-risk { font-size: 2.1rem; font-weight: 600; line-height: 1.1; }
  .lab-rule { font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    font-size: 0.86rem; padding: 0.3rem 0; border-bottom: 1px solid rgba(139,147,167,0.18); }
  .lab-rule span { color: var(--lab-accent); }
  .lab-meter { height: 6px; border-radius: 3px; background: rgba(139,147,167,0.2);
    margin: 0.15rem 0 0.75rem 0; overflow: hidden; }
  .lab-meter > div { height: 100%; background: var(--lab-accent); }
</style>
"""


def configure_page() -> None:
    st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout="wide")
    st.markdown(_STYLESHEET, unsafe_allow_html=True)
