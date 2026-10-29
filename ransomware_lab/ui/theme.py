from __future__ import annotations

import streamlit as st

PAGE_TITLE = "Ransomware Behavior Lab"
PAGE_ICON = "🛡️"

_STYLESHEET = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

  :root {
    --lab-malicious: #d64545;
    --lab-benign: #1f9d55;
    --lab-accent: #f2b63c;
    --lab-muted: #8b93a7;
    --lab-line: rgba(139, 147, 167, 0.18);
  }
  html, body, button, input, select, textarea,
  [data-testid="stAppViewContainer"], [data-testid="stSidebar"] {
    font-family: 'Inter', -apple-system, "Segoe UI", sans-serif;
  }
  .block-container { padding-top: 2.2rem; padding-bottom: 4rem; max-width: 1420px; }

  h1 { font-size: 2.25rem; font-weight: 700; letter-spacing: -0.025em; margin-bottom: 0.1rem; }
  h1::after { content: ""; display: block; width: 72px; height: 3px; margin-top: 0.55rem;
    border-radius: 2px;
    background: linear-gradient(90deg, var(--lab-accent), rgba(242, 182, 60, 0)); }
  h2, h3 { letter-spacing: -0.01em; }
  [data-testid="stHeadingWithActionElements"] h3 { font-size: 1.15rem; font-weight: 600; }

  [data-testid="stMetricValue"] { font-size: 1.75rem; font-weight: 600;
    font-variant-numeric: tabular-nums; }
  [data-testid="stMetricLabel"] p { color: var(--lab-muted); text-transform: uppercase;
    font-size: 0.68rem; font-weight: 600; letter-spacing: 0.09em; }

  [data-testid="stTabs"] button p { font-size: 0.95rem; font-weight: 600; }
  [data-testid="stVerticalBlockBorderWrapper"] { border-radius: 14px; }

  [data-testid="stSidebarUserContent"] h3 { font-size: 0.72rem; text-transform: uppercase;
    letter-spacing: 0.12em; color: var(--lab-muted); margin-bottom: 0.1rem; }
  [data-testid="stSidebarUserContent"] { padding-top: 1.2rem; }

  .lab-badge { display: inline-block; padding: 0.4rem 1rem; border-radius: 999px;
    font-weight: 700; letter-spacing: 0.07em; font-size: 0.92rem; }
  .lab-badge--malicious { background: var(--lab-malicious); color: #fff;
    box-shadow: 0 0 0 4px rgba(214, 69, 69, 0.14); }
  .lab-badge--benign { background: var(--lab-benign); color: #fff;
    box-shadow: 0 0 0 4px rgba(31, 157, 85, 0.14); }

  .lab-risk { font-size: 2.2rem; font-weight: 700; line-height: 1.05;
    font-variant-numeric: tabular-nums; }
  .lab-caption { color: var(--lab-muted); text-transform: uppercase; font-size: 0.66rem;
    font-weight: 600; letter-spacing: 0.1em; }

  .lab-rule { font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    font-size: 0.85rem; padding: 0.38rem 0; border-bottom: 1px solid var(--lab-line);
    display: flex; justify-content: space-between; gap: 1rem; }
  .lab-rule span { color: var(--lab-accent); white-space: nowrap; }

  .lab-note { border-left: 3px solid var(--lab-accent); border-radius: 0 10px 10px 0;
    background: rgba(242, 182, 60, 0.07); padding: 0.75rem 1.1rem; margin: 0.9rem 0 1.4rem 0;
    color: #cfd4e0; font-size: 0.9rem; }

  .lab-meter { height: 6px; border-radius: 3px; background: rgba(139, 147, 167, 0.18);
    margin: 0.2rem 0 0.85rem 0; overflow: hidden; }
  .lab-meter > div { height: 100%; background: var(--lab-accent); border-radius: 3px; }
  .lab-meter--malicious > div { background: var(--lab-malicious); }
  .lab-meter--benign > div { background: var(--lab-benign); }
</style>
"""


def configure_page() -> None:
    st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout="wide")
    st.markdown(_STYLESHEET, unsafe_allow_html=True)
