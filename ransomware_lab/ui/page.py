from __future__ import annotations

import streamlit as st

from ransomware_lab.ui.panels import (
    assessment,
    decision_tree,
    evasion,
    header,
    importance,
    processes,
    triage,
)
from ransomware_lab.ui.sidebar import render_language_picker, render_sidebar
from ransomware_lab.ui.state import lab_session, translator
from ransomware_lab.ui.theme import configure_page

TAB_KEYS = ("tabs.detection", "tabs.model", "tabs.incident")


def render_page() -> None:
    configure_page()
    render_language_picker()
    translate = translator()
    session = lab_session()

    render_sidebar(session, translate)
    header.render(session, translate)

    detection_tab, model_tab, incident_tab = st.tabs([translate(key) for key in TAB_KEYS])
    with detection_tab:
        process_column, analysis_column = st.columns([3, 2], gap="large")
        with process_column, st.container(border=True):
            processes.render(session, translate)
        with analysis_column:
            with st.container(border=True):
                assessment.render(session, translate)
            with st.container(border=True):
                evasion.render(session, translate)
    with model_tab:
        with st.container(border=True):
            decision_tree.render(session, translate)
        with st.container(border=True):
            importance.render(session, translate)
    with incident_tab:
        with st.container(border=True):
            triage.render(session, translate)
