from __future__ import annotations

import streamlit as st

from ransomware_lab.i18n import ENGLISH, Translator
from ransomware_lab.session import LabSession

LAB_KEY = "lab"
LANGUAGE_KEY = "language"


def lab_session() -> LabSession:
    if LAB_KEY not in st.session_state:
        st.session_state[LAB_KEY] = LabSession.bootstrap()
    return st.session_state[LAB_KEY]


def reset_lab() -> None:
    # Widget state outlives the lab object, so stale pids would survive a reset.
    language = current_language()
    st.session_state.clear()
    st.session_state[LANGUAGE_KEY] = language


def current_language() -> str:
    return st.session_state.get(LANGUAGE_KEY, ENGLISH)


def translator() -> Translator:
    return Translator(current_language())
