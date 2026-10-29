from __future__ import annotations

import streamlit as st

from ransomware_lab.i18n import Translator
from ransomware_lab.session import LabSession
from ransomware_lab.ui.formatting import meter, percentage


def render(session: LabSession, translate: Translator) -> None:
    st.subheader(translate("importance.title"), anchor=False)
    st.caption(translate("importance.caption"))
    ranked = sorted(
        session.detector.feature_importance().items(), key=lambda item: item[1], reverse=True
    )
    for feature, share in ranked:
        st.markdown(
            f'<div class="lab-rule" style="border:none">'
            f"{translate.feature(feature)} <span>{percentage(share, decimals=1)}</span></div>"
            f"{meter(share)}",
            unsafe_allow_html=True,
        )
