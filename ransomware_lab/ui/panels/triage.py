from __future__ import annotations

import streamlit as st

from ransomware_lab.i18n import Translator
from ransomware_lab.session import LabSession
from ransomware_lab.ui.formatting import percentage

TRIAGE_PREVIEW = 6


def render(session: LabSession, translate: Translator) -> None:
    st.subheader(translate("triage.title"), anchor=False)
    st.caption(translate("triage.caption"))
    tickets = session.triage_queue().most_critical(TRIAGE_PREVIEW)
    if not tickets:
        st.info(translate("triage.empty"))
        return
    st.dataframe(
        [
            {
                translate("triage.pid"): ticket.pid,
                translate("triage.image"): ticket.image_name,
                translate("triage.risk"): percentage(ticket.risk),
                translate("triage.depth"): ticket.lineage_depth,
            }
            for ticket in tickets
        ],
        hide_index=True,
        width="stretch",
    )
