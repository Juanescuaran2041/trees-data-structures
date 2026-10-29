from __future__ import annotations

import streamlit as st

from ransomware_lab.diagrams import process_tree_dot
from ransomware_lab.i18n import Translator
from ransomware_lab.profiles import PROFILE_CATALOG
from ransomware_lab.session import LabSession
from ransomware_lab.ui.formatting import process_caption


def render(session: LabSession, translate: Translator) -> None:
    st.subheader(translate("processes.title"), anchor=False)
    st.graphviz_chart(
        process_tree_dot(
            session.process_tree,
            translate.diagram_labels(),
            session.detected_pids(),
            session.suspect_pids(),
            session.selected.pid,
        ),
        width="content",
    )
    _render_spawn_controls(session, translate)
    _render_selector(session, translate)


def _render_spawn_controls(session: LabSession, translate: Translator) -> None:
    profile_column, parent_column, action_column = st.columns(
        [2, 2, 1], vertical_alignment="bottom"
    )
    profile_name = profile_column.selectbox(
        translate("processes.spawn"), tuple(PROFILE_CATALOG), key="spawn-profile"
    )
    parent_pid = parent_column.selectbox(
        translate("processes.parent"),
        _pids(session),
        format_func=lambda pid: process_caption(session.process_tree.require(pid)),
        index=_pids(session).index(session.selected.pid),
        key="spawn-parent",
    )
    if action_column.button("➕", width="stretch", key="spawn"):
        # The selector is the single source of truth for the selection, so the new
        # child is written into its state before the rerun re-reads the widget.
        st.session_state["selected-pid"] = session.spawn(profile_name, parent_pid).pid
        st.rerun()


def _render_selector(session: LabSession, translate: Translator) -> None:
    selected_pid = st.selectbox(
        translate("processes.selected"),
        _pids(session),
        format_func=lambda pid: process_caption(session.process_tree.require(pid)),
        index=_pids(session).index(session.selected.pid),
        key="selected-pid",
    )
    if selected_pid != session.selected.pid:
        session.select(selected_pid)
        st.rerun()


def _pids(session: LabSession) -> tuple[int, ...]:
    return tuple(process.pid for process in session.process_tree)
