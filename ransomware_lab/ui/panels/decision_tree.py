from __future__ import annotations

import streamlit as st

from ransomware_lab.diagrams import decision_tree_dot
from ransomware_lab.i18n import Translator
from ransomware_lab.session import LabSession


def render(session: LabSession, translate: Translator) -> None:
    tree = session.detector.tree
    st.subheader(translate("tree.title"), anchor=False)
    st.caption(
        translate("tree.caption", height=tree.height, leaves=tree.leaf_count, nodes=tree.node_count)
    )
    st.graphviz_chart(
        decision_tree_dot(
            tree,
            translate.diagram_labels(),
            session.assess(session.selected.pid).path.visited,
        ),
        width="stretch",
    )
