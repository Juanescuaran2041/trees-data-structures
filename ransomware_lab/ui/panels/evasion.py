from __future__ import annotations

import streamlit as st

from ransomware_lab.i18n import Translator
from ransomware_lab.process_tree import MonitoredProcess
from ransomware_lab.session import LabSession
from ransomware_lab.telemetry import BehaviorFeature


def render(session: LabSession, translate: Translator) -> None:
    process = session.selected
    st.subheader(translate("evasion.title"), anchor=False)
    st.caption(translate("evasion.caption"))
    for feature, reading in process.behavior.as_mapping().items():
        value = _render_control(process, feature, reading, translate)
        if value != reading:
            session.tamper(process.pid, feature, value)
            st.rerun()


def _render_control(
    process: MonitoredProcess,
    feature: BehaviorFeature,
    reading: float,
    translate: Translator,
) -> float:
    key = f"reading-{process.pid}-{feature.column}"
    if feature is BehaviorFeature.SHADOW_COPY_DELETION:
        return float(st.toggle(translate.feature(feature), value=reading >= 0.5, key=key))
    return st.slider(
        translate.feature(feature),
        feature.lower_bound,
        feature.upper_bound,
        float(reading),
        feature.ui_step,
        key=key,
    )
