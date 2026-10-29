from __future__ import annotations

import streamlit as st

from ransomware_lab.detector import ThreatAssessment
from ransomware_lab.i18n import Translator
from ransomware_lab.process_tree import MonitoredProcess
from ransomware_lab.profiles import PROFILE_CATALOG
from ransomware_lab.session import LabSession
from ransomware_lab.telemetry import ProcessClass
from ransomware_lab.ui.formatting import badge, caption, meter, percentage, rule_sentence


def render(session: LabSession, translate: Translator) -> None:
    process = session.selected
    assessment = session.assess(process.pid)
    st.subheader(translate("assessment.title"), anchor=False)

    verdict_column, risk_column = st.columns([3, 2], vertical_alignment="center")
    verdict_column.markdown(
        badge(translate(f"verdict.{assessment.verdict.value}"), assessment.is_malicious),
        unsafe_allow_html=True,
    )
    risk_column.markdown(
        caption(translate("assessment.risk"))
        + f'<div class="lab-risk">{percentage(assessment.risk)}</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        meter(assessment.risk, "malicious" if assessment.is_malicious else "benign"),
        unsafe_allow_html=True,
    )

    st.write(f"**{translate('assessment.ground_truth')}:** `{process.ground_truth_profile}`")
    _render_truth_banner(process, assessment, translate)
    _render_reasons(assessment, translate)


def _render_truth_banner(
    process: MonitoredProcess, assessment: ThreatAssessment, translate: Translator
) -> None:
    truth = PROFILE_CATALOG[process.ground_truth_profile].process_class
    if truth is assessment.verdict.process_class:
        st.success(translate("assessment.correct"), icon="✅")
    elif truth is ProcessClass.RANSOMWARE:
        st.error(translate("assessment.false_negative"), icon="🚨")
    else:
        st.warning(translate("assessment.false_positive"), icon="⚠️")


def _render_reasons(assessment: ThreatAssessment, translate: Translator) -> None:
    st.markdown(caption(translate("assessment.reasons")), unsafe_allow_html=True)
    for outcome in assessment.triggered_rules:
        st.markdown(rule_sentence(outcome, translate), unsafe_allow_html=True)
    st.caption(translate("assessment.leaf_support", samples=assessment.leaf_sample_count))
