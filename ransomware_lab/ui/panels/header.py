from __future__ import annotations

import streamlit as st

from ransomware_lab.i18n import Translator
from ransomware_lab.session import LabSession
from ransomware_lab.ui.formatting import percentage

CROSS_VALIDATION_FOLDS = 5


def render(session: LabSession, translate: Translator) -> None:
    st.title(translate("app.title"), anchor=False)
    st.caption(translate("app.tagline"))
    st.warning(translate("app.disclaimer"), icon="⚠️")
    _render_metrics(session, translate)


def _render_metrics(session: LabSession, translate: Translator) -> None:
    report = session.cross_validation_report(CROSS_VALIDATION_FOLDS)
    readings = (
        ("metrics.recall", report.mean_recall),
        ("metrics.precision", report.mean_precision),
        ("metrics.accuracy", report.mean_accuracy),
        ("metrics.worst_recall", report.worst_recall),
    )
    for column, (key, value) in zip(st.columns(len(readings)), readings):
        column.metric(translate(key), percentage(value, decimals=1))
    st.caption(
        translate(
            "metrics.caption",
            folds=CROSS_VALIDATION_FOLDS,
            samples=len(session.dataset),
            source=session.source.description,
        )
    )
