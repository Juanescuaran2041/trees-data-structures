from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import streamlit as st

from ransomware_lab.decision_tree import (
    GiniImpurity,
    GrowthLimits,
    ImpurityCriterion,
    ShannonEntropyImpurity,
)
from ransomware_lab.i18n import LANGUAGE_NAMES, Translator, supported_languages
from ransomware_lab.session import LabSession
from ransomware_lab.sources import CsvTelemetrySource, SyntheticTelemetrySource, TelemetrySource
from ransomware_lab.telemetry import BehaviorFeature, TelemetryFormatError
from ransomware_lab.ui.state import LANGUAGE_KEY, current_language, reset_lab

CRITERIA: Mapping[str, ImpurityCriterion] = {
    "gini": GiniImpurity(),
    "entropy": ShannonEntropyImpurity(),
}
CSV_COLUMNS = (*BehaviorFeature.columns(), "label")


@dataclass(frozen=True, slots=True)
class ModelControls:
    criterion_name: str
    max_depth: int
    min_samples_leaf: int
    use_csv: bool
    upload: Any

    @property
    def criterion(self) -> ImpurityCriterion:
        return CRITERIA[self.criterion_name]

    @property
    def limits(self) -> GrowthLimits:
        return GrowthLimits(max_depth=self.max_depth, min_samples_leaf=self.min_samples_leaf)


def render_language_picker() -> None:
    codes = supported_languages()
    with st.sidebar:
        st.radio(
            Translator(current_language())("sidebar.language"),
            codes,
            index=codes.index(current_language()),
            format_func=lambda code: LANGUAGE_NAMES[code],
            horizontal=True,
            key=LANGUAGE_KEY,
        )


def render_sidebar(session: LabSession, translate: Translator) -> None:
    with st.sidebar:
        controls = _render_controls(session, translate)
        _render_threshold(session, translate)
        _render_actions(session, translate, controls)


def _render_controls(session: LabSession, translate: Translator) -> ModelControls:
    st.subheader(translate("sidebar.data"), anchor=False)
    use_csv = st.toggle(translate("sidebar.source.csv"), value=False, key="use-csv")
    upload = None
    if use_csv:
        st.caption(translate("sidebar.csv.prompt", columns=", ".join(CSV_COLUMNS)))
        upload = st.file_uploader(
            "telemetry.csv", type="csv", label_visibility="collapsed", key="csv-upload"
        )

    st.subheader(translate("sidebar.model"), anchor=False)
    limits = session.detector.tree.limits
    return ModelControls(
        criterion_name=st.selectbox(
            translate("sidebar.criterion"),
            tuple(CRITERIA),
            format_func=str.capitalize,
            key="criterion",
        ),
        max_depth=st.slider(translate("sidebar.max_depth"), 2, 8, limits.max_depth, key="max-depth"),
        min_samples_leaf=st.slider(
            translate("sidebar.min_samples_leaf"), 1, 40, limits.min_samples_leaf, key="min-samples-leaf"
        ),
        use_csv=use_csv,
        upload=upload,
    )


def _render_threshold(session: LabSession, translate: Translator) -> None:
    threshold = st.slider(
        translate("sidebar.threshold"),
        0.05,
        1.0,
        session.detector.risk_threshold,
        0.05,
        help=translate("sidebar.threshold.help"),
        key="risk-threshold",
    )
    if threshold != session.detector.risk_threshold:
        session.retune(threshold)


def _render_actions(session: LabSession, translate: Translator, controls: ModelControls) -> None:
    if st.button(translate("sidebar.retrain"), width="stretch", type="primary", key="retrain"):
        _retrain(session, translate, controls)
    if st.button(translate("sidebar.reset"), width="stretch", key="reset"):
        reset_lab()
        st.rerun()


def _retrain(session: LabSession, translate: Translator, controls: ModelControls) -> None:
    source = _resolve_source(translate, controls)
    if source is None:
        return
    try:
        session.retrain(source, controls.criterion, controls.limits)
    except TelemetryFormatError as error:
        st.error(translate("error.csv", detail=str(error)))


def _resolve_source(translate: Translator, controls: ModelControls) -> TelemetrySource | None:
    if not controls.use_csv:
        return SyntheticTelemetrySource()
    if controls.upload is None:
        st.error(translate("error.csv_required"))
        return None
    return CsvTelemetrySource.from_bytes(controls.upload.getvalue(), origin=controls.upload.name)
