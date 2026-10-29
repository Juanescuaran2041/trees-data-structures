from __future__ import annotations

from collections.abc import Mapping

import streamlit as st

from ransomware_lab.decision_tree import (
    GiniImpurity,
    GrowthLimits,
    ImpurityCriterion,
    RuleOutcome,
    ShannonEntropyImpurity,
)
from ransomware_lab.detector import ThreatAssessment
from ransomware_lab.diagrams import decision_tree_dot, process_tree_dot
from ransomware_lab.evaluation import StratifiedFoldSplitter
from ransomware_lab.i18n import ENGLISH, LANGUAGE_NAMES, Translator, supported_languages
from ransomware_lab.process_tree import MonitoredProcess
from ransomware_lab.profiles import PROFILE_CATALOG
from ransomware_lab.session import LabSession
from ransomware_lab.sources import CsvTelemetrySource, SyntheticTelemetrySource
from ransomware_lab.telemetry import BehaviorFeature, ProcessClass, TelemetryFormatError

CRITERIA: Mapping[str, ImpurityCriterion] = {
    "gini": GiniImpurity(),
    "entropy": ShannonEntropyImpurity(),
}
CROSS_VALIDATION_FOLDS = 5
TRIAGE_PREVIEW = 6


def main() -> None:
    st.set_page_config(page_title="Ransomware Behavior Lab", page_icon="🛡️", layout="wide")
    translate = Translator(_language())
    session = _session()

    st.title(translate("app.title"))
    st.caption(translate("app.tagline"))
    st.warning(translate("app.disclaimer"), icon="⚠️")

    _render_sidebar(session, translate)
    _render_metrics(session, translate)

    left, right = st.columns([3, 2], gap="large")
    with left:
        _render_process_tree(session, translate)
    with right:
        _render_assessment(session, translate)
        _render_evasion_lab(session, translate)

    _render_decision_tree(session, translate)
    _render_triage(session, translate)
    _render_importance(session, translate)


def _language() -> str:
    codes = supported_languages()
    current = st.session_state.get("language", ENGLISH)
    with st.sidebar:
        chosen = st.radio(
            Translator(current)("sidebar.language"),
            codes,
            index=codes.index(current),
            format_func=lambda code: LANGUAGE_NAMES[code],
            horizontal=True,
            key="language",
        )
    return chosen


def _session() -> LabSession:
    if "lab" not in st.session_state:
        st.session_state["lab"] = LabSession.bootstrap()
    return st.session_state["lab"]


def _render_sidebar(session: LabSession, translate: Translator) -> None:
    with st.sidebar:
        st.subheader(translate("sidebar.data"))
        use_csv = st.toggle(translate("sidebar.source.csv"), value=False)
        upload = None
        if use_csv:
            st.caption(translate("sidebar.csv.prompt", columns=", ".join(_csv_columns())))
            upload = st.file_uploader("telemetry.csv", type="csv", label_visibility="collapsed")

        st.subheader(translate("sidebar.model"))
        criterion_name = st.selectbox(
            translate("sidebar.criterion"),
            tuple(CRITERIA),
            format_func=str.capitalize,
            key="criterion",
        )
        max_depth = st.slider(
            translate("sidebar.max_depth"),
            2,
            8,
            session.detector.tree.limits.max_depth,
            key="max-depth",
        )
        min_samples_leaf = st.slider(
            translate("sidebar.min_samples_leaf"),
            1,
            40,
            session.detector.tree.limits.min_samples_leaf,
            key="min-samples-leaf",
        )
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

        if st.button(translate("sidebar.retrain"), width="stretch", type="primary", key="retrain"):
            _retrain(session, translate, use_csv, upload, criterion_name, max_depth, min_samples_leaf)
        if st.button(translate("sidebar.reset"), width="stretch", key="reset"):
            st.session_state.pop("lab")
            st.rerun()


def _retrain(
    session: LabSession,
    translate: Translator,
    use_csv: bool,
    upload: object,
    criterion_name: str,
    max_depth: int,
    min_samples_leaf: int,
) -> None:
    limits = GrowthLimits(max_depth=max_depth, min_samples_leaf=min_samples_leaf)
    if not use_csv:
        source = SyntheticTelemetrySource()
    elif upload is None:
        st.error(translate("error.csv_required"))
        return
    else:
        source = CsvTelemetrySource.from_bytes(upload.getvalue(), origin=upload.name)
    try:
        session.retrain(source, CRITERIA[criterion_name], limits)
    except TelemetryFormatError as error:
        st.error(translate("error.csv", detail=str(error)))


def _render_metrics(session: LabSession, translate: Translator) -> None:
    report = session.detector.cross_validate(
        session.dataset, StratifiedFoldSplitter(CROSS_VALIDATION_FOLDS)
    )
    st.subheader(translate("metrics.title"))
    columns = st.columns(4)
    for column, (key, value) in zip(
        columns,
        (
            ("metrics.recall", report.mean_recall),
            ("metrics.precision", report.mean_precision),
            ("metrics.accuracy", report.mean_accuracy),
            ("metrics.worst_recall", report.worst_recall),
        ),
    ):
        column.metric(translate(key), f"{value * 100:.1f}%")
    st.caption(
        translate(
            "metrics.caption",
            folds=CROSS_VALIDATION_FOLDS,
            samples=len(session.dataset),
            source=session.source.description,
        )
    )


def _render_process_tree(session: LabSession, translate: Translator) -> None:
    st.subheader(translate("processes.title"))
    detected = session.detected_pids()
    suspects = session.suspect_pids()
    st.graphviz_chart(
        process_tree_dot(
            session.process_tree,
            translate.diagram_labels(),
            detected,
            suspects,
            session.selected.pid,
        ),
        width="stretch",
    )

    spawn, parent, action = st.columns([2, 2, 1], vertical_alignment="bottom")
    profile_name = spawn.selectbox(translate("processes.spawn"), tuple(PROFILE_CATALOG))
    parent_pid = parent.selectbox(
        translate("processes.parent"),
        tuple(process.pid for process in session.process_tree),
        format_func=lambda pid: _process_caption(session.process_tree.require(pid)),
        index=_pid_index(session, session.selected.pid),
    )
    if action.button("➕", width="stretch", key="spawn"):
        session.spawn(profile_name, parent_pid)
        st.rerun()

    selected_pid = st.selectbox(
        translate("processes.selected"),
        tuple(process.pid for process in session.process_tree),
        format_func=lambda pid: _process_caption(session.process_tree.require(pid)),
        index=_pid_index(session, session.selected.pid),
    )
    if selected_pid != session.selected.pid:
        session.select(selected_pid)
        st.rerun()


def _render_assessment(session: LabSession, translate: Translator) -> None:
    process = session.selected
    assessment = session.assess(process.pid)
    st.subheader(translate("assessment.title"))
    verdict_column, risk_column = st.columns(2)
    verdict_column.metric(
        translate("assessment.verdict"), translate(f"verdict.{assessment.verdict.value}")
    )
    risk_column.metric(translate("assessment.risk"), f"{assessment.risk * 100:.0f}%")
    st.write(f"**{translate('assessment.ground_truth')}:** `{process.ground_truth_profile}`")
    _render_truth_banner(process, assessment, translate)

    st.markdown(f"**{translate('assessment.reasons')}**")
    for outcome in assessment.triggered_rules:
        st.markdown(f"- {_describe(outcome, translate)}")
    st.caption(translate("assessment.leaf_support", samples=assessment.leaf_sample_count))


def _render_truth_banner(
    process: MonitoredProcess, assessment: ThreatAssessment, translate: Translator
) -> None:
    truth = PROFILE_CATALOG[process.ground_truth_profile].process_class
    predicted = assessment.verdict.process_class
    if truth is predicted:
        st.success(translate("assessment.correct"), icon="✅")
    elif truth is ProcessClass.RANSOMWARE:
        st.error(translate("assessment.false_negative"), icon="🚨")
    else:
        st.warning(translate("assessment.false_positive"), icon="⚠️")


def _render_evasion_lab(session: LabSession, translate: Translator) -> None:
    process = session.selected
    with st.expander(translate("evasion.title"), expanded=True):
        st.caption(translate("evasion.caption"))
        for feature, reading in process.behavior.as_mapping().items():
            if feature is BehaviorFeature.SHADOW_COPY_DELETION:
                value = float(
                    st.toggle(
                        translate.feature(feature),
                        value=reading >= 0.5,
                        key=f"reading-{process.pid}-{feature.column}",
                    )
                )
            else:
                value = st.slider(
                    translate.feature(feature),
                    feature.lower_bound,
                    feature.upper_bound,
                    float(reading),
                    feature.ui_step,
                    key=f"reading-{process.pid}-{feature.column}",
                )
            if value != reading:
                session.tamper(process.pid, feature, value)
                st.rerun()


def _render_decision_tree(session: LabSession, translate: Translator) -> None:
    tree = session.detector.tree
    st.subheader(translate("tree.title"))
    st.graphviz_chart(
        decision_tree_dot(
            tree,
            translate.diagram_labels(),
            session.detector.assess(session.selected.behavior).path.visited,
        ),
        width="stretch",
    )
    st.caption(
        translate(
            "tree.caption", height=tree.height, leaves=tree.leaf_count, nodes=tree.node_count
        )
    )


def _render_triage(session: LabSession, translate: Translator) -> None:
    st.subheader(translate("triage.title"))
    tickets = session.triage_queue().most_critical(TRIAGE_PREVIEW)
    if not tickets:
        st.info(translate("triage.empty"))
        return
    st.dataframe(
        [
            {
                translate("triage.pid"): ticket.pid,
                translate("triage.image"): ticket.image_name,
                translate("triage.risk"): f"{ticket.risk * 100:.0f}%",
                translate("triage.depth"): ticket.lineage_depth,
            }
            for ticket in tickets
        ],
        hide_index=True,
        width="stretch",
    )
    st.caption(translate("triage.caption"))


def _render_importance(session: LabSession, translate: Translator) -> None:
    st.subheader(translate("importance.title"))
    importance = session.detector.feature_importance()
    for feature, share in sorted(importance.items(), key=lambda item: item[1], reverse=True):
        st.write(f"{translate.feature(feature)} — {share * 100:.1f}%")
        st.progress(min(share, 1.0))
    st.caption(translate("importance.caption"))


def _describe(outcome: RuleOutcome, translate: Translator) -> str:
    comparison = "<=" if outcome.satisfied else ">"
    return (
        f"`{translate.feature(outcome.rule.feature)}` = **{outcome.observed:.2f}** "
        f"{comparison} {outcome.rule.threshold:.2f}"
    )


def _process_caption(process: MonitoredProcess) -> str:
    return f"{process.image_name} ({process.pid})"


def _pid_index(session: LabSession, pid: int) -> int:
    return tuple(process.pid for process in session.process_tree).index(pid)


def _csv_columns() -> tuple[str, ...]:
    return (*BehaviorFeature.columns(), "label")


if __name__ == "__main__":
    main()
