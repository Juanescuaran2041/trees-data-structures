from __future__ import annotations

from random import Random

import pytest

from ransomware_lab.decision_tree import GrowthLimits, ShannonEntropyImpurity
from ransomware_lab.detector import RansomwareDetector, Verdict
from ransomware_lab.diagrams import decision_tree_dot, process_tree_dot
from ransomware_lab.evaluation import ConfusionMatrix, StratifiedFoldSplitter
from ransomware_lab.i18n import ENGLISH, SPANISH, Translator, phrase_keys, supported_languages
from ransomware_lab.profiles import ARCHIVE_COMPRESSOR, PROFILE_CATALOG
from ransomware_lab.session import LabSession
from ransomware_lab.sources import CsvTelemetrySource, SyntheticTelemetrySource
from ransomware_lab.telemetry import BehaviorFeature, ProcessClass, TelemetryFormatError

VALID_CSV = [
    "files_per_sec,entropy,rename_ratio,shadow_delete,dirs_touched,label",
    "80.5,7.9,0.91,1,92,1",
    "120.0,7.8,0.95,1,140,1",
    "0.7,5.1,0.00,0,3,0",
    "1.2,4.4,0.01,0,5,0",
]


def synthetic_dataset():
    return SyntheticTelemetrySource(seed=31).load()


def test_synthetic_source_is_reproducible_and_balanced():
    first = SyntheticTelemetrySource(seed=5).load()
    second = SyntheticTelemetrySource(seed=5).load()
    assert [observation.behavior for observation in first] == [
        observation.behavior for observation in second
    ]
    counts = first.class_counts()
    assert counts[ProcessClass.BENIGN] > 0
    assert counts[ProcessClass.RANSOMWARE] > 0


def test_csv_source_parses_both_classes():
    dataset = CsvTelemetrySource(VALID_CSV).load()
    assert len(dataset) == 4
    assert dataset.ransomware_ratio() == pytest.approx(0.5)
    assert dataset[0].behavior[BehaviorFeature.PAYLOAD_ENTROPY] == pytest.approx(7.9)


@pytest.mark.parametrize(
    "rows, detail",
    [
        (["files_per_sec,entropy,label", "1,2,0"], "missing CSV columns"),
        ([VALID_CSV[0]], "no data rows"),
        ([VALID_CSV[0], "80.5,7.9,0.91,1,,1"], "is empty"),
        ([VALID_CSV[0], "80.5,fast,0.91,1,92,1"], "not numeric"),
        ([VALID_CSV[0], "80.5,7.9,0.91,1,92,7"], "label must be 0 or 1"),
        ([VALID_CSV[0], VALID_CSV[1]], "no samples for"),
    ],
)
def test_csv_source_reports_bad_input(rows, detail):
    with pytest.raises(TelemetryFormatError, match=detail):
        CsvTelemetrySource(rows).load()


def test_detector_separates_the_synthetic_classes():
    dataset = synthetic_dataset()
    detector = RansomwareDetector.trained_on(dataset)
    matrix = detector.evaluate(dataset)
    assert matrix.recall > 0.9
    assert matrix.precision > 0.9
    assert matrix.total == len(dataset)


def test_cross_validation_generalizes_to_held_out_folds():
    dataset = synthetic_dataset()
    report = RansomwareDetector.trained_on(dataset).cross_validate(
        dataset, StratifiedFoldSplitter(folds=5, seed=3)
    )
    assert len(report.folds) == 5
    assert report.pooled.total == len(dataset)
    assert report.mean_recall > 0.85
    assert report.worst_recall > 0.75


def test_lowering_the_threshold_never_lowers_recall():
    dataset = synthetic_dataset()
    strict = RansomwareDetector.trained_on(dataset, risk_threshold=0.9)
    lenient = strict.with_threshold(0.1)
    assert lenient.evaluate(dataset).recall >= strict.evaluate(dataset).recall
    assert lenient.tree is strict.tree


def test_threshold_outside_the_unit_interval_is_rejected():
    dataset = synthetic_dataset()
    with pytest.raises(ValueError):
        RansomwareDetector.trained_on(dataset, risk_threshold=0.0)


def test_feature_importance_is_a_distribution_over_used_features():
    detector = RansomwareDetector.trained_on(synthetic_dataset())
    importance = detector.feature_importance()
    assert set(importance) == set(BehaviorFeature)
    assert sum(importance.values()) == pytest.approx(1.0)
    assert all(share >= 0.0 for share in importance.values())


def test_entropy_criterion_and_tight_limits_still_produce_a_usable_tree():
    dataset = synthetic_dataset()
    detector = RansomwareDetector.trained_on(
        dataset, ShannonEntropyImpurity(), GrowthLimits(max_depth=3, min_samples_leaf=20)
    )
    assert detector.tree.height <= 4
    assert detector.evaluate(dataset).recall > 0.8


def test_confusion_matrix_ratios_and_addition():
    matrix = ConfusionMatrix.of(
        [
            (ProcessClass.RANSOMWARE, ProcessClass.RANSOMWARE),
            (ProcessClass.RANSOMWARE, ProcessClass.BENIGN),
            (ProcessClass.BENIGN, ProcessClass.BENIGN),
            (ProcessClass.BENIGN, ProcessClass.RANSOMWARE),
        ]
    )
    assert (matrix.true_positives, matrix.false_negatives) == (1, 1)
    assert matrix.recall == pytest.approx(0.5)
    assert matrix.precision == pytest.approx(0.5)
    assert matrix.f1_score == pytest.approx(0.5)
    assert (matrix + matrix).total == 8
    assert ConfusionMatrix().accuracy == 0.0


def test_fold_splitter_partitions_the_dataset_without_overlap():
    dataset = synthetic_dataset()
    splitter = StratifiedFoldSplitter(folds=4, seed=11)
    holdout_sizes = []
    for training, holdout in splitter.split(dataset):
        assert len(training) + len(holdout) == len(dataset)
        holdout_sizes.append(len(holdout))
    assert sum(holdout_sizes) == len(dataset)
    assert max(holdout_sizes) - min(holdout_sizes) <= 2


def test_session_flags_a_locker_and_marks_its_parent_as_a_suspect():
    session = LabSession.bootstrap()
    locker = session.spawn("fast-locker", session.process_tree.root.pid)
    assert session.assess(locker.pid).verdict is Verdict.RANSOMWARE
    assert locker.pid in session.detected_pids()
    assert session.process_tree.root.pid in session.suspect_pids()


def test_the_archiver_profile_is_mostly_cleared_despite_its_high_entropy():
    detector = RansomwareDetector.trained_on(synthetic_dataset())
    entropy_source = Random(77)
    cleared = sum(
        not detector.assess(ARCHIVE_COMPRESSOR.sample_behavior(entropy_source)).is_malicious
        for _ in range(100)
    )
    assert cleared >= 80


def test_triage_queue_ranks_the_detected_processes_only():
    session = LabSession.bootstrap()
    session.spawn("fast-locker", session.process_tree.root.pid)
    session.spawn("office-workload", session.process_tree.root.pid)
    queue = session.triage_queue()
    assert queue.holds_heap_invariant()
    assert set(ticket.pid for ticket in queue) == session.detected_pids()


def test_slowing_a_locker_down_can_hide_it_from_the_detector():
    session = LabSession.bootstrap()
    locker = session.spawn("fast-locker", session.process_tree.root.pid)
    assert session.assess(locker.pid).is_malicious
    for feature, value in (
        (BehaviorFeature.FILES_PER_SECOND, 0.4),
        (BehaviorFeature.RENAME_RATIO, 0.0),
        (BehaviorFeature.SHADOW_COPY_DELETION, 0.0),
        (BehaviorFeature.DIRECTORIES_TOUCHED, 1.0),
        (BehaviorFeature.PAYLOAD_ENTROPY, 4.0),
    ):
        session.tamper(locker.pid, feature, value)
    assert not session.assess(locker.pid).is_malicious


def test_tampering_clamps_to_the_feature_bounds():
    session = LabSession.bootstrap()
    process = session.spawn("office-workload", session.process_tree.root.pid)
    session.tamper(process.pid, BehaviorFeature.PAYLOAD_ENTROPY, 99.0)
    assert process.behavior[BehaviorFeature.PAYLOAD_ENTROPY] == 8.0


def test_retraining_with_a_csv_replaces_the_model_and_keeps_the_process_tree():
    session = LabSession.bootstrap()
    session.spawn("fast-locker", session.process_tree.root.pid)
    before = len(session.process_tree)
    session.retrain(CsvTelemetrySource(VALID_CSV))
    assert session.source.description.startswith("csv:")
    assert len(session.dataset) == 4
    assert len(session.process_tree) == before


def test_unknown_profile_is_rejected():
    session = LabSession.bootstrap()
    with pytest.raises(KeyError):
        session.spawn("not-a-profile")


def test_every_profile_declares_a_consistent_class():
    for name, profile in PROFILE_CATALOG.items():
        assert profile.name == name
        assert profile.process_class in ProcessClass


def test_diagrams_render_dot_for_both_trees():
    session = LabSession.bootstrap()
    session.spawn("stealth-locker", session.process_tree.root.pid)
    labels = Translator(SPANISH).diagram_labels()
    assessment = session.assess(session.selected.pid)
    tree_dot = decision_tree_dot(session.detector.tree, labels, assessment.path.visited)
    process_dot = process_tree_dot(
        session.process_tree, labels, session.detected_pids(), session.suspect_pids()
    )
    assert tree_dot.startswith("digraph decision_tree {")
    assert tree_dot.count("->") == 2 * (session.detector.tree.node_count - session.detector.tree.leaf_count)
    assert process_dot.count("->") == len(session.process_tree) - 1


def test_translations_cover_the_same_keys_in_every_language():
    reference = phrase_keys(ENGLISH)
    for language in supported_languages():
        assert phrase_keys(language) == reference


def test_translator_formats_placeholders_and_feature_labels():
    translate = Translator(SPANISH)
    assert "5" in translate("metrics.caption", folds=5, samples=10, source="x")
    assert translate.feature(BehaviorFeature.PAYLOAD_ENTROPY) != ""
    assert Translator(ENGLISH)("missing.key") == "missing.key"


def test_unsupported_language_is_rejected():
    with pytest.raises(KeyError):
        Translator("fr")
