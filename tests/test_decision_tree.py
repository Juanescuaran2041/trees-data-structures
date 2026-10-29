from __future__ import annotations

import pytest

from ransomware_lab.decision_tree import (
    BehaviorSplit,
    CartTreeBuilder,
    DecisionRule,
    GiniImpurity,
    GrowthLimits,
    ShannonEntropyImpurity,
    VerdictLeaf,
)
from ransomware_lab.telemetry import (
    BehaviorFeature,
    BehaviorVector,
    LabeledObservation,
    ProcessClass,
    TelemetryDataset,
    TelemetryFormatError,
)

FILES = BehaviorFeature.FILES_PER_SECOND
ENTROPY = BehaviorFeature.PAYLOAD_ENTROPY


def behavior(files_per_second: float = 1.0, entropy: float = 4.0) -> BehaviorVector:
    return BehaviorVector.from_mapping(
        {
            BehaviorFeature.FILES_PER_SECOND: files_per_second,
            BehaviorFeature.PAYLOAD_ENTROPY: entropy,
            BehaviorFeature.RENAME_RATIO: 0.0,
            BehaviorFeature.SHADOW_COPY_DELETION: 0.0,
            BehaviorFeature.DIRECTORIES_TOUCHED: 1.0,
        }
    )


def dataset_of(*rows: tuple[float, ProcessClass]) -> TelemetryDataset:
    return TelemetryDataset(
        [LabeledObservation(behavior(files_per_second=value), label) for value, label in rows]
    )


def separable_dataset(size: int = 40) -> TelemetryDataset:
    benign = [(float(index), ProcessClass.BENIGN) for index in range(size)]
    malicious = [(100.0 + index, ProcessClass.RANSOMWARE) for index in range(size)]
    return dataset_of(*benign, *malicious)


def test_gini_is_zero_for_a_pure_dataset_and_maximal_for_a_balanced_one():
    criterion = GiniImpurity()
    assert criterion.score(10, 0) == 0.0
    assert criterion.score(10, 10) == 0.0
    assert criterion.score(10, 5) == pytest.approx(0.5)


def test_entropy_peaks_at_one_bit_for_a_balanced_dataset():
    criterion = ShannonEntropyImpurity()
    assert criterion.score(8, 4) == pytest.approx(1.0)
    assert criterion.score(8, 0) == 0.0


def test_rule_partitions_on_the_threshold_inclusive_on_the_left():
    rule = DecisionRule(FILES, 10.0)
    matching, violating = rule.partition(
        dataset_of((10.0, ProcessClass.BENIGN), (10.1, ProcessClass.RANSOMWARE))
    )
    assert len(matching) == 1
    assert len(violating) == 1
    assert rule.holds_for(behavior(files_per_second=10.0))
    assert not rule.holds_for(behavior(files_per_second=10.01))


def test_builder_finds_the_separating_threshold():
    tree = CartTreeBuilder().build(separable_dataset())
    assert isinstance(tree.root, BehaviorSplit)
    assert tree.root.rule.feature is FILES
    assert 39.0 <= tree.root.rule.threshold <= 100.0
    assert tree.height == 2
    assert tree.leaf_count == 2


def test_pure_dataset_collapses_into_a_single_leaf():
    pure = dataset_of(*[(float(index), ProcessClass.BENIGN) for index in range(20)])
    tree = CartTreeBuilder().build(pure)
    assert isinstance(tree.root, VerdictLeaf)
    assert tree.root.majority_class is ProcessClass.BENIGN
    assert tree.height == 1


def test_growth_limits_cap_the_height():
    tree = CartTreeBuilder(limits=GrowthLimits(max_depth=1)).build(separable_dataset())
    assert tree.height <= 2


def test_min_samples_leaf_rejects_lopsided_splits():
    tree = CartTreeBuilder(limits=GrowthLimits(min_samples_leaf=35)).build(separable_dataset(40))
    for node in tree.root.walk():
        if isinstance(node, VerdictLeaf):
            assert node.sample_count >= 35


def test_trace_records_every_rule_and_ends_on_the_reached_leaf():
    tree = CartTreeBuilder().build(separable_dataset())
    path = tree.trace(behavior(files_per_second=500.0))
    assert path.leaf.majority_class is ProcessClass.RANSOMWARE
    assert path.risk == pytest.approx(1.0)
    assert len(path.outcomes) == len(path.visited) - 1
    assert path.visited[-1] is path.leaf
    assert all(not outcome.satisfied for outcome in path.outcomes)


def test_node_counts_are_consistent_with_the_traversal():
    tree = CartTreeBuilder().build(separable_dataset())
    walked = tuple(tree.root.walk())
    assert tree.node_count == len(walked)
    assert tree.leaf_count == sum(1 for node in walked if isinstance(node, VerdictLeaf))


def test_empty_dataset_is_rejected():
    with pytest.raises(TelemetryFormatError):
        CartTreeBuilder().build(TelemetryDataset([]))
