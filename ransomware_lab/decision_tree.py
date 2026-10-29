from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from math import log2
from typing import Generic, TypeVar

from ransomware_lab.telemetry import (
    BehaviorFeature,
    BehaviorVector,
    LabeledObservation,
    ProcessClass,
    TelemetryDataset,
    TelemetryFormatError,
)

VisitResult = TypeVar("VisitResult")


class ImpurityCriterion(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def score(self, total: int, malicious: int) -> float: ...

    def impurity(self, dataset: TelemetryDataset) -> float:
        return self.score(len(dataset), dataset.malicious_count())

    def weighted_score(self, parts: Sequence[tuple[int, int]]) -> float:
        total = sum(size for size, _ in parts)
        if total == 0:
            return 0.0
        return sum(size / total * self.score(size, malicious) for size, malicious in parts)


class GiniImpurity(ImpurityCriterion):
    @property
    def name(self) -> str:
        return "gini"

    def score(self, total: int, malicious: int) -> float:
        if total == 0:
            return 0.0
        ratio = malicious / total
        return 2.0 * ratio * (1.0 - ratio)


class ShannonEntropyImpurity(ImpurityCriterion):
    @property
    def name(self) -> str:
        return "entropy"

    def score(self, total: int, malicious: int) -> float:
        if total == 0:
            return 0.0
        ratio = malicious / total
        if ratio in (0.0, 1.0):
            return 0.0
        return -(ratio * log2(ratio) + (1.0 - ratio) * log2(1.0 - ratio))


@dataclass(frozen=True, slots=True)
class DecisionRule:
    feature: BehaviorFeature
    threshold: float

    def holds_for(self, behavior: BehaviorVector) -> bool:
        return behavior[self.feature] <= self.threshold

    def partition(self, dataset: TelemetryDataset) -> tuple[TelemetryDataset, TelemetryDataset]:
        matching: list[LabeledObservation] = []
        violating: list[LabeledObservation] = []
        for observation in dataset:
            target = matching if self.holds_for(observation.behavior) else violating
            target.append(observation)
        return TelemetryDataset(matching), TelemetryDataset(violating)


@dataclass(frozen=True, slots=True)
class RuleOutcome:
    rule: DecisionRule
    observed: float
    satisfied: bool


@dataclass(frozen=True, slots=True)
class GrowthLimits:
    max_depth: int = 5
    min_samples_split: int = 12
    min_samples_leaf: int = 4
    min_impurity_decrease: float = 1e-4

    def allows_split(self, dataset: TelemetryDataset, depth: int) -> bool:
        return depth < self.max_depth and len(dataset) >= self.min_samples_split


class TreeVisitor(ABC, Generic[VisitResult]):
    @abstractmethod
    def visit_split(self, split: BehaviorSplit) -> VisitResult: ...

    @abstractmethod
    def visit_leaf(self, leaf: VerdictLeaf) -> VisitResult: ...


class ClassificationNode(ABC):
    def __init__(self, dataset: TelemetryDataset) -> None:
        self._sample_count = len(dataset)
        self._ransomware_ratio = dataset.ransomware_ratio()

    @property
    def sample_count(self) -> int:
        return self._sample_count

    @property
    def ransomware_ratio(self) -> float:
        return self._ransomware_ratio

    @abstractmethod
    def resolve(self, behavior: BehaviorVector, trail: list[RuleOutcome]) -> VerdictLeaf: ...

    @abstractmethod
    def accept(self, visitor: TreeVisitor[VisitResult]) -> VisitResult: ...

    @abstractmethod
    def walk(self) -> Iterator[ClassificationNode]: ...

    @property
    @abstractmethod
    def height(self) -> int: ...

    @property
    @abstractmethod
    def leaf_count(self) -> int: ...


class VerdictLeaf(ClassificationNode):
    def resolve(self, behavior: BehaviorVector, trail: list[RuleOutcome]) -> VerdictLeaf:
        return self

    def accept(self, visitor: TreeVisitor[VisitResult]) -> VisitResult:
        return visitor.visit_leaf(self)

    def walk(self) -> Iterator[ClassificationNode]:
        yield self

    @property
    def height(self) -> int:
        return 1

    @property
    def leaf_count(self) -> int:
        return 1

    @property
    def majority_class(self) -> ProcessClass:
        if self.ransomware_ratio >= 0.5:
            return ProcessClass.RANSOMWARE
        return ProcessClass.BENIGN


class BehaviorSplit(ClassificationNode):
    def __init__(
        self,
        dataset: TelemetryDataset,
        rule: DecisionRule,
        impurity_decrease: float,
        on_match: ClassificationNode,
        on_violation: ClassificationNode,
    ) -> None:
        super().__init__(dataset)
        self._rule = rule
        self._impurity_decrease = impurity_decrease
        self._on_match = on_match
        self._on_violation = on_violation

    @property
    def rule(self) -> DecisionRule:
        return self._rule

    @property
    def impurity_decrease(self) -> float:
        return self._impurity_decrease

    @property
    def on_match(self) -> ClassificationNode:
        return self._on_match

    @property
    def on_violation(self) -> ClassificationNode:
        return self._on_violation

    def resolve(self, behavior: BehaviorVector, trail: list[RuleOutcome]) -> VerdictLeaf:
        satisfied = self._rule.holds_for(behavior)
        trail.append(RuleOutcome(self._rule, behavior[self._rule.feature], satisfied))
        branch = self._on_match if satisfied else self._on_violation
        return branch.resolve(behavior, trail)

    def accept(self, visitor: TreeVisitor[VisitResult]) -> VisitResult:
        return visitor.visit_split(self)

    def walk(self) -> Iterator[ClassificationNode]:
        yield self
        yield from self._on_match.walk()
        yield from self._on_violation.walk()

    @property
    def height(self) -> int:
        return 1 + max(self._on_match.height, self._on_violation.height)

    @property
    def leaf_count(self) -> int:
        return self._on_match.leaf_count + self._on_violation.leaf_count


@dataclass(frozen=True, slots=True)
class DecisionPath:
    outcomes: tuple[RuleOutcome, ...]
    leaf: VerdictLeaf
    visited: tuple[ClassificationNode, ...]

    @property
    def risk(self) -> float:
        return self.leaf.ransomware_ratio


@dataclass(frozen=True, slots=True)
class _SplitCandidate:
    rule: DecisionRule
    impurity_decrease: float


class CartTreeBuilder:
    def __init__(
        self,
        criterion: ImpurityCriterion | None = None,
        limits: GrowthLimits | None = None,
    ) -> None:
        self._criterion = criterion or GiniImpurity()
        self._limits = limits or GrowthLimits()

    @property
    def criterion(self) -> ImpurityCriterion:
        return self._criterion

    @property
    def limits(self) -> GrowthLimits:
        return self._limits

    def build(self, dataset: TelemetryDataset) -> BehaviorDecisionTree:
        if not dataset:
            raise TelemetryFormatError("cannot grow a tree from an empty dataset")
        return BehaviorDecisionTree(self._grow(dataset, depth=0), self._criterion, self._limits)

    def _grow(self, dataset: TelemetryDataset, depth: int) -> ClassificationNode:
        if dataset.is_pure() or not self._limits.allows_split(dataset, depth):
            return VerdictLeaf(dataset)
        candidate = self._best_candidate(dataset)
        if candidate is None:
            return VerdictLeaf(dataset)
        matching, violating = candidate.rule.partition(dataset)
        return BehaviorSplit(
            dataset,
            candidate.rule,
            candidate.impurity_decrease,
            self._grow(matching, depth + 1),
            self._grow(violating, depth + 1),
        )

    def _best_candidate(self, dataset: TelemetryDataset) -> _SplitCandidate | None:
        total = len(dataset)
        malicious_total = dataset.malicious_count()
        parent_impurity = self._criterion.score(total, malicious_total)
        best: _SplitCandidate | None = None
        for feature in BehaviorFeature:
            for candidate in self._sweep(dataset, feature, total, malicious_total, parent_impurity):
                if best is None or candidate.impurity_decrease > best.impurity_decrease:
                    best = candidate
        return best

    def _sweep(
        self,
        dataset: TelemetryDataset,
        feature: BehaviorFeature,
        total: int,
        malicious_total: int,
        parent_impurity: float,
    ) -> Iterator[_SplitCandidate]:
        # One sorted pass per feature with running class counts: O(n log n) instead of
        # re-partitioning the dataset once per candidate threshold.
        ordered = sorted(dataset, key=lambda observation: observation.behavior[feature])
        matching_size = 0
        matching_malicious = 0
        for position in range(total - 1):
            matching_size += 1
            if ordered[position].process_class is ProcessClass.RANSOMWARE:
                matching_malicious += 1
            low = ordered[position].behavior[feature]
            high = ordered[position + 1].behavior[feature]
            if low == high:
                continue
            violating_size = total - matching_size
            if min(matching_size, violating_size) < self._limits.min_samples_leaf:
                continue
            decrease = parent_impurity - self._criterion.weighted_score(
                (
                    (matching_size, matching_malicious),
                    (violating_size, malicious_total - matching_malicious),
                )
            )
            if decrease < self._limits.min_impurity_decrease:
                continue
            yield _SplitCandidate(DecisionRule(feature, (low + high) / 2.0), decrease)


class BehaviorDecisionTree:
    def __init__(
        self,
        root: ClassificationNode,
        criterion: ImpurityCriterion,
        limits: GrowthLimits,
    ) -> None:
        self._root = root
        self._criterion = criterion
        self._limits = limits

    @property
    def root(self) -> ClassificationNode:
        return self._root

    @property
    def criterion(self) -> ImpurityCriterion:
        return self._criterion

    @property
    def limits(self) -> GrowthLimits:
        return self._limits

    @property
    def height(self) -> int:
        return self._root.height

    @property
    def leaf_count(self) -> int:
        return self._root.leaf_count

    @property
    def node_count(self) -> int:
        return sum(1 for _ in self._root.walk())

    def trace(self, behavior: BehaviorVector) -> DecisionPath:
        trail: list[RuleOutcome] = []
        leaf = self._root.resolve(behavior, trail)
        return DecisionPath(tuple(trail), leaf, self._visited_chain(behavior))

    def risk_of(self, behavior: BehaviorVector) -> float:
        return self.trace(behavior).risk

    def _visited_chain(self, behavior: BehaviorVector) -> tuple[ClassificationNode, ...]:
        chain: list[ClassificationNode] = []
        cursor = self._root
        while isinstance(cursor, BehaviorSplit):
            chain.append(cursor)
            cursor = cursor.on_match if cursor.rule.holds_for(behavior) else cursor.on_violation
        chain.append(cursor)
        return tuple(chain)
