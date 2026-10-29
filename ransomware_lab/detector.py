from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ransomware_lab.decision_tree import (
    BehaviorDecisionTree,
    BehaviorSplit,
    CartTreeBuilder,
    DecisionPath,
    GrowthLimits,
    ImpurityCriterion,
    RuleOutcome,
    TreeVisitor,
    VerdictLeaf,
)
from ransomware_lab.evaluation import ConfusionMatrix, CrossValidationReport, StratifiedFoldSplitter
from ransomware_lab.telemetry import (
    BehaviorFeature,
    BehaviorVector,
    ProcessClass,
    TelemetryDataset,
)

DEFAULT_RISK_THRESHOLD = 0.5


class Verdict(Enum):
    BENIGN = "benign"
    RANSOMWARE = "ransomware"

    @property
    def process_class(self) -> ProcessClass:
        return ProcessClass.RANSOMWARE if self is Verdict.RANSOMWARE else ProcessClass.BENIGN


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    verdict: Verdict
    risk: float
    threshold: float
    path: DecisionPath

    @property
    def triggered_rules(self) -> tuple[RuleOutcome, ...]:
        return self.path.outcomes

    @property
    def leaf_sample_count(self) -> int:
        return self.path.leaf.sample_count

    @property
    def is_malicious(self) -> bool:
        return self.verdict is Verdict.RANSOMWARE


class _ImpurityImportance(TreeVisitor[None]):
    def __init__(self, root_sample_count: int) -> None:
        self._root_sample_count = max(root_sample_count, 1)
        self._gains: dict[BehaviorFeature, float] = {feature: 0.0 for feature in BehaviorFeature}

    @property
    def normalized(self) -> dict[BehaviorFeature, float]:
        total = sum(self._gains.values())
        if total == 0.0:
            return dict(self._gains)
        return {feature: gain / total for feature, gain in self._gains.items()}

    def visit_split(self, split: BehaviorSplit) -> None:
        weight = split.sample_count / self._root_sample_count
        self._gains[split.rule.feature] += weight * split.impurity_decrease
        split.on_match.accept(self)
        split.on_violation.accept(self)

    def visit_leaf(self, leaf: VerdictLeaf) -> None:
        return None


class RansomwareDetector:
    def __init__(
        self,
        tree: BehaviorDecisionTree,
        risk_threshold: float = DEFAULT_RISK_THRESHOLD,
        training_size: int = 0,
    ) -> None:
        if not 0.0 < risk_threshold <= 1.0:
            raise ValueError("risk threshold must fall in (0, 1]")
        self._tree = tree
        self._risk_threshold = risk_threshold
        self._training_size = training_size

    @classmethod
    def trained_on(
        cls,
        dataset: TelemetryDataset,
        criterion: ImpurityCriterion | None = None,
        limits: GrowthLimits | None = None,
        risk_threshold: float = DEFAULT_RISK_THRESHOLD,
    ) -> RansomwareDetector:
        tree = CartTreeBuilder(criterion, limits).build(dataset)
        return cls(tree, risk_threshold, len(dataset))

    @property
    def tree(self) -> BehaviorDecisionTree:
        return self._tree

    @property
    def risk_threshold(self) -> float:
        return self._risk_threshold

    @property
    def training_size(self) -> int:
        return self._training_size

    def with_threshold(self, risk_threshold: float) -> RansomwareDetector:
        return RansomwareDetector(self._tree, risk_threshold, self._training_size)

    def assess(self, behavior: BehaviorVector) -> ThreatAssessment:
        path = self._tree.trace(behavior)
        verdict = Verdict.RANSOMWARE if path.risk >= self._risk_threshold else Verdict.BENIGN
        return ThreatAssessment(verdict, path.risk, self._risk_threshold, path)

    def evaluate(self, dataset: TelemetryDataset) -> ConfusionMatrix:
        return ConfusionMatrix.of(
            [
                (observation.process_class, self.assess(observation.behavior).verdict.process_class)
                for observation in dataset
            ]
        )

    def feature_importance(self) -> dict[BehaviorFeature, float]:
        accumulator = _ImpurityImportance(self._tree.root.sample_count)
        self._tree.root.accept(accumulator)
        return accumulator.normalized

    def cross_validate(
        self,
        dataset: TelemetryDataset,
        splitter: StratifiedFoldSplitter | None = None,
    ) -> CrossValidationReport:
        folds = splitter or StratifiedFoldSplitter()
        matrices = []
        for training, holdout in folds.split(dataset):
            candidate = RansomwareDetector.trained_on(
                training,
                self._tree.criterion,
                self._tree.limits,
                self._risk_threshold,
            )
            matrices.append(candidate.evaluate(holdout))
        return CrossValidationReport(tuple(matrices))
