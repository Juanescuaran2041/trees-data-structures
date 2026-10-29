from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from random import Random

from ransomware_lab.telemetry import ProcessClass, TelemetryDataset, TelemetryFormatError


@dataclass(frozen=True, slots=True)
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @classmethod
    def of(cls, outcomes: Sequence[tuple[ProcessClass, ProcessClass]]) -> ConfusionMatrix:
        counters = [0, 0, 0, 0]
        for expected, predicted in outcomes:
            malicious_expected = expected is ProcessClass.RANSOMWARE
            malicious_predicted = predicted is ProcessClass.RANSOMWARE
            if malicious_expected and malicious_predicted:
                counters[0] += 1
            elif malicious_predicted:
                counters[1] += 1
            elif malicious_expected:
                counters[3] += 1
            else:
                counters[2] += 1
        return cls(*counters)

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def accuracy(self) -> float:
        return self._ratio(self.true_positives + self.true_negatives, self.total)

    @property
    def precision(self) -> float:
        return self._ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        return self._ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def specificity(self) -> float:
        return self._ratio(self.true_negatives, self.true_negatives + self.false_positives)

    @property
    def f1_score(self) -> float:
        denominator = self.precision + self.recall
        if denominator == 0.0:
            return 0.0
        return 2.0 * self.precision * self.recall / denominator

    def __add__(self, other: ConfusionMatrix) -> ConfusionMatrix:
        return ConfusionMatrix(
            self.true_positives + other.true_positives,
            self.false_positives + other.false_positives,
            self.true_negatives + other.true_negatives,
            self.false_negatives + other.false_negatives,
        )

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0


@dataclass(frozen=True, slots=True)
class CrossValidationReport:
    folds: tuple[ConfusionMatrix, ...]

    @property
    def pooled(self) -> ConfusionMatrix:
        pooled = ConfusionMatrix()
        for fold in self.folds:
            pooled = pooled + fold
        return pooled

    @property
    def mean_recall(self) -> float:
        return self._mean(fold.recall for fold in self.folds)

    @property
    def mean_precision(self) -> float:
        return self._mean(fold.precision for fold in self.folds)

    @property
    def mean_accuracy(self) -> float:
        return self._mean(fold.accuracy for fold in self.folds)

    @property
    def worst_recall(self) -> float:
        return min((fold.recall for fold in self.folds), default=0.0)

    def _mean(self, values: Iterator[float]) -> float:
        collected = tuple(values)
        return sum(collected) / len(collected) if collected else 0.0


class StratifiedFoldSplitter:
    def __init__(self, folds: int = 5, seed: int = 7) -> None:
        if folds < 2:
            raise ValueError("cross-validation needs at least 2 folds")
        self._folds = folds
        self._seed = seed

    @property
    def folds(self) -> int:
        return self._folds

    def split(self, dataset: TelemetryDataset) -> Iterator[tuple[TelemetryDataset, TelemetryDataset]]:
        buckets = self._stratified_buckets(dataset)
        for index in range(self._folds):
            holdout = buckets[index]
            training_positions = [
                position
                for other, bucket in enumerate(buckets)
                if other != index
                for position in bucket
            ]
            yield dataset.subset(training_positions), dataset.subset(holdout)

    def _stratified_buckets(self, dataset: TelemetryDataset) -> list[list[int]]:
        dataset.require_both_classes()
        shuffler = Random(self._seed)
        buckets: list[list[int]] = [[] for _ in range(self._folds)]
        for process_class in ProcessClass:
            positions = [
                position
                for position, observation in enumerate(dataset)
                if observation.process_class is process_class
            ]
            if len(positions) < self._folds:
                raise TelemetryFormatError(
                    f"class {process_class.name.lower()} has {len(positions)} samples, "
                    f"fewer than the {self._folds} requested folds"
                )
            shuffler.shuffle(positions)
            for offset, position in enumerate(positions):
                buckets[offset % self._folds].append(position)
        return buckets
