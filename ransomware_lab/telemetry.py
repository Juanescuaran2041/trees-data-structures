from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, IntEnum


class ProcessClass(IntEnum):
    BENIGN = 0
    RANSOMWARE = 1

    @property
    def column_value(self) -> int:
        return int(self)


class BehaviorFeature(Enum):
    FILES_PER_SECOND = ("files_per_sec", 0.0, 400.0, 0.5)
    PAYLOAD_ENTROPY = ("entropy", 0.0, 8.0, 0.05)
    RENAME_RATIO = ("rename_ratio", 0.0, 1.0, 0.01)
    SHADOW_COPY_DELETION = ("shadow_delete", 0.0, 1.0, 1.0)
    DIRECTORIES_TOUCHED = ("dirs_touched", 0.0, 400.0, 1.0)

    def __init__(self, column: str, lower_bound: float, upper_bound: float, ui_step: float) -> None:
        self.column = column
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound
        self.ui_step = ui_step

    @property
    def index(self) -> int:
        return tuple(BehaviorFeature).index(self)

    def clamp(self, value: float) -> float:
        return min(max(value, self.lower_bound), self.upper_bound)

    @classmethod
    def columns(cls) -> tuple[str, ...]:
        return tuple(feature.column for feature in cls)

    @classmethod
    def from_column(cls, column: str) -> BehaviorFeature:
        for feature in cls:
            if feature.column == column:
                return feature
        raise KeyError(column)


class TelemetryFormatError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BehaviorVector:
    readings: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.readings) != len(BehaviorFeature):
            raise TelemetryFormatError(
                f"expected {len(BehaviorFeature)} readings, got {len(self.readings)}"
            )

    @classmethod
    def from_mapping(cls, readings: Mapping[BehaviorFeature, float]) -> BehaviorVector:
        missing = [feature.column for feature in BehaviorFeature if feature not in readings]
        if missing:
            raise TelemetryFormatError(f"missing features: {', '.join(missing)}")
        return cls(tuple(float(readings[feature]) for feature in BehaviorFeature))

    def __getitem__(self, feature: BehaviorFeature) -> float:
        return self.readings[feature.index]

    def with_reading(self, feature: BehaviorFeature, value: float) -> BehaviorVector:
        mutated = list(self.readings)
        mutated[feature.index] = feature.clamp(float(value))
        return BehaviorVector(tuple(mutated))

    def as_mapping(self) -> dict[BehaviorFeature, float]:
        return {feature: self.readings[feature.index] for feature in BehaviorFeature}


@dataclass(frozen=True, slots=True)
class LabeledObservation:
    behavior: BehaviorVector
    process_class: ProcessClass


class TelemetryDataset(Sequence[LabeledObservation]):
    def __init__(self, observations: Sequence[LabeledObservation]) -> None:
        self._observations = tuple(observations)

    def __len__(self) -> int:
        return len(self._observations)

    def __getitem__(self, position: int) -> LabeledObservation:  # type: ignore[override]
        return self._observations[position]

    def __iter__(self) -> Iterator[LabeledObservation]:
        return iter(self._observations)

    def class_counts(self) -> dict[ProcessClass, int]:
        counts = {process_class: 0 for process_class in ProcessClass}
        for observation in self._observations:
            counts[observation.process_class] += 1
        return counts

    def malicious_count(self) -> int:
        return sum(
            1 for observation in self._observations
            if observation.process_class is ProcessClass.RANSOMWARE
        )

    def ransomware_ratio(self) -> float:
        if not self._observations:
            return 0.0
        return self.malicious_count() / len(self._observations)

    def is_pure(self) -> bool:
        return len({observation.process_class for observation in self._observations}) <= 1

    def subset(self, positions: Sequence[int]) -> TelemetryDataset:
        return TelemetryDataset([self._observations[position] for position in positions])

    def merged_with(self, other: TelemetryDataset) -> TelemetryDataset:
        return TelemetryDataset(self._observations + tuple(other))

    def require_both_classes(self) -> None:
        counts = self.class_counts()
        empty = [name.name.lower() for name, total in counts.items() if total == 0]
        if empty:
            raise TelemetryFormatError(f"dataset has no samples for: {', '.join(empty)}")
