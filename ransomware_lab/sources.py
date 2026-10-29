from __future__ import annotations

import csv
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from random import Random

from ransomware_lab.profiles import (
    ARCHIVE_COMPRESSOR,
    BACKUP_AGENT,
    FAST_LOCKER,
    OFFICE_WORKLOAD,
    STEALTH_LOCKER,
    BehaviorProfile,
)
from ransomware_lab.telemetry import (
    BehaviorFeature,
    BehaviorVector,
    LabeledObservation,
    ProcessClass,
    TelemetryDataset,
    TelemetryFormatError,
)

LABEL_COLUMN = "label"


class TelemetrySource(ABC):
    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def load(self) -> TelemetryDataset: ...


class SyntheticTelemetrySource(TelemetrySource):
    DEFAULT_MIX: Mapping[BehaviorProfile, int] = {
        OFFICE_WORKLOAD: 200,
        BACKUP_AGENT: 90,
        ARCHIVE_COMPRESSOR: 90,
        FAST_LOCKER: 150,
        STEALTH_LOCKER: 120,
    }

    def __init__(self, seed: int = 20_251_029, mix: Mapping[BehaviorProfile, int] | None = None) -> None:
        self._seed = seed
        self._mix = dict(mix or self.DEFAULT_MIX)

    @property
    def description(self) -> str:
        return f"synthetic:{sum(self._mix.values())}@seed{self._seed}"

    def load(self) -> TelemetryDataset:
        entropy_source = Random(self._seed)
        observations = [
            profile.sample_observation(entropy_source)
            for profile, count in self._mix.items()
            for _ in range(count)
        ]
        entropy_source.shuffle(observations)
        dataset = TelemetryDataset(observations)
        dataset.require_both_classes()
        return dataset


class CsvTelemetrySource(TelemetrySource):
    def __init__(self, rows: Iterable[str], origin: str = "uploaded.csv") -> None:
        self._rows = list(rows)
        self._origin = origin

    @classmethod
    def from_path(cls, path: str) -> CsvTelemetrySource:
        with open(path, newline="", encoding="utf-8-sig") as handle:
            return cls(handle.read().splitlines(), origin=path)

    @classmethod
    def from_bytes(cls, payload: bytes, origin: str = "uploaded.csv") -> CsvTelemetrySource:
        return cls(payload.decode("utf-8-sig").splitlines(), origin=origin)

    @property
    def description(self) -> str:
        return f"csv:{self._origin}"

    def load(self) -> TelemetryDataset:
        reader = csv.DictReader(self._rows)
        if reader.fieldnames is None:
            raise TelemetryFormatError("the CSV file is empty")
        self._require_columns(reader.fieldnames)
        observations = [self._parse(row, number) for number, row in enumerate(reader, start=2)]
        if not observations:
            raise TelemetryFormatError("the CSV file has a header but no data rows")
        dataset = TelemetryDataset(observations)
        dataset.require_both_classes()
        return dataset

    @staticmethod
    def _require_columns(fieldnames: Sequence[str]) -> None:
        present = {name.strip() for name in fieldnames}
        expected = (*BehaviorFeature.columns(), LABEL_COLUMN)
        missing = [column for column in expected if column not in present]
        if missing:
            raise TelemetryFormatError(f"missing CSV columns: {', '.join(missing)}")

    @staticmethod
    def _parse(row: Mapping[str, str | None], line_number: int) -> LabeledObservation:
        readings: dict[BehaviorFeature, float] = {}
        for feature in BehaviorFeature:
            readings[feature] = CsvTelemetrySource._to_float(
                row.get(feature.column), feature.column, line_number
            )
        raw_label = CsvTelemetrySource._to_float(row.get(LABEL_COLUMN), LABEL_COLUMN, line_number)
        if raw_label not in (0.0, 1.0):
            raise TelemetryFormatError(
                f"line {line_number}: label must be 0 or 1, got {raw_label:g}"
            )
        return LabeledObservation(
            BehaviorVector.from_mapping(readings), ProcessClass(int(raw_label))
        )

    @staticmethod
    def _to_float(raw: str | None, column: str, line_number: int) -> float:
        if raw is None or raw.strip() == "":
            raise TelemetryFormatError(f"line {line_number}: column {column!r} is empty")
        try:
            return float(raw)
        except ValueError as error:
            raise TelemetryFormatError(
                f"line {line_number}: column {column!r} is not numeric ({raw!r})"
            ) from error
