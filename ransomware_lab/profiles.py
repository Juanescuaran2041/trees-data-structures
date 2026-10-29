from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from random import Random

from ransomware_lab.telemetry import (
    BehaviorFeature,
    BehaviorVector,
    LabeledObservation,
    ProcessClass,
)


class FeatureDistribution(ABC):
    @abstractmethod
    def draw(self, feature: BehaviorFeature, entropy_source: Random) -> float: ...


@dataclass(frozen=True, slots=True)
class GaussianReading(FeatureDistribution):
    mean: float
    deviation: float

    def draw(self, feature: BehaviorFeature, entropy_source: Random) -> float:
        return feature.clamp(entropy_source.gauss(self.mean, self.deviation))


@dataclass(frozen=True, slots=True)
class BernoulliReading(FeatureDistribution):
    probability: float

    def draw(self, feature: BehaviorFeature, entropy_source: Random) -> float:
        return 1.0 if entropy_source.random() < self.probability else 0.0


class BehaviorProfile(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def process_class(self) -> ProcessClass: ...

    @abstractmethod
    def sample_behavior(self, entropy_source: Random) -> BehaviorVector: ...

    def sample_observation(self, entropy_source: Random) -> LabeledObservation:
        return LabeledObservation(self.sample_behavior(entropy_source), self.process_class)


class StochasticProfile(BehaviorProfile):
    def __init__(
        self,
        name: str,
        process_class: ProcessClass,
        distributions: Mapping[BehaviorFeature, FeatureDistribution],
    ) -> None:
        missing = [feature.column for feature in BehaviorFeature if feature not in distributions]
        if missing:
            raise ValueError(f"profile {name!r} lacks distributions for: {', '.join(missing)}")
        self._name = name
        self._process_class = process_class
        self._distributions = dict(distributions)

    @property
    def name(self) -> str:
        return self._name

    @property
    def process_class(self) -> ProcessClass:
        return self._process_class

    def sample_behavior(self, entropy_source: Random) -> BehaviorVector:
        return BehaviorVector.from_mapping(
            {
                feature: distribution.draw(feature, entropy_source)
                for feature, distribution in self._distributions.items()
            }
        )


def _profile(
    name: str,
    process_class: ProcessClass,
    files_per_second: FeatureDistribution,
    entropy: FeatureDistribution,
    rename_ratio: FeatureDistribution,
    shadow_copy_deletion: FeatureDistribution,
    directories_touched: FeatureDistribution,
) -> StochasticProfile:
    return StochasticProfile(
        name,
        process_class,
        {
            BehaviorFeature.FILES_PER_SECOND: files_per_second,
            BehaviorFeature.PAYLOAD_ENTROPY: entropy,
            BehaviorFeature.RENAME_RATIO: rename_ratio,
            BehaviorFeature.SHADOW_COPY_DELETION: shadow_copy_deletion,
            BehaviorFeature.DIRECTORIES_TOUCHED: directories_touched,
        },
    )


OFFICE_WORKLOAD = _profile(
    "office-workload",
    ProcessClass.BENIGN,
    GaussianReading(1.4, 1.0),
    GaussianReading(4.6, 0.8),
    GaussianReading(0.01, 0.01),
    BernoulliReading(0.0),
    GaussianReading(4.0, 2.0),
)

# Writes fast across many directories: the benign case that stops the tree from
# learning "fast writes mean ransomware".
BACKUP_AGENT = _profile(
    "backup-agent",
    ProcessClass.BENIGN,
    GaussianReading(96.0, 22.0),
    GaussianReading(5.4, 0.6),
    GaussianReading(0.02, 0.02),
    BernoulliReading(0.0),
    GaussianReading(140.0, 40.0),
)

# Compressed output is high-entropy and replaces its input files, so entropy and
# rename ratio alone cannot separate the classes either.
ARCHIVE_COMPRESSOR = _profile(
    "archive-compressor",
    ProcessClass.BENIGN,
    GaussianReading(28.0, 9.0),
    GaussianReading(7.72, 0.12),
    GaussianReading(0.34, 0.12),
    BernoulliReading(0.0),
    GaussianReading(9.0, 4.0),
)

FAST_LOCKER = _profile(
    "fast-locker",
    ProcessClass.RANSOMWARE,
    GaussianReading(135.0, 35.0),
    GaussianReading(7.86, 0.08),
    GaussianReading(0.93, 0.05),
    BernoulliReading(0.95),
    GaussianReading(120.0, 45.0),
)

STEALTH_LOCKER = _profile(
    "stealth-locker",
    ProcessClass.RANSOMWARE,
    GaussianReading(6.5, 2.5),
    GaussianReading(7.58, 0.18),
    GaussianReading(0.47, 0.17),
    BernoulliReading(0.25),
    GaussianReading(26.0, 10.0),
)

PROFILE_CATALOG: Mapping[str, BehaviorProfile] = {
    profile.name: profile
    for profile in (
        OFFICE_WORKLOAD,
        BACKUP_AGENT,
        ARCHIVE_COMPRESSOR,
        FAST_LOCKER,
        STEALTH_LOCKER,
    )
}
