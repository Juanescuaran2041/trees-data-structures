from __future__ import annotations

from itertools import count
from random import Random

from ransomware_lab.decision_tree import GrowthLimits, ImpurityCriterion
from ransomware_lab.detector import DEFAULT_RISK_THRESHOLD, RansomwareDetector, ThreatAssessment
from ransomware_lab.evaluation import CrossValidationReport, StratifiedFoldSplitter
from ransomware_lab.process_tree import MonitoredProcess, ProcessTree
from ransomware_lab.profiles import OFFICE_WORKLOAD, PROFILE_CATALOG, BehaviorProfile
from ransomware_lab.sources import SyntheticTelemetrySource, TelemetrySource
from ransomware_lab.telemetry import BehaviorFeature, TelemetryDataset
from ransomware_lab.triage import ThreatTriageQueue

ROOT_PID = 4
IMAGE_NAMES = {
    "office-workload": "winword.exe",
    "backup-agent": "backup-agent.exe",
    "archive-compressor": "7z.exe",
    "fast-locker": "svch0st.exe",
    "stealth-locker": "updater.exe",
}


class LabSession:
    def __init__(
        self,
        source: TelemetrySource,
        dataset: TelemetryDataset,
        detector: RansomwareDetector,
        process_tree: ProcessTree,
        seed: int = 4_8151_62,
    ) -> None:
        self._source = source
        self._dataset = dataset
        self._detector = detector
        self._process_tree = process_tree
        self._entropy_source = Random(seed)
        self._pid_sequence = count(ROOT_PID + 1000)
        self._selected_pid = process_tree.root.pid

    @classmethod
    def bootstrap(
        cls,
        source: TelemetrySource | None = None,
        criterion: ImpurityCriterion | None = None,
        limits: GrowthLimits | None = None,
        risk_threshold: float = DEFAULT_RISK_THRESHOLD,
    ) -> LabSession:
        resolved_source = source or SyntheticTelemetrySource()
        dataset = resolved_source.load()
        detector = RansomwareDetector.trained_on(dataset, criterion, limits, risk_threshold)
        root = MonitoredProcess(
            ROOT_PID,
            "System",
            OFFICE_WORKLOAD.sample_behavior(Random(0)),
            OFFICE_WORKLOAD.name,
        )
        return cls(resolved_source, dataset, detector, ProcessTree(root))

    @property
    def source(self) -> TelemetrySource:
        return self._source

    @property
    def dataset(self) -> TelemetryDataset:
        return self._dataset

    @property
    def detector(self) -> RansomwareDetector:
        return self._detector

    @property
    def process_tree(self) -> ProcessTree:
        return self._process_tree

    @property
    def selected(self) -> MonitoredProcess:
        return self._process_tree.require(self._selected_pid)

    def select(self, pid: int) -> MonitoredProcess:
        self._selected_pid = self._process_tree.require(pid).pid
        return self.selected

    def retune(self, risk_threshold: float) -> None:
        self._detector = self._detector.with_threshold(risk_threshold)

    def retrain(
        self,
        source: TelemetrySource,
        criterion: ImpurityCriterion | None = None,
        limits: GrowthLimits | None = None,
        risk_threshold: float | None = None,
    ) -> None:
        dataset = source.load()
        self._source = source
        self._dataset = dataset
        self._detector = RansomwareDetector.trained_on(
            dataset,
            criterion,
            limits,
            risk_threshold if risk_threshold is not None else self._detector.risk_threshold,
        )

    def spawn(self, profile_name: str, parent_pid: int | None = None) -> MonitoredProcess:
        profile = self._require_profile(profile_name)
        child = MonitoredProcess(
            next(self._pid_sequence),
            IMAGE_NAMES.get(profile.name, f"{profile.name}.exe"),
            profile.sample_behavior(self._entropy_source),
            profile.name,
        )
        parent = parent_pid if parent_pid is not None else self._selected_pid
        self._process_tree.attach(parent, child)
        self._selected_pid = child.pid
        return child

    def tamper(self, pid: int, feature: BehaviorFeature, value: float) -> MonitoredProcess:
        process = self._process_tree.require(pid)
        process.observe(process.behavior.with_reading(feature, value))
        return process

    def cross_validation_report(self, folds: int = 5) -> CrossValidationReport:
        return self._detector.cross_validate(self._dataset, StratifiedFoldSplitter(folds))

    def assess(self, pid: int) -> ThreatAssessment:
        return self._detector.assess(self._process_tree.require(pid).behavior)

    def detected_pids(self) -> frozenset[int]:
        return frozenset(
            process.pid for process in self._process_tree if self.assess(process.pid).is_malicious
        )

    def suspect_pids(self) -> frozenset[int]:
        detected = self.detected_pids()
        return frozenset(
            ancestor.pid
            for pid in detected
            for ancestor in self._process_tree.require(pid).ancestors()
        ) - detected

    def triage_queue(self) -> ThreatTriageQueue:
        queue = ThreatTriageQueue()
        for process in self._process_tree:
            assessment = self.assess(process.pid)
            if assessment.is_malicious:
                queue.admit(
                    process.pid, process.image_name, assessment.risk, process.depth
                )
        return queue

    @staticmethod
    def _require_profile(profile_name: str) -> BehaviorProfile:
        profile = PROFILE_CATALOG.get(profile_name)
        if profile is None:
            raise KeyError(f"unknown behavior profile {profile_name!r}")
        return profile
