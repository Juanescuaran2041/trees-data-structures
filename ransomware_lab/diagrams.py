from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass

from ransomware_lab.decision_tree import (
    BehaviorDecisionTree,
    BehaviorSplit,
    ClassificationNode,
    TreeVisitor,
    VerdictLeaf,
)
from ransomware_lab.process_tree import MonitoredProcess, ProcessTree
from ransomware_lab.telemetry import BehaviorFeature

PALETTE = {
    "ink": "#0f1115",
    "edge": "#8b93a7",
    "neutral": "#e8ebf2",
    "benign": "#1f9d55",
    "malicious": "#d64545",
    "highlight": "#f2b63c",
    "suspect": "#b07d2b",
}


@dataclass(frozen=True, slots=True)
class DiagramLabels:
    feature_label: Callable[[BehaviorFeature], str]
    samples: str
    risk: str
    ransomware: str
    benign: str
    suspect: str
    profile: str


class _DotTreeRenderer(TreeVisitor[str]):
    def __init__(self, labels: DiagramLabels, highlighted: Collection[ClassificationNode]) -> None:
        self._labels = labels
        self._highlighted = {id(node) for node in highlighted}
        self._lines: list[str] = []
        self._names: dict[int, str] = {}

    def render(self, tree: BehaviorDecisionTree) -> str:
        self._lines = [
            "digraph decision_tree {",
            "  rankdir=TB;",
            '  bgcolor="transparent";',
            '  size="13,7"; ranksep=0.55; nodesep=0.28;',
            '  node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=10'
            ' margin="0.18,0.10"];',
            f'  edge [color="{PALETTE["edge"]}" fontname="Helvetica" fontsize=9];',
        ]
        tree.root.accept(self)
        self._lines.append("}")
        return "\n".join(self._lines)

    def visit_split(self, split: BehaviorSplit) -> str:
        name = self._name_of(split)
        label = (
            f"{self._labels.feature_label(split.rule.feature)}\\n"
            f"<= {split.rule.threshold:.2f}\\n"
            f"{self._labels.samples}: {split.sample_count}"
        )
        self._declare(name, label, self._fill_for(split, PALETTE["neutral"]))
        for branch, edge_label in ((split.on_match, "yes"), (split.on_violation, "no")):
            child = branch.accept(self)
            on_traced_path = id(split) in self._highlighted and id(branch) in self._highlighted
            emphasis = f' penwidth=2.2 color="{PALETTE["highlight"]}"' if on_traced_path else ""
            self._lines.append(f'  {name} -> {child} [label="{edge_label}"{emphasis}];')
        return name

    def visit_leaf(self, leaf: VerdictLeaf) -> str:
        name = self._name_of(leaf)
        verdict = (
            self._labels.ransomware if leaf.ransomware_ratio >= 0.5 else self._labels.benign
        )
        label = (
            f"{verdict}\\n"
            f"{self._labels.risk}: {leaf.ransomware_ratio * 100:.0f}%\\n"
            f"{self._labels.samples}: {leaf.sample_count}"
        )
        base = PALETTE["malicious"] if leaf.ransomware_ratio >= 0.5 else PALETTE["benign"]
        self._declare(name, label, self._fill_for(leaf, base), font="#ffffff")
        return name

    def _declare(self, name: str, label: str, fill: str, font: str = PALETTE["ink"]) -> None:
        self._lines.append(f'  {name} [label="{label}" fillcolor="{fill}" fontcolor="{font}"];')

    def _fill_for(self, node: ClassificationNode, base: str) -> str:
        return PALETTE["highlight"] if id(node) in self._highlighted else base

    def _name_of(self, node: ClassificationNode) -> str:
        return self._names.setdefault(id(node), f"n{len(self._names)}")


def decision_tree_dot(
    tree: BehaviorDecisionTree,
    labels: DiagramLabels,
    highlighted: Collection[ClassificationNode] = (),
) -> str:
    return _DotTreeRenderer(labels, highlighted).render(tree)


def process_tree_dot(
    process_tree: ProcessTree,
    labels: DiagramLabels,
    detected_pids: Collection[int] = (),
    suspect_pids: Collection[int] = (),
    selected_pid: int | None = None,
) -> str:
    lines = [
        "digraph process_tree {",
        "  rankdir=LR;",
        '  bgcolor="transparent";',
        # Capped so a two-node lineage is not blown up to the width of the column.
        '  size="7,4.5"; ranksep=0.45; nodesep=0.22;',
        '  node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=10'
        ' margin="0.16,0.09"];',
        f'  edge [color="{PALETTE["edge"]}"];',
    ]
    for process in process_tree:
        outline = (
            f' penwidth=2.6 color="{PALETTE["highlight"]}"'
            if process.pid == selected_pid
            else ""
        )
        lines.append(
            f'  p{process.pid} [label="{_process_label(process, labels, detected_pids, suspect_pids)}"'
            f' fillcolor="{_process_fill(process, detected_pids, suspect_pids)}"'
            f' fontcolor="{_process_font(process, detected_pids, suspect_pids)}"{outline}];'
        )
        if process.parent is not None:
            lines.append(f"  p{process.parent.pid} -> p{process.pid};")
    lines.append("}")
    return "\n".join(lines)


def _process_label(
    process: MonitoredProcess,
    labels: DiagramLabels,
    detected_pids: Collection[int],
    suspect_pids: Collection[int],
) -> str:
    badge = ""
    if process.pid in detected_pids:
        badge = f"\\n[{labels.ransomware}]"
    elif process.pid in suspect_pids:
        badge = f"\\n[{labels.suspect}]"
    return (
        f"{process.image_name} ({process.pid}){badge}\\n"
        f"{labels.profile}: {process.ground_truth_profile}"
    )


def _process_fill(
    process: MonitoredProcess,
    detected_pids: Collection[int],
    suspect_pids: Collection[int],
) -> str:
    if process.pid in detected_pids:
        return PALETTE["malicious"]
    if process.pid in suspect_pids:
        return PALETTE["suspect"]
    return PALETTE["neutral"]


def _process_font(
    process: MonitoredProcess,
    detected_pids: Collection[int],
    suspect_pids: Collection[int],
) -> str:
    if process.pid in detected_pids or process.pid in suspect_pids:
        return "#ffffff"
    return PALETTE["ink"]
